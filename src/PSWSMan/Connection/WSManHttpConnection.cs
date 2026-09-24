using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan.Connection;

/// <summary>A single authenticated HTTP connection to a WSMan endpoint.</summary>
/// <remarks>
/// <para>
/// The connection owns exactly one socket and one authentication context. It is not thread safe and must only be
/// used by one caller at a time, which is what <see cref="WSManConnectionPool"/> guarantees through its leases.
/// </para>
/// <para>
/// If the socket is closed, for example by the server's idle timeout, the next request transparently opens a new
/// socket and re-runs the authentication handshake. A request that fails for any reason marks the connection as
/// broken so the pool disposes it rather than handing it out again.
/// </para>
/// <para>
/// TCP keepalive is enabled on every socket so a peer that disappears while a request is waiting for its response
/// fails the request within a few probe intervals instead of the full request timeout.
/// </para>
/// </remarks>
internal sealed class WSManHttpConnection : IDisposable
{
    private const int MaxSendAttempts = 3;

    private readonly WSManConnectionOptions _options;
    private readonly Uri _requestUri;
    private readonly HttpClient _http;

    // Per socket state, replaced by the connect callback every time a new socket is established.
    private IWSManAuthenticationContext? _auth;
    private IWSManEncryptionContext? _encryptor;
    private Socket? _socket;
    private int _generation;

    private bool _disposed;

    /// <summary>Whether a request on this connection failed and the connection should not be used again.</summary>
    public bool IsBroken { get; private set; }

    /// <summary>Creates a new connection, the socket is opened on the first <see cref="Send"/>.</summary>
    /// <param name="options">The options for the endpoint.</param>
    public WSManHttpConnection(WSManConnectionOptions options)
    {
        options.Validate();
        _options = options;

        // TLS is done inside the connect callback so that the channel binding token is available to the
        // authentication context. The request URI is rewritten to http so SocketsHttpHandler does not attempt to wrap
        // the stream in its own TLS session.
        UriBuilder uriBuilder = new(options.ConnectionUri) { Scheme = Uri.UriSchemeHttp };
        _requestUri = uriBuilder.Uri;

        SocketsHttpHandler handler = new()
        {
            // A WSMan connection is bound to its authentication context so the handler must never open a second
            // socket behind our back or drop an idle one on its own schedule. Reconnects still happen when the server
            // closes the socket, which the connect callback handles by resetting the authentication state.
            MaxConnectionsPerServer = 1,
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
            PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
            ConnectTimeout = options.ConnectTimeout,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            ConnectCallback = ConnectAsync,
        };

        _http = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
        _http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", options.UserAgent);
        _http.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Encoding", "identity");
    }

    /// <summary>Sends a WSMan envelope and returns the raw response envelope.</summary>
    /// <param name="message">The envelope to send.</param>
    /// <param name="cancellationToken">Aborts the request, the connection is broken afterwards.</param>
    /// <returns>
    /// The raw response envelope, this may be a fault that the caller is expected to parse. The memory is owned by
    /// the caller and is not reused by the connection.
    /// </returns>
    /// <exception cref="OperationCanceledException">The request was cancelled.</exception>
    /// <exception cref="TimeoutException">The request exceeded the configured request timeout.</exception>
    /// <exception cref="AuthenticationException">The server rejected the authentication attempt.</exception>
    /// <exception cref="HttpRequestException">The connection failed or the server returned an empty error response.</exception>
    public ReadOnlyMemory<byte> Send(ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (IsBroken)
        {
            throw new InvalidOperationException("The WSMan connection is broken and cannot be reused.");
        }

        CancellationTokenSource? timeoutCts = null;
        CancellationToken token = cancellationToken;
        if (_options.RequestTimeout != Timeout.InfiniteTimeSpan)
        {
            timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_options.RequestTimeout);
            token = timeoutCts.Token;
        }

        try
        {
            return SendCore(message, token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            IsBroken = true;
            throw;
        }
        catch (OperationCanceledException e) when (timeoutCts?.IsCancellationRequested == true)
        {
            IsBroken = true;
            throw new TimeoutException(
                $"WSMan request did not complete within the request timeout of {_options.RequestTimeout}", e);
        }
        catch (OperationCanceledException e)
        {
            // A connection timeout surfaces as a TaskCanceledException with a vague message. Use the base exception
            // which contains the real details, e.g. connect timeout or DNS failure.
            IsBroken = true;
            ExceptionDispatchInfo.Throw(e.GetBaseException());
            throw;
        }
        catch (HttpRequestException e) when (e.InnerException is AuthenticationException or WSManTransportException)
        {
            // Failures raised inside the connect callback are wrapped by the handler, surface the real cause.
            IsBroken = true;
            ExceptionDispatchInfo.Throw(e.InnerException);
            throw;
        }
        catch
        {
            IsBroken = true;
            throw;
        }
        finally
        {
            timeoutCts?.Dispose();
        }
    }

    private ReadOnlyMemory<byte> SendCore(ReadOnlyMemory<byte> message, CancellationToken token)
    {
        for (int attempt = 1; ; attempt++)
        {
            // The server closes idle sockets on its own schedule. Checking up front means the request is built for
            // a fresh handshake rather than for a context that is about to be replaced by the connect callback.
            if (_auth is not null && !IsSocketAlive())
            {
                Trace("socket closed by the peer, dropping the authentication context");
                DropContext();
            }

            int generation = _generation;
            HttpRequestMessage request = CreateRequest(message);
            using HttpResponseMessage response = SendWithChallenges(message, ref request, token);
            IWSManAuthenticationContext auth = CurrentAuth;
            TraceResponse(response, auth);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                throw new AuthenticationException(
                    $"WinRM {auth.HttpAuthLabel} authentication failure{StageSuffix(auth)}");
            }

            // Without encryption the payload goes out with the very first request. With it the payload is only sent
            // once the context is complete, and a reconnect under the request means the body was encrypted with a
            // context the server never had.
            bool payloadSent = !_options.Encrypt
                || (request.Content is not AuthPlaceholderContent && generation == _generation);

            if (!auth.Complete)
            {
                // The server answered without finishing the exchange. The context cannot produce another token until
                // it gets a challenge, so nothing more can be sent on this connection and the pool disposes it once
                // the caller is done. The response is still the server's answer to the payload if that went out.
                IsBroken = true;
                Trace("authentication exchange was not completed by the server, connection marked broken");
                if (!payloadSent)
                {
                    throw new AuthenticationException(
                        $"WinRM {auth.HttpAuthLabel} authentication failure{StageSuffix(auth)} - the server " +
                        $"responded with {(int)response.StatusCode} before the authentication exchange completed");
                }
            }
            else if (!payloadSent)
            {
                // The context is complete now so the next attempt carries the real payload. This loops in case the
                // server closes the socket in between, which restarts the handshake on a new socket.
                if (attempt >= MaxSendAttempts)
                {
                    throw new WSManTransportException(
                        $"WSMan connection failed to send the request after {attempt} authentication attempts.");
                }
                continue;
            }

            return ProcessResponse(response);
        }
    }

    /// <summary>Sends the request and answers each challenge until the context is complete or the server stops challenging.</summary>
    /// <param name="message">The envelope, used to build the request for each challenge round.</param>
    /// <param name="request">The request to send, replaced with the last request sent when challenges were answered.</param>
    /// <param name="token">Cancels the requests.</param>
    /// <returns>The response to the last request sent, owned by the caller.</returns>
    private HttpResponseMessage SendWithChallenges(ReadOnlyMemory<byte> message, ref HttpRequestMessage request,
        CancellationToken token)
    {
        HttpResponseMessage response = _http.Send(request, HttpCompletionOption.ResponseContentRead, token);
        try
        {
            // The connect callback creates the authentication context so it is always set once a response is
            // received. Each challenge round is sent with a new request that carries the next token.
            while (!CurrentAuth.Complete)
            {
                HttpRequestMessage next = CreateRequest(message, addAuthHeader: false);
                if (!AddAuthenticationHeader(next, response))
                {
                    break;
                }

                request = next;
                response.Dispose();
                response = _http.Send(request, HttpCompletionOption.ResponseContentRead, token);
            }

            return response;
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    private IWSManAuthenticationContext CurrentAuth => _auth
        ?? throw new WSManTransportException("WSMan connection has no authentication context.");

    /// <summary>The " during the stage X" suffix for error messages of contexts that report a stage, like CredSSP.</summary>
    private static string StageSuffix(IWSManAuthenticationContext auth)
        => string.IsNullOrWhiteSpace(auth.AuthenticationStage) ? "" : $" during the stage {auth.AuthenticationStage}";

    private HttpRequestMessage CreateRequest(ReadOnlyMemory<byte> message, bool addAuthHeader = true)
    {
        HttpRequestMessage request = new(HttpMethod.Post, _requestUri)
        {
            Content = CreateContent(message),
        };

        if (addAuthHeader && _auth is not null)
        {
            if (!_auth.Complete)
            {
                // Stepping an exchange without the server's token is never valid, SendCore marks the connection
                // broken when an exchange stalls so this cannot happen through the pool.
                throw new WSManTransportException(
                    "WSMan connection has an unfinished authentication exchange and cannot send a new request.");
            }

            // Schemes that do not exchange tokens, like Basic, provide their header on every request. For the rest
            // the socket is authenticated once the exchange completes. A fresh socket has no context yet, the
            // connect callback adds the first token in that case.
            if (!_auth.ExchangesTokens)
            {
                AddAuthenticationHeader(request, null);
            }
        }

        return request;
    }

    private HttpContent CreateContent(ReadOnlyMemory<byte> message)
    {
        if (!_options.Encrypt)
        {
            // The caller's buffer is referenced as is, the request is fully sent before Send returns.
            ReadOnlyMemoryContent content = new(message);
            content.Headers.ContentType = new MediaTypeHeaderValue(WSManEncryption.ContentType) { CharSet = "UTF-8" };
            return content;
        }

        if (_encryptor is null || !_auth!.Complete)
        {
            // The context is not established yet so the payload cannot be encrypted, send an empty body while the
            // handshake completes and resend the real payload after.
            return new AuthPlaceholderContent();
        }

        return WSManEncryption.Wrap(message.Span, _encryptor);
    }

    private ReadOnlyMemory<byte> ProcessResponse(HttpResponseMessage response)
    {
        byte[] buffer = ReadBody(response);
        ReadOnlyMemory<byte> body = buffer;

        string mediaType = response.Content.Headers.ContentType?.MediaType ?? "";
        if (mediaType == WSManEncryption.MultipartEncrypted || mediaType == WSManEncryption.MultipartMultiEncrypted)
        {
            if (_encryptor is null)
            {
                throw new WSManTransportException("Received encrypted response but no encryption context is set.");
            }

            // Decrypted in place, the plaintext is compacted to the start of the same buffer.
            int length = WSManEncryption.Unwrap(buffer, _encryptor);
            body = buffer.AsMemory(0, length);
        }

        if (body.Span.IndexOfAnyExcept(" \t\r\n"u8) == -1)
        {
            // WSMan faults come back as a 500 with a SOAP body which the caller parses, only an empty error body is
            // treated as a transport failure.
            response.EnsureSuccessStatusCode();
        }

        return body;
    }

    private static byte[] ReadBody(HttpResponseMessage response)
    {
        // The content has already been buffered by HttpCompletionOption.ResponseContentRead so this is a copy from
        // memory rather than a socket read.
        using Stream stream = response.Content.ReadAsStream();
        long? length = response.Content.Headers.ContentLength;
        if (length is > 0 and <= int.MaxValue)
        {
            byte[] buffer = new byte[(int)length.Value];
            stream.ReadExactly(buffer);
            return buffer;
        }

        using MemoryStream ms = new();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    private bool AddAuthenticationHeader(HttpRequestMessage request, HttpResponseMessage? response)
    {
        IWSManAuthenticationContext auth = CurrentAuth;

        AuthenticationHeaderValue[]? challenges = response?.Headers.WwwAuthenticate.ToArray();
        byte[]? inputToken = null;
        if (
            challenges?.Length == 1 &&
            challenges[0].Scheme == auth.HttpAuthLabel &&
            !string.IsNullOrEmpty(challenges[0].Parameter)
        )
        {
            inputToken = Convert.FromBase64String(challenges[0].Parameter!);
        }
        else if (response is not null)
        {
            if (!string.IsNullOrWhiteSpace(auth.AuthenticationStage) &&
                response.StatusCode == HttpStatusCode.Unauthorized)
            {
                throw new AuthenticationException(
                    $"WinRM {auth.HttpAuthLabel} authentication failure{StageSuffix(auth)} - the server did not " +
                    "respond with a token");
            }

            // No challenge to process, let the caller deal with the response as is.
            return false;
        }

        byte[]? outputToken;
        try
        {
            outputToken = auth.Step(inputToken);
        }
        catch (AuthenticationException)
        {
            throw;
        }
        catch (Exception e)
        {
            throw new AuthenticationException(
                $"Unknown WinRM authentication failure{StageSuffix(auth)}: {e.Message}", e);
        }

        if (outputToken is null)
        {
            return false;
        }

        string authValue = outputToken.Length == 0
            ? auth.HttpAuthLabel
            : $"{auth.HttpAuthLabel} {Convert.ToBase64String(outputToken)}";

        // Some auth providers don't follow the RFC format 'Protocol Token' so TryAddWithoutValidation is used instead.
        request.Headers.Remove("Authorization");
        request.Headers.TryAddWithoutValidation("Authorization", authValue);

        return true;
    }

    private async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken token)
    {
        Socket socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        Stream? stream = null;
        try
        {
            ConfigureKeepAlive(socket);
            await socket.ConnectAsync(context.DnsEndPoint, token).ConfigureAwait(false);
            stream = new NetworkStream(socket, ownsSocket: true);

            X509Certificate2? serverCertificate = null;
            if (_options.TlsOptions is not null)
            {
                SslStream ssl = new(stream);
                stream = ssl;

                await ssl.AuthenticateAsClientAsync(_options.TlsOptions, token).ConfigureAwait(false);
                if (ssl.RemoteCertificate is not null)
                {
                    serverCertificate = new X509Certificate2(ssl.RemoteCertificate);
                }
            }

            _socket = socket;
            using (serverCertificate)
            {
                ResetAuthentication(serverCertificate, context.InitialRequestMessage);
            }
            Trace($"connected socket generation {_generation} to {context.DnsEndPoint}, " +
                $"authenticating with {_auth?.HttpAuthLabel}");
            return stream;
        }
        catch
        {
            if (stream is null)
            {
                socket.Dispose();
            }
            else
            {
                stream.Dispose();
            }
            throw;
        }
    }

    private void ConfigureKeepAlive(Socket socket)
    {
        if (_options.KeepAliveTime == Timeout.InfiniteTimeSpan)
        {
            return;
        }

        // The socket options are in whole seconds. A request/response exchange has nothing on the wire while the
        // server holds a Receive so the probes are the only way to learn the peer is gone before the request
        // timeout. The per socket timers are supported on Windows 10 1709+, Linux and macOS.
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime,
            (int)_options.KeepAliveTime.TotalSeconds);
        socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval,
            (int)_options.KeepAliveInterval.TotalSeconds);
        socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount,
            _options.KeepAliveRetryCount);
    }

    private void ResetAuthentication(X509Certificate2? serverCertificate, HttpRequestMessage request)
    {
        // A new socket means a new security context. Its first token, or the credential header of a scheme that does
        // not exchange tokens, is added to the request that triggered the connection here because the channel
        // bindings are only known once TLS is established.
        DropContext();
        _generation++;
        _auth = _options.Credential.CreateAuthContext(serverCertificate);
        _encryptor = _options.Encrypt ? (IWSManEncryptionContext)_auth : null;

        AddAuthenticationHeader(request, null);
    }

    private void TraceResponse(HttpResponseMessage response, IWSManAuthenticationContext auth)
    {
        if (_options.Trace is null)
        {
            return;
        }

        // Only the schemes of the challenges are logged, never the tokens.
        string challenges = string.Join(", ", response.Headers.WwwAuthenticate.Select(
            c => string.IsNullOrEmpty(c.Parameter) ? c.Scheme : $"{c.Scheme} <token>"));
        Trace($"response {(int)response.StatusCode} {response.ReasonPhrase}, " +
            $"content-type '{response.Content.Headers.ContentType?.MediaType}', " +
            $"authentication {(auth.Complete ? "complete" : "incomplete")}, " +
            $"www-authenticate [{challenges}]");
    }

    private void Trace(string message)
    {
        if (_options.Trace is null)
        {
            return;
        }

        try
        {
            _options.Trace($"PSWSMan Connection: {message}");
        }
        catch (Exception)
        {
            // Tracing is best effort, it must never affect the connection.
        }
    }

    private void DropContext()
    {
        _auth?.Dispose();
        _auth = null;
        _encryptor = null;
    }

    private bool IsSocketAlive()
    {
        Socket? socket = _socket;
        if (socket is null)
        {
            return false;
        }

        try
        {
            // A readable socket with nothing to read means the peer closed it. Any data waiting would be a protocol
            // violation for a request/response exchange so it is treated the same way.
            return socket.Connected && !socket.Poll(0, SelectMode.SelectRead);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException)
        {
            return false;
        }
    }

    /// <summary>Closes the socket and releases the authentication context. Aborts any request in flight.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        IsBroken = true;

        _http.Dispose();
        DropContext();
    }

    /// <summary>Marks the requests sent with an empty body while the authentication handshake completes.</summary>
    private sealed class AuthPlaceholderContent : ByteArrayContent
    {
        public AuthPlaceholderContent() : base(Array.Empty<byte>())
        { }
    }
}
