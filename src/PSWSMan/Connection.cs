using PSWSMan.Authentication;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan;

internal class WSManInitialRequest : HttpRequestMessage
{
    internal WSManConnection Connection { get; }

    public WSManInitialRequest(HttpMethod method, Uri uri, WSManConnection connection)
        : base(method, uri)
    {
        Connection = connection;
    }
}

/// <summary>Raw WSMan HTTP connection class.</summary>
public class WSManConnection : IDisposable
{
    private const string CONTENT_TYPE = "application/soap+xml";

    private readonly Uri _connectionUri;
    private readonly IWSManEncryptionContext? _encryptor;
    private readonly NegotiateOptions _negoOptions;
    private readonly TimeSpan _connectTimeout;

    private HttpClient? _http;

    internal AuthenticationContext AuthContext { get; }

    internal SslClientAuthenticationOptions? SslOptions { get; }

    internal ChannelBindings? ChannelBindings { get; set; }

    /// <summary>Create connection for WSMan payloads</summary>
    /// <param name="connectionUri">The connection URI.</param>
    /// <param name="credential">The authentication credential used to authenticate the connection.</param>
    /// <param name="negoOptions">Extra options to provide for negotiate authentication contexts.</param>
    /// <param name="sslOptions">Set the TLS connection options for a HTTPS connection.</param>
    /// <param name="encrypt">Whether to use WinRM message encryption or not.</param>
    /// <param name="connectTimeout">The timeout for connecting to the host, null is InfiniteTimeSpan</param>
    /// </param>
    public WSManConnection(Uri connectionUri, WSManCredential credential, NegotiateOptions negoOptions,
        SslClientAuthenticationOptions? sslOptions, bool encrypt, TimeSpan? connectTimeout)
    {
        _connectionUri = connectionUri;
        _connectTimeout = connectTimeout ?? Timeout.InfiniteTimeSpan;
        _negoOptions = negoOptions;
        AuthContext = credential.CreateAuthContext();
        SslOptions = sslOptions;

        if (encrypt)
        {
            if (AuthContext is not IWSManEncryptionContext)
            {
                string provClass = AuthContext.GetType().Name;
                throw new ArgumentException(
                    $"Cannot encrypt WSMan payload as {provClass} does not support message encryption.");
            }
            _encryptor = (IWSManEncryptionContext)AuthContext;
        }
    }

    /// <summary>Send a HTTP payload as a POST request.</summary>
    /// <param name="message">The HTTP payload to send.</param>
    /// <param name="cancelToken">The cancellation token for the request.</param>
    /// <returns>The response for this request.</returns>
    public async Task<string> SendMessage(string message, CancellationToken cancelToken)
    {
        HttpRequestMessage request;

        HttpContent? content = null;
        HttpResponseMessage? response = null;

        if (_http == null)
        {
            _http = GetWSManHttpClient(_connectTimeout);

            content = PrepareContent(message);
            response = await Authenticate(_http, content, cancelToken);

            // If doing HTTP encryption, the response isn't the final response as the request need to be resent with
            // encryption
            if (_encryptor is not null)
            {
                content = null;
                response = null;
            }
        }

        if (response is null)
        {
            content ??= PrepareContent(message);
            request = new(HttpMethod.Post, _connectionUri);
            request.Content = content;
            AddAuthenticationHeaders(request, null);

            response = await _http.SendAsync(request, cancelToken).ConfigureAwait(false);
        }

        string responseContent = await ProcessResponse(response).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new AuthenticationException("WinRM authentication failure");
        }
        else if (string.IsNullOrWhiteSpace(responseContent))
        {
            response.EnsureSuccessStatusCode();
        }
        return responseContent;
    }

    internal bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response)
    {
        if (AuthContext.Complete)
        {
            return false;
        }

        AuthenticationHeaderValue[]? respAuthHeader = response?.Headers.WwwAuthenticate.ToArray();
        byte[]? inputToken = null;
        if (respAuthHeader?.Length == 1 && respAuthHeader[0].Scheme == AuthContext.HttpAuthLabel)
        {
            inputToken = Convert.FromBase64String(respAuthHeader[0].Parameter ?? "");
        }
        else if (response is not null)
        {
            if (!string.IsNullOrWhiteSpace(AuthContext.AuthenticationStage) && response.StatusCode == HttpStatusCode.Unauthorized)
            {
                string msg = $"WinRM authentication failure - server did not response to token during the stage {AuthContext.AuthenticationStage}";
                throw new AuthenticationException(msg);
            }
            else
            {
                // Pass back and let the connection code to handle it.
                return false;
            }
        }

        byte[]? outputToken;
        try
        {
            outputToken = AuthContext.Step(inputToken, _negoOptions, ChannelBindings);
        }
        catch (AuthenticationException)
        {
            throw;
        }
        catch (Exception e)
        {
            string stageMsg = "";
            if (!string.IsNullOrWhiteSpace(AuthContext.AuthenticationStage))
            {
                stageMsg = $" during the stage {AuthContext.AuthenticationStage}";
            }
            throw new AuthenticationException($"Unknown WinRM authentication failure{stageMsg}: {e.Message}", e);
        }

        if (outputToken == null)
        {
            return false;
        }

        string authValue;
        if (outputToken.Length == 0)
        {
            authValue = AuthContext.HttpAuthLabel;
        }
        else
        {
            authValue = $"{AuthContext.HttpAuthLabel} {Convert.ToBase64String(outputToken)}";
        }

        // Some auth providers don't follow the RFC format 'Protocol Token' so TryAddWithoutValidation is used instead
        request.Headers.TryAddWithoutValidation("Authorization", authValue);

        return true;
    }

    private async Task<HttpResponseMessage> Authenticate(HttpClient http, HttpContent content,
        CancellationToken cancelToken)
    {
        // The WSMan http client is set to call the authentication provider and add the first token once the socket
        // is connected and TLS negotiated (if needed). This is required as some auth providers require the TLS
        // channel binding tokens before creating the first token. Subsequent authentication steps are done here
        // after the connection is set up.
        HttpRequestMessage request = new WSManInitialRequest(
            HttpMethod.Post,
            _connectionUri,
            this);
        request.Content = content;

        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, cancelToken).ConfigureAwait(false);
        }
        catch (TaskCanceledException e)
        {
            // A connection timeout resutls in TaskCanceledException but the message there is very vague. Use the base
            // exception instead which contains more details like, i.e. timeout on connection or DNS errors.
            throw e.GetBaseException();
        }

        while (!AuthContext.Complete)
        {
            request = new HttpRequestMessage(HttpMethod.Post, _connectionUri);
            request.Content = content;
            if (!AddAuthenticationHeaders(request, response))
            {
                // No more rounds needed to authenticate with the remote host.
                break;
            }
            response = await http.SendAsync(request, cancelToken).ConfigureAwait(false);
        }

        return response;
    }

    private HttpContent PrepareContent(string message)
    {
        if (_encryptor is not null)
        {
            if (AuthContext.Complete)
            {
                return PrepareEncryptedContent(message, _encryptor);
            }
            else
            {
                // The initial request needs to be empty as it's setting up the security context for later encryption.
                return new StringContent("");
            }
        }
        else
        {
            return new StringContent(message, Encoding.UTF8, CONTENT_TYPE);
        }
    }

    private HttpContent PrepareEncryptedContent(string message, IWSManEncryptionContext encryptor)
    {
        const string boundary = "Encrypted Boundary";

        Span<byte> toEncrypt = new(Encoding.UTF8.GetBytes(message));
        int chunkSize = encryptor.MaxEncryptionChunkSize == -1 ? toEncrypt.Length : encryptor.MaxEncryptionChunkSize;

        // I tried using the .NET MultipartContent but the format is just different enough to not work for WinRM so
        // this code manually builds the MIME payload as a byte[] array.
        List<(byte[], int)> chunks = new();
        int finalSize = 0;
        ArrayPool<byte> pool = ArrayPool<byte>.Shared;
        try
        {
            while (toEncrypt.Length > 0)
            {
                int msgSize = Math.Min(toEncrypt.Length, chunkSize);
                (byte[] chunk, int encChunkSize) = EncryptWSManChunk(boundary, encryptor, toEncrypt[..msgSize], pool);
                chunks.Add((chunk, encChunkSize));
                finalSize += encChunkSize;
                toEncrypt = toEncrypt[msgSize..];
            }

            byte[] contentBytes = new byte[finalSize];
            int contentOffset = 0;
            foreach ((byte[] chunk, int chunkLength) in chunks)
            {
                Buffer.BlockCopy(chunk, 0, contentBytes, contentOffset, chunkLength);
                contentOffset += chunkLength;
            }

            string contentSubType = chunks.Count == 1 ? "multipart/encrypted" : "multipart/x-multi-encrypted";
            string contentType =
                $"{contentSubType};protocol=\"{encryptor.EncryptionProtocol}\";boundary=\"{boundary}\"";
            ByteArrayContent content = new(contentBytes);
            content.Headers.Remove("Content-Type");
            content.Headers.TryAddWithoutValidation("Content-Type", contentType);

            return content;
        }
        finally
        {
            foreach ((byte[] array, int _) in chunks)
            {
                pool.Return(array);
            }
        }
    }

    private async Task<string> ProcessResponse(HttpResponseMessage response)
    {
        MediaTypeHeaderValue? contentType = response.Content.Headers.ContentType;

        string contentTypeBase = contentType?.MediaType ?? "";
        if (!(contentTypeBase == "multipart/encrypted" || contentTypeBase == "multipart/x-multi-encrypted"))
        {
            return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }
        else if (_encryptor is null)
        {
            throw new ArgumentException("Received encrypted response but not encryption provider is set");
        }

        byte[] encData = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        return DecryptMimePayload(encData.AsSpan(), _encryptor);
    }

    private string DecryptMimePayload(Span<byte> payload, IWSManEncryptionContext encryptor)
    {
        // While the boundary text should be derived from the HTTP headers to form '--{boundary}\r\n' some endpoints,
        // like Exchange Servers, put a space after the hyphens to become '-- {boundary}\r\n'. Instead of this just
        // scan up to the first newline and use that value.
        Span<byte> newLine = stackalloc byte[] { 0x0D, 0x0A };
        int nextIdx = payload.IndexOf(newLine);
        byte[] boundaryBytes = payload[..nextIdx].ToArray();
        payload = payload[(nextIdx + 2)..];

        StringBuilder response = new();

        // The last payload in the MIME will have 2 extra bytes which are disregarded here.
        while (payload.Length > 2)
        {
            // // First MIME part contains the metadata, including the length of the plaintext data.
            nextIdx = payload.IndexOf(boundaryBytes);
            string entry = Encoding.UTF8.GetString(payload[..nextIdx]);
            Match m = Regex.Match(entry, "Length=(\\d+)", RegexOptions.IgnoreCase);
            if (!m.Success)
            {
                throw new ArgumentException("Invalid WSMan encryption payload - failed to find plaintext lenght size");
            }
            int expectedLength = int.Parse(m.Groups[1].Value);
            payload = payload[(nextIdx + boundaryBytes.Length + 2)..];

            // Second MIME part contains a known header and encrypted contents. Ignore the first Content-Type value and
            // go to the next newline which contains the encrypted payload.
            nextIdx = payload.IndexOf(newLine);
            payload = payload[(nextIdx + 2)..];
            nextIdx = payload.IndexOf(boundaryBytes);

            Span<byte> encryptedBlock = payload[..nextIdx];
            int headerLength = BitConverter.ToInt32(encryptedBlock[..4]);
            encryptedBlock = encryptedBlock[4..];
            Span<byte> header = encryptedBlock.Slice(0, headerLength);
            Span<byte> encData = encryptedBlock[headerLength..];

            payload = payload[(nextIdx + boundaryBytes.Length + 2)..];

            Span<byte> decData = encryptor.UnwrapWinRM(encryptedBlock, header, encData);
            if (decData.Length != expectedLength)
            {
                throw new ArgumentException("Mismatched WSMan encryption payload length");
            }
            response.Append(Encoding.UTF8.GetString(decData));
        }

        return response.ToString();
    }

    private (byte[], int) EncryptWSManChunk(string boundary, IWSManEncryptionContext encryptor, Span<byte> chunk,
        ArrayPool<byte> arrayPool)
    {
        byte[] encBytes = encryptor.WrapWinRM(chunk, out var headerLength, out var paddingLength);

        StringBuilder mpHeader = new();
        mpHeader.AppendFormat("--{0}\r\n", boundary);
        mpHeader.AppendFormat("Content-Type: {0}\r\n", encryptor.EncryptionProtocol);
        mpHeader.AppendFormat("OriginalContent: type={0};charset=UTF-8;Length={1}\r\n", CONTENT_TYPE,
            chunk.Length + paddingLength);
        mpHeader.AppendFormat("--{0}\r\n", boundary);
        mpHeader.Append("Content-Type: application/octet-stream\r\n");
        byte[] multipartHeader = Encoding.UTF8.GetBytes(mpHeader.ToString());
        byte[] multipartFooter = Encoding.UTF8.GetBytes($"--{boundary}--\r\n");

        int bufferLength = multipartHeader.Length + 4 + encBytes.Length + multipartFooter.Length;
        byte[] buffer = arrayPool.Rent(bufferLength);
        try
        {
            Span<byte> bufferSpan = buffer.AsSpan();

            multipartHeader.CopyTo(bufferSpan);
            bufferSpan = bufferSpan[multipartHeader.Length..];

            BitConverter.TryWriteBytes(bufferSpan, headerLength);
            bufferSpan = bufferSpan[4..];

            encBytes.CopyTo(bufferSpan);
            bufferSpan = bufferSpan[encBytes.Length..];

            multipartFooter.CopyTo(bufferSpan);

            return (buffer, bufferLength);
        }
        catch
        {
            arrayPool.Return(buffer);
            throw;
        }
    }

    private static HttpClient GetWSManHttpClient(TimeSpan connectTimeout)
    {
        // We need a custom handle to make the connection and do the TLS handshake before sending the request so that
        // the Negotiate authentication contain can contain the TLS channel binding data.
        SocketsHttpHandler httpHandler = new();
        httpHandler.ConnectTimeout = connectTimeout;
        httpHandler.ConnectCallback = async (context, cancelToken) =>
        {
            Socket socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                return await ConnectAsync(
                    socket,
                    context.DnsEndPoint,
                    context.InitialRequestMessage,
                    cancelToken);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        };

        HttpClient client = new(httpHandler, true);
        client.DefaultRequestHeaders.Add("User-Agent", "PSWSMan Client");
        client.DefaultRequestHeaders.Add("Accept-Encoding", "identity");
        return client;
    }

    private async static Task<Stream> ConnectAsync(Socket socket, DnsEndPoint endpoint, HttpRequestMessage request,
        CancellationToken cancelToken)
    {
        await socket.ConnectAsync(endpoint, cancelToken).ConfigureAwait(false);

        Stream stream = new NetworkStream(socket, ownsSocket: true);
        if (request is WSManInitialRequest wsmanRequest)
        {
            WSManConnection connection = wsmanRequest.Connection;

            if (connection.SslOptions is not null)
            {
                SslStream sslStream = new(stream);
                stream = sslStream;

                TlsSessionResumeSetting.ResetTlsResumeDelegate? resetTlsResumeSetting = null;
                if ((connection.SslOptions.ClientCertificates?.Count ?? 0) > 0)
                {
                    // We only need to disable TLS Resume when dealing with client certificates.
#if NET8_0_OR_GREATER
                    connection.SslOptions.AllowTlsResume = false;
#else
                    resetTlsResumeSetting = TlsSessionResumeSetting.DisableTlsSessionResume(sslStream);
#endif
                }
                try
                {
                    await sslStream.AuthenticateAsClientAsync(connection.SslOptions, cancelToken).ConfigureAwait(false);
                }
                catch
                {
                    sslStream.Dispose();
                    throw;
                }
                finally
                {
                    resetTlsResumeSetting?.Invoke();
                }

                connection.ChannelBindings = GetTlsChannelBindings(sslStream);
            }

            // Add the initial authentication headers now that the TLS bindings have been set.
            connection.AddAuthenticationHeaders(wsmanRequest, null);
        }

        return stream;
    }

    /// <summary>Get channel binding data for Negotiate auth</summary>
    /// <remarks>
    /// While .NET has it's own function to retrieve this value it returns an opaque pointer with no publicly
    /// documented structure. To avoid using any internal implementation details this just does the same work to
    /// achieve the same result.
    /// </remarks>
    /// <param name="tls">The SslStream that has been authenticated.</param>
    /// <returns>The channel binding data if available.</returns>
    private static ChannelBindings? GetTlsChannelBindings(SslStream tls)
    {
        if (tls.RemoteCertificate == null)
        {
            return null;
        }
        using X509Certificate2 cert = new(tls.RemoteCertificate);

        byte[] certHash;
        switch (cert.SignatureAlgorithm.Value)
        {
            case "2.16.840.1.101.3.4.2.2": // SHA384
            case "1.2.840.10045.4.3.3": // SHA384ECDSA
            case "1.2.840.113549.1.1.12": // SHA384RSA
                using (SHA384 hasher = SHA384.Create())
                    certHash = hasher.ComputeHash(cert.RawData);
                break;

            case "2.16.840.1.101.3.4.2.3": // SHA512
            case "1.2.840.10045.4.3.4": // SHA512ECDSA
            case "1.2.840.113549.1.1.13": // SHA512RSA
                using (SHA512 hasher = SHA512.Create())
                    certHash = hasher.ComputeHash(cert.RawData);
                break;

            // Older protocols default to SHA256, use this as a catch all in case of a weird algorithm.
            default:
                using (SHA256 hasher = SHA256.Create())
                    certHash = hasher.ComputeHash(cert.RawData);
                break;
        }

        byte[] prefix = Encoding.UTF8.GetBytes("tls-server-end-point:");
        byte[] finalCB = new byte[prefix.Length + certHash.Length];
        Array.Copy(prefix, 0, finalCB, 0, prefix.Length);
        Array.Copy(certHash, 0, finalCB, prefix.Length, certHash.Length);

        return new ChannelBindings()
        {
            ApplicationData = finalCB,
        };
    }

    public void Dispose()
    {
        _http?.Dispose();
        AuthContext?.Dispose();
        GC.SuppressFinalize(this);
    }
    ~WSManConnection() { Dispose(); }
}

