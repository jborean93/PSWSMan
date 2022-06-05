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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan;

internal class WSManInitialRequest : HttpRequestMessage
{
    internal AuthenticationProvider Authentication { get; }
    internal SslClientAuthenticationOptions? SslOptions { get; set; }

    public WSManInitialRequest(HttpMethod method, Uri uri, AuthenticationProvider authProvider,
        SslClientAuthenticationOptions? sslOptions)
        : base(method, uri)
    {
        Authentication = authProvider;
        SslOptions = sslOptions;
    }
}

/// <summary>Raw WSMan HTTP connection class.</summary>
internal class WSManConnection : IDisposable
{
    private const string CONTENT_TYPE = "application/soap+xml";

    private readonly AuthenticationProvider _authProvider;
    private readonly Uri _connectionUri;
    private readonly SslClientAuthenticationOptions? _sslOptions;
    private readonly IWinRMEncryptor? _encryptor;

    private HttpClient? _http;

    /// <summary>Create connection for WSMan payloads</summary>
    /// <param name="connectionUri">The connection URI.</param>
    /// <param name="authProvider">The authentication provider used for the connection.</param>
    /// <param name="sslOptions">Set the TLS connection options for a HTTPS connection.</param>
    /// <param name="encrypt">
    /// Encrypt the payloads using the authentication provider. If true the authProvider must implement
    /// IWinRMEncryptor.
    /// </param>
    public WSManConnection(Uri connectionUri, AuthenticationProvider authProvider,
        SslClientAuthenticationOptions? sslOptions, bool encrypt)
    {
        _connectionUri = connectionUri;
        _authProvider = authProvider;
        _sslOptions = sslOptions;

        if (encrypt)
        {
            if (authProvider is not IWinRMEncryptor)
            {
                string provClass = authProvider.GetType().Name;
                throw new InvalidOperationException(
                    $"Cannot encrypt WSMan payload as {provClass} does not support message encryption.");
            }
            _encryptor = (IWinRMEncryptor)authProvider;
        }
    }

    /// <summary>Send a HTTP payload as a POST request.</summary>
    /// <param name="message">The HTTP payload to send.</param>
    /// <returns>The response for this request.</returns>
    public async Task<string> SendMessage(string message)
    {
        HttpRequestMessage request;

        HttpContent? content = null;
        HttpResponseMessage? response = null;

        if (_http == null)
        {
            _http = GetWSManHttpClient();

            content = PrepareContent(message);
            response = await Authenticate(_http, content);

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

            response = await _http.SendAsync(request).ConfigureAwait(false);
        }

        string responseContent = await ProcessResponse(response).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(responseContent))
        {
            response.EnsureSuccessStatusCode();
        }
        return responseContent;
    }

    private async Task<HttpResponseMessage> Authenticate(HttpClient http, HttpContent content)
    {
        // The WSMan http client is set to call the authentication provider and add the first token once the socket
        // is connected and TLS negotiated (if needed). This is required as some auth providers require the TLS
        // channel binding tokens before creating the first token. Subsequent authentication steps are done here
        // after the connection is set up.
        HttpRequestMessage request = new WSManInitialRequest(
            HttpMethod.Post,
            _connectionUri,
            _authProvider,
            _sslOptions);
        request.Content = content;
        HttpResponseMessage response = await http.SendAsync(request).ConfigureAwait(false);

        while (!_authProvider.Complete)
        {
            request = new HttpRequestMessage(HttpMethod.Post, _connectionUri);
            request.Content = content;
            if (!_authProvider.AddAuthenticationHeaders(request, response))
            {
                // No more rounds needed to authenticate with the remote host.
                break;
            }
            response = await http.SendAsync(request).ConfigureAwait(false);
        }

        return response;
    }

    private HttpContent PrepareContent(string message)
    {
        if (_encryptor is not null)
        {
            if (_authProvider.Complete)
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

    private HttpContent PrepareEncryptedContent(string message, IWinRMEncryptor encryptor)
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

        string? boundary = contentType?.Parameters
            .Where(p => p.Name == "boundary")
            .Select(p => p.Value)
            .FirstOrDefault()
            ?.Trim('\\', '"');
        if (string.IsNullOrWhiteSpace(boundary))
        {
            throw new ArgumentException($"Failed to determine encryption boundary from '{contentType}'");
        }

        byte[] encData = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        return DecryptMimePayload(boundary, encData.AsSpan(), _encryptor);
    }

    private string DecryptMimePayload(string boundary, Span<byte> payload, IWinRMEncryptor encryptor)
    {
        // The MIME payload from Exchange has a space after the '--' so just split by the boundary itself.
        Span<byte> mimeSeparator = stackalloc byte[] { 45, 45 };
        Span<byte> boundaryPattern = Encoding.UTF8.GetBytes(boundary).AsSpan();

        // Ignore the start -- and end --\r\n
        int boundaryIdx = payload.IndexOf(boundaryPattern);
        payload = payload[(boundaryIdx + boundaryPattern.Length)..(payload.Length - 4)];
        StringBuilder response = new();

        while (payload.Length > 0)
        {
            // First MIME part contains the metadata, including the length of the plaintext data.
            boundaryIdx = payload.IndexOf(boundaryPattern);
            string entry = Encoding.UTF8.GetString(payload[..boundaryIdx]).Trim('\r', '\n', '-');
            Match m = Regex.Match(entry, "Length=(\\d+)", RegexOptions.IgnoreCase);
            if (!m.Success)
            {
                throw new ArgumentException("Invalid WSMan encryption payload - failed to find plaintext lenght size");
            }
            int expectedLength = int.Parse(m.Groups[1].Value);
            payload = payload[(boundaryIdx + boundaryPattern.Length)..];

            // Second MIME part contains a known header and encrypted contents.
            boundaryIdx = payload.IndexOf(boundaryPattern);

            // Length here is the '\r\nContent-Type: application/octet-stream\r\n' entry.
            const int startIdx = 42;
            int endIdx = payload[..boundaryIdx].LastIndexOf(mimeSeparator);
            Span<byte> encryptedData = payload[startIdx..endIdx];
            payload = payload[(boundaryIdx + boundaryPattern.Length)..];

            Span<byte> decData = encryptor.Decrypt(encryptedData);
            if (decData.Length != expectedLength)
            {
                throw new ArgumentException("Mismatched WSMan encryption payload length");
            }
            response.Append(Encoding.UTF8.GetString(decData));
        }

        return response.ToString();
    }

    private (byte[], int) EncryptWSManChunk(string boundary, IWinRMEncryptor encryptor, Span<byte> chunk,
        ArrayPool<byte> arrayPool)
    {
        byte[] encData = encryptor.Encrypt(chunk, out var paddingLength);

        StringBuilder mpHeader = new();
        mpHeader.AppendFormat("--{0}\r\n", boundary);
        mpHeader.AppendFormat("Content-Type: {0}\r\n", encryptor.EncryptionProtocol);
        mpHeader.AppendFormat("OriginalContent: type={0};charset=UTF-8;Length={1}\r\n", CONTENT_TYPE,
            chunk.Length + paddingLength);
        mpHeader.AppendFormat("--{0}\r\n", boundary);
        mpHeader.Append("Content-Type: application/octet-stream\r\n");
        byte[] multipartHeader = Encoding.UTF8.GetBytes(mpHeader.ToString());
        byte[] multipartFooter = Encoding.UTF8.GetBytes($"--{boundary}--\r\n");

        int encryptedLength = multipartHeader.Length + encData.Length + multipartFooter.Length;
        byte[] buffer = arrayPool.Rent(encryptedLength);
        try
        {
            int offset = 0;

            Buffer.BlockCopy(multipartHeader, 0, buffer, 0, multipartHeader.Length);
            offset += multipartHeader.Length;

            Buffer.BlockCopy(encData, 0, buffer, offset, encData.Length);
            offset += encData.Length;

            Buffer.BlockCopy(multipartFooter, 0, buffer, offset, multipartFooter.Length);

            return (buffer, encryptedLength);
        }
        catch
        {
            arrayPool.Return(buffer);
            throw;
        }
    }

    public void Dispose()
    {
        _http?.Dispose();
        _authProvider.Dispose();
        GC.SuppressFinalize(this);
    }
    ~WSManConnection() { Dispose(); }

    private static HttpClient GetWSManHttpClient()
    {
        // We need a custom handle to make the connection and do the TLS handshake before sending the request so that
        // the Negotiate authentication contain can contain the TLS channel binding data.
        SocketsHttpHandler httpHandler = new();
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
            AuthenticationProvider authProvider = wsmanRequest.Authentication;
            if (wsmanRequest.SslOptions is not null)
            {
                SslStream sslStream = new(stream);
                stream = sslStream;

                try
                {
                    await sslStream.AuthenticateAsClientAsync(wsmanRequest.SslOptions, cancelToken).ConfigureAwait(false);
                }
                catch
                {
                    sslStream.Dispose();
                    throw;
                }

                authProvider.SetChannelBindings(GetTlsChannelBindings(sslStream));
            }

            // Add the initial authentication headers now that the TLS bindings have been set.
            authProvider.AddAuthenticationHeaders(wsmanRequest, null);
        }

        return stream;
    }

    /// <summary>Get channel binding data for SASL auth</summary>
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
}
