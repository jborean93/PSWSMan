using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
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

internal class WSManConnection : IDisposable
{
    private readonly AuthenticationProvider _authProvider;
    private readonly Uri _connectionUri;
    private readonly SslClientAuthenticationOptions? _sslOptions;
    private HttpClient? _http;

    public WSManConnection(Uri connectionUri, AuthenticationProvider authProvider,
        SslClientAuthenticationOptions? sslOptions)
    {
        _connectionUri = connectionUri;
        _authProvider = authProvider;
        _sslOptions = sslOptions;
    }

    public async Task<string> SendMessage(string message)
    {
        HttpContent content;
        HttpRequestMessage request;
        HttpResponseMessage response;

        if (_http == null)
        {
            _http = GetWSManHttpClient();

            // If doing HTTP encryption, the initial content must be nothing to avoid disclosing the information.
            content = PrepareContent(message);

            // The WSMan http client is set to call the authentication provider and add the first token once the socket
            // is connected and TLS negotiated (if needed). This is required as some auth providers require the TLS
            // channel binding tokens before creating the first token. Subsequent authentication steps are done here
            // after the connection is set up.
            request = new WSManInitialRequest(
                HttpMethod.Post,
                _connectionUri,
                _authProvider,
                _sslOptions);
            request.Content = content;
            response = await _http.SendAsync(request).ConfigureAwait(false);

            while (!_authProvider.Complete)
            {
                request = new HttpRequestMessage(HttpMethod.Post, _connectionUri);
                request.Content = content;
                if (!_authProvider.AddAuthenticationHeaders(request, response))
                {
                    // No more rounds needed to authenticate with the remote host.
                    break;
                }
                response = await _http.SendAsync(request).ConfigureAwait(false);
            }

            // FIXME: Check for WSManFault contents on a 500 and don't raise.
            response.EnsureSuccessStatusCode();

            // If not doing HTTP encryption, the response is the actual response which needs to be returned.
            if (!_authProvider.WillEncrypt)
            {
                return await ProcessResponse(response).ConfigureAwait(false);
            }
        }

        content = PrepareContent(message);
        request = new(HttpMethod.Post, _connectionUri);
        request.Content = content;

        response = await _http.SendAsync(request).ConfigureAwait(false);

        return await ProcessResponse(response).ConfigureAwait(false);
    }

    private HttpContent PrepareContent(string message)
    {
        if (_authProvider.WillEncrypt)
        {
            if (_authProvider.Complete)
            {
                return PrepareEncryptedContent(message);
            }
            else
            {
                // The initial request needs to be empty as it's setting up the security context for later encryption.
                return new StringContent("");
            }
        }
        else
        {
            return new StringContent(message, Encoding.UTF8, "application/soap+xml");
        }
    }

    private HttpContent PrepareEncryptedContent(string message)
    {
        // This originally used MultipartContent but the output format didn't meet what WSMan expects.
        string encryptionProtocol = "application/HTTP-SPNEGO-session-encrypted";
        string boundary = "Encrypted Boundary";
        string contentType = $"multipart/encrypted;protocol=\"{encryptionProtocol}\";boundary=\"{boundary}\"";

        // FIXME: Call WrapIOV to get this properly for Kerberos.
        byte[] encBytes = _authProvider.Wrap(Encoding.UTF8.GetBytes(message));
        int signatureLength = 16;

        StringBuilder multipartBuilder = new();
        multipartBuilder.AppendFormat("--{0}\r\n", boundary);
        multipartBuilder.AppendFormat("Content-Type: {0}\r\n", encryptionProtocol);
        multipartBuilder.AppendFormat("OriginalContent: type=application/soap+xml;charset=UTF-8;Length={0}\r\n", message.Length);
        multipartBuilder.AppendFormat("--{0}\r\n", boundary);
        multipartBuilder.Append("Content-Type: application/octet-stream\r\n");
        byte[] multipartHeader = Encoding.UTF8.GetBytes(multipartBuilder.ToString());
        byte[] multipartFooter = Encoding.UTF8.GetBytes($"--{boundary}--\r\n");

        ArrayPool<byte> shared = ArrayPool<byte>.Shared;
        byte[] rentedArray = shared.Rent(multipartHeader.Length + 4 + encBytes.Length + multipartFooter.Length);
        try
        {
            int offset = 0;
            Buffer.BlockCopy(multipartHeader, 0, rentedArray, 0, multipartHeader.Length);
            offset += multipartBuilder.Length;

            rentedArray[offset] = (byte)signatureLength;
            rentedArray[offset + 1] = (byte)(signatureLength >> 8);
            rentedArray[offset + 2] = (byte)(signatureLength >> 16);
            rentedArray[offset + 3] = (byte)(signatureLength >> 24);
            offset += 4;

            Buffer.BlockCopy(encBytes, 0, rentedArray, multipartHeader.Length + 4, encBytes.Length);
            offset += encBytes.Length;

            Buffer.BlockCopy(multipartFooter, 0, rentedArray, offset, multipartFooter.Length);
            offset += multipartFooter.Length;

            ByteArrayContent content = new(rentedArray, 0, offset);
            content.Headers.Remove("Content-Type");
            content.Headers.TryAddWithoutValidation("Content-Type", contentType);

            return content;
        }
        finally
        {
            shared.Return(rentedArray);
        }
    }

    private async Task<string> ProcessResponse(HttpResponseMessage response)
    {
        string contentType = response.Content.Headers.ContentType?.MediaType ?? "";
        if (!(contentType == "multipart/encrypted" || contentType == "multipart/x-multi-encrypted"))
        {
            return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }

        string? protocol = response.Content.Headers.ContentType?.Parameters
            .Where(p => p.Name == "protocol")
            .Select(p => p.Value)
            .FirstOrDefault()
            ?.Trim('\\', '"');
        string? boundary = response.Content.Headers.ContentType?.Parameters
            .Where(p => p.Name == "boundary")
            .Select(p => p.Value)
            .FirstOrDefault()
            ?.Trim('\\', '"');
        if (string.IsNullOrWhiteSpace(protocol) || string.IsNullOrWhiteSpace(boundary))
        {
            throw new Exception("FIXME: unknown protocol or boundary");
        }

        byte[] encData = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        return DecryptMimePayload(protocol, boundary, encData.AsSpan());
    }

    private string DecryptMimePayload(string protocol, string boundary, Span<byte> payload)
    {
        // Starting to Exchange has a space after the '--' so just split by the boundary itself.
        Span<byte> boundaryPattern = Encoding.UTF8.GetBytes(boundary).AsSpan();

        int boundaryIdx = payload.IndexOf(boundaryPattern);
        payload = payload[(boundaryIdx + boundaryPattern.Length)..];

        int? expectedLength = null;
        int? signatureLength = null;
        Span<byte> encryptedData = default;
        while ((boundaryIdx = payload.IndexOf(boundaryPattern)) != -1)
        {
            string entry = Encoding.UTF8.GetString(payload[..boundaryIdx]).Trim('\r', '\n', '-');
            string a;
            if (entry.StartsWith($"Content-Type: {protocol}"))
            {
                Match m = Regex.Match(entry, "Length=(\\d+)", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    expectedLength = int.Parse(m.Groups[1].Value);
                }
            }
            else if (entry.StartsWith("Content-Type: application/octet-stream"))
            {
                // Length here is the Content-Type entry + \r\n on either side.
                int startIdx = 42;
                int endIdx = payload[..boundaryIdx].LastIndexOf(new byte[] { 45, 45 }.AsSpan());
                signatureLength = BitConverter.ToInt32(payload[startIdx..(startIdx + 4)]);
                encryptedData = payload[(startIdx + 4)..endIdx];
            }

            payload = payload[(boundaryIdx + boundaryPattern.Length)..];
        }

        if (expectedLength == null || signatureLength == null || encryptedData.Length == 0)
        {
            throw new Exception("FIXME: Failed to decrypt encrypted MIME payload");
        }

        byte[] decData = _authProvider.Unwrap(encryptedData.ToArray());
        string decPayload = Encoding.UTF8.GetString(decData);
        if (decPayload.Length != expectedLength)
        {
            throw new Exception("FIXME: Unexpected decrypted length");
        }

        return decPayload;
    }

    public void Dispose()
    {
        _http?.Dispose();
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
