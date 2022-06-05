using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;

namespace PSWSMan;

internal class NegotiateAuthProvider : AuthenticationProvider, IWinRMEncryptor
{
    private readonly SecurityContext _secContext;
    private readonly string _authHeaderName;

    public override bool Complete => _secContext.Complete;

    public string EncryptionProtocol
    {
        get
        {
            string authProtocol = _authHeaderName == "Kerberos" ? "Kerberos" : "SPNEGO";
            return $"application/HTTP-{authProtocol}-session-encrypted";
        }
    }

    public NegotiateAuthProvider(string? username, string? password, string service, string hostname,
        AuthenticationMethod method, string authHeaderName, bool requestDelegate)
    {
        _secContext = SecurityContext.GetPlatformSecurityContext(username, password, method, service, hostname,
            requestDelegate);
        _authHeaderName = authHeaderName;
    }

    public override bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response)
    {
        if (Complete)
        {
            return false;
        }

        AuthenticationHeaderValue[]? respAuthHeader = response?.Headers.WwwAuthenticate.ToArray();
        byte[]? inputToken = null;
        if (respAuthHeader?.Length == 1)
        {
            inputToken = Convert.FromBase64String(respAuthHeader[0].Parameter ?? "");
        }
        else if (response is not null)
        {
            // This happens if the auth failed in the previous step failed, return the response as is.
            return false;
        }

        byte[] outputToken = _secContext.Step(inputToken);
        if (outputToken.Length == 0)
        {
            return false;
        }

        string authValue = Convert.ToBase64String(outputToken);
        request.Headers.Add("Authorization", $"{_authHeaderName} {authValue}");
        return true;
    }

    public byte[] Encrypt(Span<byte> data, out int paddingLength)
    {
        byte[] header = _secContext.WrapWinRM(data, out var encryptedLength, out paddingLength);
        byte[] wrappedData = new byte[4 + header.Length + encryptedLength];
        BitConverter.TryWriteBytes(wrappedData.AsSpan(0, 4), header.Length);
        Buffer.BlockCopy(header, 0, wrappedData, 4, header.Length);
        data[..encryptedLength].CopyTo(wrappedData.AsSpan(4 + header.Length));

        return wrappedData;
    }

    public Span<byte> Decrypt(Span<byte> data)
    {
        return _secContext.UnwrapWinRM(data);
    }

    public override void SetChannelBindings(ChannelBindings? bindings)
    {
        _secContext.SetChannelBindings(bindings);
    }

    public override void Dispose()
    {
        _secContext.Dispose();
        GC.SuppressFinalize(this);
    }
}
