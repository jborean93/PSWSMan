using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;

namespace PSWSMan;

public enum AuthenticationMethod
{
    /// <summary>Selects the best auth mechanism available.</summary>
    Default,

    Basic,

    Certificate,

    Negotiate,

    NTLM,

    Kerberos,

    CredSSP
}

internal abstract class AuthenticationProvider
{
    public abstract bool Complete { get; }
    public abstract bool WillEncrypt { get; }

    public abstract bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response);
    public virtual void SetChannelBindings(ChannelBindings? bindings) { }
    public virtual byte[] Wrap(byte[] data) => throw new NotImplementedException();
    public virtual byte[] Unwrap(byte[] data) => throw new NotImplementedException();
}

internal class BasicAuthProvider : AuthenticationProvider
{
    private readonly string _authValue;
    private bool _complete;

    public override bool Complete => _complete;
    public override bool WillEncrypt => false;

    public BasicAuthProvider(string? username, string? password)
        : this("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))) { }

    public BasicAuthProvider(string authValue)
    {
        _authValue = authValue;
    }

    public override bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response)
    {
        if (Complete)
        {
            throw new Exception("Auth provider is already completed");
        }

        request.Headers.Add("Authorization", _authValue);
        _complete = true;
        return true;
    }
}

internal class NegotiateAuthProvider : AuthenticationProvider
{
    private readonly bool _encrypt;
    private readonly SecurityContext _secContext;
    private readonly string _authHeaderName;

    public override bool Complete => _secContext.Complete;

    public override bool WillEncrypt => _encrypt;

    public NegotiateAuthProvider(string? username, string? password, string service, string hostname,
        AuthenticationMethod method, string authHeaderName, bool encrypt)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            _secContext = new SspiContext(
                username,
                password,
                method,
                $"{service}/{hostname}");
        }
        else
        {
            _secContext = new GssapiContext(
                username,
                password,
                method,
                $"{service}@{hostname}");
        }
        _authHeaderName = authHeaderName;
        _encrypt = encrypt;
    }

    public override bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response)
    {
        if (Complete)
        {
            throw new Exception("Auth provider is already completed");
        }

        AuthenticationHeaderValue? respAuthHeader = response?.Headers.WwwAuthenticate.FirstOrDefault();
        byte[]? inputToken = null;
        if (respAuthHeader is not null)
        {
            if (respAuthHeader.Scheme != _authHeaderName)
            {
                throw new Exception($"Unexpected WWW-Authenticate header response {respAuthHeader.Scheme}");
            }
            inputToken = Convert.FromBase64String(respAuthHeader.Parameter ?? "");
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

    public override byte[] Wrap(byte[] data)
    {
        return _secContext.Wrap(data, true);
    }

    public override byte[] Unwrap(byte[] data)
    {
        return _secContext.Unwrap(data);
    }

    public override void SetChannelBindings(ChannelBindings? bindings)
    {
        _secContext.SetChannelBindings(bindings);
    }
}
