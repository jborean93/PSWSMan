using PSWSMan.Connection;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PSWSMan.Authentication;

internal sealed class BasicCredential : WSManCredential
{
    private readonly byte[] _authValue;

    public BasicCredential(string? username, string? password)
    {
        _authValue = Encoding.UTF8.GetBytes($"{username}:{password}");
    }

    public override IWSManAuthenticationContext CreateAuthContext(X509Certificate2? serverCertificate)
        => new BasicAuthContext(_authValue);
}

internal sealed class BasicAuthContext : IWSManAuthenticationContext
{
    private readonly byte[] _authToken;

    // Nothing to negotiate, Step provides the same header for every request.
    public bool Complete => true;

    public bool ExchangesTokens => false;

    public string HttpAuthLabel => "Basic";

    public string? AuthenticationStage => null;

    internal BasicAuthContext(byte[] authToken)
    {
        _authToken = authToken;
    }

    public byte[]? Step(Span<byte> inToken)
        => _authToken;

    public void Dispose()
    { }
}
