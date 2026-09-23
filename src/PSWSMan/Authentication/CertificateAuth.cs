using PSWSMan.Connection;
using System;
using System.Security.Cryptography.X509Certificates;

namespace PSWSMan.Authentication;

internal sealed class CertificateCredential : WSManCredential
{
    public CertificateCredential()
    { }

    public override IWSManAuthenticationContext CreateAuthContext(X509Certificate2? serverCertificate)
        => new CertificateAuthContext();
}

internal sealed class CertificateAuthContext : IWSManAuthenticationContext
{
    public bool Complete => false;  // Always include the authentication header in the request

    public string HttpAuthLabel => "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual";

    public string? AuthenticationStage => null;

    internal CertificateAuthContext()
    { }

    // Certificate auth is provided in the SslClientAuthenticationOptions.
    // This just ensures the correct header is set.
    public byte[]? Step(Span<byte> inToken)
        => [];

    public void Dispose()
    { }
}
