using System;

namespace PSWSMan.Shared.Authentication;

public sealed class CertificateCredential : WSManCredential
{
    public CertificateCredential()
    { }

    protected internal override AuthenticationContext CreateAuthContext()
        => new CertificateAuthContext();
}

public sealed class CertificateAuthContext : AuthenticationContext
{
    public override bool Complete => false;

    public override string HttpAuthLabel => "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual";

    internal CertificateAuthContext()
    { }

    // Certificate auth is provided in the SslClientAuthenticationOptions.
    // This just ensures the correct header is set.
    protected internal override byte[]? Step(Span<byte> inToken, NegotiateOptions options, ChannelBindings? bindings)
        => Array.Empty<byte>();
}
