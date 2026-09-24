using PSWSMan.Connection;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PSWSMan.Authentication;

/// <summary>
/// Options to request during the negotiate authentication stepping. The values
/// are based on GSSAPI but are mapped internally to the SSPI equivalents on
/// Windows.
/// </summary>
[Flags]
internal enum NegotiateRequestFlags
{
    None = 0x00000000,
    Delegate = 0x00000001,
    MutualAuth = 0x00000002,
    ReplayDetect = 0x00000004,
    SequenceDetect = 0x00000008,
    Confidentiality = 0x00000010,
    Integrity = 0x00000020,
    Anonymous = 0x00000040,
    Identify = 0x00002000,
    DelegatePolicy = 0x00008000,

    Default = NegotiateRequestFlags.MutualAuth | NegotiateRequestFlags.ReplayDetect |
        NegotiateRequestFlags.SequenceDetect | NegotiateRequestFlags.Confidentiality |
        NegotiateRequestFlags.Integrity,
}

/// <summary>
/// Specifies the authentication method used by the Negotiate context.
/// </summary>
internal enum NegotiateMethod
{
    NTLM,
    Kerberos,
    Negotiate,
}

/// <summary>
/// Channel bindings that can be supplied to a INegotiateContext to bind the
/// authentication context to the transport layer.
/// </summary>
/// <remarks>
/// WSMan will only set the ApplicationData byte value to the one expected by
/// Windows. The other properties are just set for completeness.
/// </remarks>
internal sealed class ChannelBindings
{
    public int InitiatorAddrType { get; set; }
    public byte[]? InitiatorAddr { get; set; }
    public int AcceptorAddrType { get; set; }
    public byte[]? AcceptorAddr { get; set; }
    public byte[]? ApplicationData { get; set; }

    /// <summary>Builds the tls-server-end-point channel bindings for a TLS server certificate.</summary>
    /// <remarks>
    /// While .NET has its own function to retrieve this value it returns an opaque pointer with no publicly
    /// documented structure. To avoid using any internal implementation details this just does the same work to
    /// achieve the same result.
    /// </remarks>
    /// <param name="certificate">The server certificate of the TLS session.</param>
    /// <returns>The channel bindings with the ApplicationData set to the hashed certificate.</returns>
    public static ChannelBindings FromTlsServerCertificate(X509Certificate2 certificate)
    {
        byte[] certHash = certificate.SignatureAlgorithm.Value switch
        {
            "2.16.840.1.101.3.4.2.2" or // SHA384
            "1.2.840.10045.4.3.3" or // SHA384ECDSA
            "1.2.840.113549.1.1.12" // SHA384RSA
                => SHA384.HashData(certificate.RawData),

            "2.16.840.1.101.3.4.2.3" or // SHA512
            "1.2.840.10045.4.3.4" or // SHA512ECDSA
            "1.2.840.113549.1.1.13" // SHA512RSA
                => SHA512.HashData(certificate.RawData),

            // Older protocols default to SHA256, use this as a catch all in case of a weird algorithm.
            _ => SHA256.HashData(certificate.RawData),
        };

        byte[] prefix = Encoding.UTF8.GetBytes("tls-server-end-point:");
        byte[] applicationData = new byte[prefix.Length + certHash.Length];
        prefix.CopyTo(applicationData, 0);
        certHash.CopyTo(applicationData, prefix.Length);

        return new ChannelBindings()
        {
            ApplicationData = applicationData,
        };
    }
}

/// <summary>
/// Extra options specific to Negotiate authentication to set on the authentication context.
/// </summary>
internal sealed class NegotiateOptions
{
    public NegotiateRequestFlags Flags { get; set; } = NegotiateRequestFlags.Default;
    public string? SPNService { get; set; }
    public string? SPNHostName { get; set; }
}
/// <summary>
/// Base class for Negotiate protocol contexts (Kerberos, NTLM, SPNEGO). On top of
/// <see cref="IWSManAuthenticationContext"/> it provides the wrap and unwrap
/// operations CredSSP uses to protect its tokens.
/// </summary>
internal abstract class NegotiateAuthContext : IWSManAuthenticationContext
{
    /// <summary>The negotiate options the credential was created with.</summary>
    protected NegotiateOptions Options { get; }

    /// <summary>The channel bindings of the connection, null when not over TLS.</summary>
    protected ChannelBindings? Bindings { get; }

    /// <param name="options">The negotiate options the credential was created with.</param>
    /// <param name="serverCertificate">The TLS server certificate to bind to, null when not over TLS.</param>
    protected NegotiateAuthContext(NegotiateOptions options, X509Certificate2? serverCertificate)
    {
        Options = options;
        Bindings = serverCertificate is null ? null : ChannelBindings.FromTlsServerCertificate(serverCertificate);
    }

    /// <inheritdoc />
    public abstract bool Complete { get; }

    public bool ExchangesTokens => true;

    /// <inheritdoc />
    public abstract string HttpAuthLabel { get; }

    /// <inheritdoc />
    public virtual string? AuthenticationStage => null;

    /// <inheritdoc />
    public abstract byte[]? Step(Span<byte> inToken);

    /// <summary>Wraps the data as a single stream.</summary>
    /// <remarks>
    /// Some platforms may mutate the input data while others won't.
    /// Don't rely on the input data to not change and always use the return
    /// value to reference the newly wrapped data. This is used by CredSSP
    /// to wrap the authentication tokens it sends post authentication.
    /// </remarks>
    /// <param name="data">The data to wrap.</param>
    /// <returns>The wrapped data.</returns>
    protected internal abstract byte[] Wrap(Span<byte> data);

    /// <summary>Unwraps the data as a single stream, in place.</summary>
    /// <remarks>
    /// The plaintext ends up inside the input buffer and a slice of it is
    /// returned. Mechanisms that cannot decrypt in place copy their output back
    /// over the input, so the input is consumed either way. This is used by
    /// CredSSP to unwrap the authentication tokens it receives post
    /// authentication.
    /// </remarks>
    /// <param name="data">The data to unwrap, overwritten with the plaintext.</param>
    /// <returns>The slice of <paramref name="data"/> holding the plaintext.</returns>
    protected internal abstract Span<byte> Unwrap(Span<byte> data);

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    { }
}
