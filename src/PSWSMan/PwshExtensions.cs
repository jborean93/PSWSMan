using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace PSWSMan;

public enum AuthenticationMethod
{
    /// <summary>
    /// Selects the best negotiate method available which is Negotiate or uses Certificate auth is client certs are
    /// specified.
    /// </summary>
    Default,

    /// <summary>Simple Basic authentication, doesn't provide any encryption over HTTP.</summary>
    Basic,

    /// <summary>Tries Kerberos authentication with a fallback to NTLM if that's not available.</summary>
    Negotiate,

    /// <summary>Uses NTLM authentication, this is not as secure as Kerberos.</summary>
    NTLM,

    /// <summary>Uses Kerberos authentication, this has no fallback to NTLM if unavailable.</summary>
    Kerberos,

    /// <summary>
    /// CredSSP authentication to delegate your credentials to the remote host. Relies on Negotiate authentication
    /// internally and will be unavailable on Linux if the GSSAPI library is not found.
    /// </summary>
    CredSSP
}

public enum AuthenticationProvider
{
    /// <summary>
    /// Uses the process wide default authentication provider.
    /// </summary>
    Default,

    /// <summary>
    /// Uses the OS system authentication provider for authentication. On Windows this is SSPI which supports all auth
    /// methods. On macOS this is GSS.Framework which supports all auth methods. On Linux this is GSSAPI through either
    /// MIT krb5 or Heimdal which typically support Kerberos out of the box and NTLM with extra packages installed.
    /// GSSAPI on Linux is usually not provided out of the box and requires extra packages to be installed.
    /// </summary>
    System,

    /// <summary>
    /// Uses Devolutions.Sspi as the authentication provider which is a self contained Rust library that implements
    /// Kerberos and NTLM support without any system dependencies.
    /// </summary>
    Devolutions,
}

/// <summary>Used as a way to extend New-PSSessionOption by adding in extra options available in this lib.</summary>
public sealed class PSWSManSessionOption
{
    public const string PSWSMAN_SESSION_OPTION_PROP = "_PSWSManSessionOption";

    public AuthenticationMethod AuthMethod { get; set; } = AuthenticationMethod.Default;
    public AuthenticationProvider AuthProvider { get; set; } = AuthenticationProvider.Default;
    public string? SPNService { get; set; }
    public string? SPNHostName { get; set; }
    public bool RequestKerberosDelegate { get; set; }
    public SslClientAuthenticationOptions? TlsOption { get; set; }
    public AuthenticationMethod CredSSPAuthMethod { get; set; } = AuthenticationMethod.Default;
    public SslClientAuthenticationOptions? CredSSPTlsOption { get; set; }
    public X509Certificate? ClientCertificate { get; set; }
}
