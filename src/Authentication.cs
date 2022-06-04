using System;
using System.Net.Http;

namespace PSWSMan;

public enum AuthenticationMethod
{
    /// <summary>
    /// Selects the best auth mechanism available. The default is Negotiate if running on Windows or the GSSAPI library
    /// is installed and loaded. Otherwise it falls back to Basic auth if GSSAPI is not available.
    /// </summary>
    Default,

    /// <summary>Simple Basic authentication, doesn't provide any encryption over HTTP.</summary>
    Basic,

    /// <summary>X.509 certificate authentication over HTTPS.</summary>
    Certificate,

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

/// <summary>Base class used for WinRM authentication.</summary>
internal abstract class AuthenticationProvider : IDisposable
{
    /// <summary>Whether the authentication phase is complete.</summary>
    public abstract bool Complete { get; }

    /// <summary>Add the authentication headers to the message request.</summary>
    /// <param name="request">The HTTP request to add the authentication headers to.</param>
    /// <param name="response">The response, if there was one, to process for the authentication step.</param>
    /// <returns>Whether any headers were added to the request, or false if no more requests are needed.</returns>
    public abstract bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response);

    /// <summary>Set channel binding information on the auth provider.</summary>
    /// <param name="bindings">The bindings to set.</param>
    public virtual void SetChannelBindings(ChannelBindings? bindings) { }

    public virtual void Dispose() => GC.SuppressFinalize(this);
    ~AuthenticationProvider() => Dispose();
}
