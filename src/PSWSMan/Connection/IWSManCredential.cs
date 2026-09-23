using System;
using System.Security.Cryptography.X509Certificates;

namespace PSWSMan.Connection;

/// <summary>A credential that can produce a new authentication context for each connection.</summary>
/// <remarks>
/// A pool opens several connections to the same endpoint and each one authenticates on its own, so a credential is
/// asked for a fresh context every time a socket is opened.
/// </remarks>
internal interface IWSManCredential : IDisposable
{
    /// <summary>Creates a new authentication context for one connection.</summary>
    /// <param name="serverCertificate">
    /// The server certificate of the TLS session for channel binding, null when the connection is not over TLS. The
    /// caller disposes it after this returns so the context must copy anything it needs.
    /// </param>
    /// <returns>The context, owned and disposed by the connection.</returns>
    IWSManAuthenticationContext CreateAuthContext(X509Certificate2? serverCertificate);
}
