using PSWSMan.Connection;
using System;
using System.Security.Cryptography.X509Certificates;

namespace PSWSMan.Authentication;

/// <summary>
/// Base class for credentials, providing the dispose pattern on top of
/// <see cref="IWSManCredential"/>.
/// </summary>
internal abstract class WSManCredential : IWSManCredential
{
    /// <inheritdoc />
    public abstract IWSManAuthenticationContext CreateAuthContext(X509Certificate2? serverCertificate);

    public virtual void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    protected virtual void Dispose(bool disposing)
    { }
    ~WSManCredential() => Dispose(false);
}
