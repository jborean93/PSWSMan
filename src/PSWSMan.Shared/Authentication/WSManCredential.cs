using System;

namespace PSWSMan.Shared.Authentication;

/// <summary>
/// A credential that can be used by WSMan to generate a new security context
/// when needed.
/// </summary>
public abstract class WSManCredential : IDisposable
{
    /// <summary>
    /// Generates a new security context with the current credentials. A WSMan
    /// connection may create multiple security contexts as needed when
    /// starting a new connection.
    /// </summary>
    protected internal abstract AuthenticationContext CreateAuthContext();

    public virtual void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    protected virtual void Dispose(bool disposing)
    { }
    ~WSManCredential() => Dispose(false);
}
