namespace PSWSMan.Authentication.Native;

using unsafe DeleteSecurityContextFn = delegate* unmanaged[Stdcall]<
    Helpers.SecHandle*, // phContext
    int>;

internal sealed unsafe partial class SspiProvider
{
    private readonly DeleteSecurityContextFn _deleteSecurityContext =
        (DeleteSecurityContextFn)GetExport(module, nameof(DeleteSecurityContext));

    /// <summary>Deletes the local data structures associated with the security context.</summary>
    /// <remarks>
    /// This is called from <see cref="SafeSspiContextHandle"/> during release so it reports the status rather
    /// than throwing.
    /// </remarks>
    /// <param name="context">The raw context handle to delete.</param>
    /// <returns>The SSPI status code, 0 on success.</returns>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/deletesecuritycontext">DeleteSecurityContext</see>
    public int DeleteSecurityContext(Helpers.SecHandle* context)
        => _deleteSecurityContext(context);
}
