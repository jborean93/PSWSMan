namespace PSWSMan.Authentication.Native;

using unsafe FreeCredentialsHandleFn = delegate* unmanaged[Stdcall]<
    Helpers.SecHandle*, // phCredential
    int>;

internal sealed unsafe partial class SspiProvider
{
    private readonly FreeCredentialsHandleFn _freeCredentialsHandle =
        (FreeCredentialsHandleFn)GetExport(module, nameof(FreeCredentialsHandle));

    /// <summary>Notifies the security package that a credential is no longer needed.</summary>
    /// <remarks>
    /// This is called from <see cref="SafeSspiCredentialHandle"/> during release so it reports the status rather
    /// than throwing.
    /// </remarks>
    /// <param name="credential">The raw credential handle to free.</param>
    /// <returns>The SSPI status code, 0 on success.</returns>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/freecredentialshandle">FreeCredentialsHandle</see>
    public int FreeCredentialsHandle(Helpers.SecHandle* credential)
        => _freeCredentialsHandle(credential);
}
