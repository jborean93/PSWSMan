namespace PSWSMan.Authentication.Native;

using unsafe ReleaseCredFn = delegate* unmanaged[Cdecl]<
    uint*,  // minor_status
    void**, // cred_handle
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly ReleaseCredFn _releaseCred =
        (ReleaseCredFn)GetExport(module, "gss_release_cred");

    /// <summary>Releases a credential handle.</summary>
    /// <remarks>
    /// This is called from <see cref="SafeGssapiCred"/> during release so it reports the status rather than
    /// throwing. The minor status is not reported as nothing acts on it for a release.
    /// </remarks>
    /// <param name="credHandle">The credential to release, set to <c>GSS_C_NO_CREDENTIAL</c> on return.</param>
    /// <returns>The major status, 0 on success.</returns>
    public uint ReleaseCred(void** credHandle)
    {
        uint minorStatus;
        return _releaseCred(&minorStatus, credHandle);
    }
}
