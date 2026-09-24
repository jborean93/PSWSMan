namespace PSWSMan.Authentication.Native;

using unsafe ReleaseNameFn = delegate* unmanaged[Cdecl]<
    uint*,  // minor_status
    void**, // name
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly ReleaseNameFn _releaseName =
        (ReleaseNameFn)GetExport(module, "gss_release_name");

    /// <summary>Releases a name object.</summary>
    /// <remarks>
    /// This is called from <see cref="SafeGssapiName"/> during release so it reports the status rather than
    /// throwing. The minor status is not reported as nothing acts on it for a release.
    /// </remarks>
    /// <param name="name">The name to release, set to <c>GSS_C_NO_NAME</c> on return.</param>
    /// <returns>The major status, 0 on success.</returns>
    public uint ReleaseName(void** name)
    {
        uint minorStatus;
        return _releaseName(&minorStatus, name);
    }
}
