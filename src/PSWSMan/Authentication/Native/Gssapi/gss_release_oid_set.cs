namespace PSWSMan.Authentication.Native;

using unsafe ReleaseOidSetFn = delegate* unmanaged[Cdecl]<
    uint*,                      // minor_status
    Helpers.gss_OID_set_desc**, // set
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly ReleaseOidSetFn _releaseOidSet =
        (ReleaseOidSetFn)GetExport(module, "gss_release_oid_set");

    /// <summary>Releases an OID set.</summary>
    /// <remarks>
    /// This is called from <see cref="SafeGssapiOidSet"/> during release so it reports the status rather than
    /// throwing. The minor status is not reported as nothing acts on it for a release.
    /// </remarks>
    /// <param name="set">The set to release, set to <c>GSS_C_NO_OID_SET</c> on return.</param>
    /// <returns>The major status, 0 on success.</returns>
    public uint ReleaseOidSet(Helpers.gss_OID_set_desc** set)
    {
        uint minorStatus;
        return _releaseOidSet(&minorStatus, set);
    }
}
