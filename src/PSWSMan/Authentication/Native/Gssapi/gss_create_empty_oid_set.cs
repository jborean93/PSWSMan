using System;

namespace PSWSMan.Authentication.Native;

using unsafe CreateEmptyOidSetFn = delegate* unmanaged[Cdecl]<
    uint*,                      // minor_status
    Helpers.gss_OID_set_desc**, // oid_set
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly CreateEmptyOidSetFn _createEmptyOidSet =
        (CreateEmptyOidSetFn)GetExport(module, "gss_create_empty_oid_set");

    /// <summary>Creates an empty OID set to add members to.</summary>
    /// <returns>The handle to the set.</returns>
    /// <exception cref="GSSAPIException">Failed to create the set.</exception>
    public SafeGssapiOidSet CreateEmptyOidSet()
    {
        uint minorStatus;
        Helpers.gss_OID_set_desc* set;
        uint majorStatus = _createEmptyOidSet(&minorStatus, &set);
        if (majorStatus != GSS_S_COMPLETE)
            throw new GSSAPIException(this, majorStatus, minorStatus, "gss_create_empty_oid_set");

        return new SafeGssapiOidSet(this, (IntPtr)set);
    }
}
