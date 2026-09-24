using System;

namespace PSWSMan.Authentication.Native;

using unsafe AddOidSetMemberFn = delegate* unmanaged[Cdecl]<
    uint*,                      // minor_status
    void*,                      // member_oid
    Helpers.gss_OID_set_desc**, // oid_set
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly AddOidSetMemberFn _addOidSetMember =
        (AddOidSetMemberFn)GetExport(module, "gss_add_oid_set_member");

    /// <summary>Adds an OID to a set.</summary>
    /// <param name="memberOid">The encoded OID to add.</param>
    /// <param name="oidSet">The set to add it to, its handle is updated if the library reallocates the set.</param>
    /// <exception cref="GSSAPIException">Failed to add the member.</exception>
    public void AddOidSetMember(
        ReadOnlySpan<byte> memberOid,
        SafeGssapiOidSet oidSet)
    {
        using SafeHandleRef setRef = new(oidSet);

        byte* oidStorage = stackalloc byte[sizeof(Helpers.gss_OID_desc)];
        fixed (byte* oidPtr = memberOid)
        {
            void* oid = WriteOid(oidStorage, oidPtr, (uint)memberOid.Length);
            Helpers.gss_OID_set_desc* set = setRef.As<Helpers.gss_OID_set_desc>();

            uint minorStatus;
            uint majorStatus = _addOidSetMember(
                &minorStatus,
                oid,
                &set);
            if (majorStatus != GSS_S_COMPLETE)
                throw new GSSAPIException(this, majorStatus, minorStatus, "gss_add_oid_set_member");

            oidSet.UpdateHandle((IntPtr)set);
        }
    }
}
