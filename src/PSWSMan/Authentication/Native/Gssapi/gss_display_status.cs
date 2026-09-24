using System;

namespace PSWSMan.Authentication.Native;

using unsafe DisplayStatusFn = delegate* unmanaged[Cdecl]<
    uint*,                    // minor_status
    uint,                     // status_value
    int,                      // status_type
    void*,                    // mech_type
    uint*,                    // message_context
    Helpers.gss_buffer_desc*, // status_string
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly DisplayStatusFn _displayStatus =
        (DisplayStatusFn)GetExport(module, "gss_display_status");

    /// <summary>Gets a textual message for a status code.</summary>
    /// <remarks>
    /// This is used while building a <see cref="GSSAPIException"/> so it reports the status rather than throwing.
    /// The minor status is not reported as nothing acts on it here.
    /// </remarks>
    /// <param name="statusValue">The status code to describe.</param>
    /// <param name="statusType">Whether the code is a major or mechanism specific minor status.</param>
    /// <param name="mechType">The mechanism a minor status belongs to, empty for <c>GSS_C_NO_OID</c>.</param>
    /// <param name="messageContext">
    /// Tracks the position in a multi part message. Start at 0 and call again while it is non zero on return.
    /// </param>
    /// <param name="statusString">Receives the message, the caller releases it with <c>ReleaseBuffer</c>.</param>
    /// <returns>The major status, 0 on success.</returns>
    public uint DisplayStatus(
        uint statusValue,
        GssapiStatusType statusType,
        ReadOnlySpan<byte> mechType,
        uint* messageContext,
        Helpers.gss_buffer_desc* statusString)
    {
        byte* oidStorage = stackalloc byte[sizeof(Helpers.gss_OID_desc)];
        fixed (byte* mechPtr = mechType)
        {
            void* mech = WriteOid(oidStorage, mechPtr, (uint)mechType.Length);

            uint minorStatus;
            return _displayStatus(
                &minorStatus,
                statusValue,
                (int)statusType,
                mech,
                messageContext,
                statusString);
        }
    }
}
