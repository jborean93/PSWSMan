using System;

namespace PSWSMan.Authentication.Native;

using unsafe WrapIovLengthFn = delegate* unmanaged[Cdecl]<
    uint*, // minor_status
    void*, // context_handle
    int,   // conf_req_flag
    uint,  // qop_req
    int*,  // conf_state
    void*, // iov
    int,   // iov_count
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly WrapIovLengthFn _wrapIovLength =
        (WrapIovLengthFn)GetExport(module, IovExport(isGssFramework, "gss_wrap_iov_length"));

    /// <summary>Fills in the lengths of the header, padding and trailer buffers that <c>WrapIov</c> would produce.</summary>
    /// <remarks>Only lengths are read and written, no buffer memory is touched or allocated.</remarks>
    /// <param name="context">The context the message would be wrapped with.</param>
    /// <param name="confReqFlag">Non zero for encryption, 0 for signing only.</param>
    /// <param name="qopReq">The quality of protection to request, 0 for the default.</param>
    /// <param name="confState">Receives whether the message would be encrypted, or <c>null</c> if not needed.</param>
    /// <param name="iov">The IOV buffers with the data length set, updated with the other lengths.</param>
    /// <exception cref="GSSAPIException">Failed to compute the lengths.</exception>
    public void WrapIovLength(
        SafeGssapiSecContext context,
        int confReqFlag,
        uint qopReq,
        int* confState,
        Span<IOVBuffer> iov)
    {
        using SafeHandleRef contextRef = new(context);

        byte* iovStorage = stackalloc byte[sizeof(Helpers.gss_iov_buffer_desc) * iov.Length];
        WriteIov(iovStorage, iov);

        uint minorStatus;
        uint majorStatus = _wrapIovLength(
            &minorStatus,
            contextRef.Pointer,
            confReqFlag,
            qopReq,
            confState,
            iovStorage,
            iov.Length);
        ReadIov(iovStorage, iov);

        if (majorStatus != GSS_S_COMPLETE)
            throw new GSSAPIException(this, majorStatus, minorStatus, "gss_wrap_iov_length");
    }
}
