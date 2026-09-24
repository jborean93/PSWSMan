using System;

namespace PSWSMan.Authentication.Native;

using unsafe WrapIovFn = delegate* unmanaged[Cdecl]<
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
    private readonly WrapIovFn _wrapIov =
        (WrapIovFn)GetExport(module, IovExport(isGssFramework, "gss_wrap_iov"));

    /// <summary>Wraps (signs or encrypts) a message laid out as IOV buffers, the data buffer in place.</summary>
    /// <remarks>
    /// The buffers are copied back from the native array after the call, including any the library allocated for
    /// entries flagged <c>GSS_IOV_BUFFER_FLAG_ALLOCATE</c>. That happens even when the call fails so the caller can
    /// always hand the same span to <c>ReleaseIovBuffer</c>.
    /// </remarks>
    /// <param name="context">The context to wrap the message with.</param>
    /// <param name="confReqFlag">Non zero to encrypt the message, 0 to only sign it.</param>
    /// <param name="qopReq">The quality of protection to request, 0 for the default.</param>
    /// <param name="confState">Receives whether the message was encrypted, or <c>null</c> if not needed.</param>
    /// <param name="iov">The IOV buffers describing the message.</param>
    /// <exception cref="GSSAPIException">Failed to wrap the message.</exception>
    public void WrapIov(
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
        uint majorStatus = _wrapIov(
            &minorStatus,
            contextRef.Pointer,
            confReqFlag,
            qopReq,
            confState,
            iovStorage,
            iov.Length);
        ReadIov(iovStorage, iov);

        if (majorStatus != GSS_S_COMPLETE)
            throw new GSSAPIException(this, majorStatus, minorStatus, "gss_wrap_iov");
    }
}
