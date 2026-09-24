using System;

namespace PSWSMan.Authentication.Native;

using unsafe UnwrapIovFn = delegate* unmanaged[Cdecl]<
    uint*, // minor_status
    void*, // context_handle
    int*,  // conf_state
    uint*, // qop_state
    void*, // iov
    int,   // iov_count
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly UnwrapIovFn _unwrapIov =
        (UnwrapIovFn)GetExport(module, IovExport(isGssFramework, "gss_unwrap_iov"));

    /// <summary>Unwraps a message laid out as IOV buffers, the data buffer in place.</summary>
    /// <remarks>
    /// The buffers are copied back from the native array after the call, including any the library allocated for
    /// entries flagged <c>GSS_IOV_BUFFER_FLAG_ALLOCATE</c>. That happens even when the call fails so the caller can
    /// always hand the same span to <c>ReleaseIovBuffer</c>.
    /// </remarks>
    /// <param name="context">The context the message was wrapped with.</param>
    /// <param name="confState">Receives whether the message was encrypted, or <c>null</c> if not needed.</param>
    /// <param name="qopState">Receives the quality of protection applied, or <c>null</c> if not needed.</param>
    /// <param name="iov">The IOV buffers describing the message.</param>
    /// <exception cref="GSSAPIException">Failed to unwrap the message.</exception>
    public void UnwrapIov(
        SafeGssapiSecContext context,
        int* confState,
        uint* qopState,
        Span<IOVBuffer> iov)
    {
        using SafeHandleRef contextRef = new(context);

        byte* iovStorage = stackalloc byte[sizeof(Helpers.gss_iov_buffer_desc) * iov.Length];
        WriteIov(iovStorage, iov);

        uint minorStatus;
        uint majorStatus = _unwrapIov(
            &minorStatus,
            contextRef.Pointer,
            confState,
            qopState,
            iovStorage,
            iov.Length);
        ReadIov(iovStorage, iov);

        if (majorStatus != GSS_S_COMPLETE)
            throw new GSSAPIException(this, majorStatus, minorStatus, "gss_unwrap_iov");
    }
}
