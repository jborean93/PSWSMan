using System;

namespace PSWSMan.Authentication.Native;

using unsafe ReleaseIovBufferFn = delegate* unmanaged[Cdecl]<
    uint*, // minor_status
    void*, // iov
    int,   // iov_count
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly ReleaseIovBufferFn _releaseIovBuffer =
        (ReleaseIovBufferFn)GetExport(module, IovExport(isGssFramework, "gss_release_iov_buffer"));

    /// <summary>Frees the buffers the library allocated in an IOV array and clears their allocated flags.</summary>
    /// <remarks>
    /// Releases run from <c>finally</c> blocks so this reports the status rather than throwing. The minor status
    /// is not reported as nothing acts on it for a release.
    /// </remarks>
    /// <param name="iov">The IOV buffers as returned by the wrap or unwrap call.</param>
    /// <returns>The major status, 0 on success.</returns>
    public uint ReleaseIovBuffer(Span<IOVBuffer> iov)
    {
        byte* iovStorage = stackalloc byte[sizeof(Helpers.gss_iov_buffer_desc) * iov.Length];
        WriteIov(iovStorage, iov);

        uint minorStatus;
        uint majorStatus = _releaseIovBuffer(&minorStatus, iovStorage, iov.Length);
        ReadIov(iovStorage, iov);

        return majorStatus;
    }
}
