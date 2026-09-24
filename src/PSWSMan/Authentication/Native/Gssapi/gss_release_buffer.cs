namespace PSWSMan.Authentication.Native;

using unsafe ReleaseBufferFn = delegate* unmanaged[Cdecl]<
    uint*,                    // minor_status
    Helpers.gss_buffer_desc*, // buffer
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly ReleaseBufferFn _releaseBuffer =
        (ReleaseBufferFn)GetExport(module, "gss_release_buffer");

    /// <summary>Frees a buffer the library allocated and resets it to <c>GSS_C_EMPTY_BUFFER</c>.</summary>
    /// <remarks>
    /// Releases run from <c>finally</c> blocks so this reports the status rather than throwing. The minor status
    /// is not reported as nothing acts on it for a release. An empty buffer is accepted and does nothing.
    /// </remarks>
    /// <param name="buffer">The buffer to free.</param>
    /// <returns>The major status, 0 on success.</returns>
    public uint ReleaseBuffer(Helpers.gss_buffer_desc* buffer)
    {
        uint minorStatus;
        return _releaseBuffer(&minorStatus, buffer);
    }
}
