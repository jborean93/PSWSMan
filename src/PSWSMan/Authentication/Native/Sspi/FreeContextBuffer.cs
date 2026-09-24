namespace PSWSMan.Authentication.Native;

using unsafe FreeContextBufferFn = delegate* unmanaged[Stdcall]<
    void*, // pvContextBuffer
    int>;

internal sealed unsafe partial class SspiProvider
{
    private readonly FreeContextBufferFn _freeContextBuffer =
        (FreeContextBufferFn)GetExport(module, nameof(FreeContextBuffer));

    /// <summary>Frees a memory buffer allocated by the security package.</summary>
    /// <param name="buffer">The buffer to free.</param>
    /// <returns>The SSPI status code, 0 on success.</returns>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/freecontextbuffer">FreeContextBuffer</see>
    public int FreeContextBuffer(void* buffer)
        => _freeContextBuffer(buffer);
}
