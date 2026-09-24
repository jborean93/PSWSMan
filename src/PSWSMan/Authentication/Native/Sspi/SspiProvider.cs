using System;
using System.Runtime.InteropServices;

namespace PSWSMan.Authentication.Native;

/// <summary>An SSPI implementation loaded from a native library.</summary>
/// <param name="module">The loaded library handle, ownership passes to the provider.</param>
/// <exception cref="EntryPointNotFoundException">The library is missing one of the required exports.</exception>
internal sealed unsafe partial class SspiProvider(IntPtr module) : IDisposable
{
    private const int SEC_I_CONTINUE_NEEDED = 0x00090312;

    private IntPtr _module = module;

    private static void* GetExport(IntPtr module, string name)
        => (void*)NativeLibrary.GetExport(module, name);

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (disposing && _module != IntPtr.Zero)
        {
            NativeLibrary.Free(_module);
            _module = IntPtr.Zero;
        }
    }

    ~SspiProvider() => Dispose(false);
}
