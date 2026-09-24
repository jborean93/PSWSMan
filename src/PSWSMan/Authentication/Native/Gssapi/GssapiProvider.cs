using System;
using System.Runtime.InteropServices;

namespace PSWSMan.Authentication.Native;

/// <summary>A GSSAPI implementation loaded from a native library.</summary>
/// <remarks>
/// Every export is resolved once when the provider is created and held as an unmanaged function pointer, so
/// calling into the library costs an indirect call and nothing else. Each export lives in its own file next to
/// the managed wrapper that calls it. MIT krb5, Heimdal and the macOS GSS.framework are all driven through the
/// same class, the differences being the symbol names of the IOV functions and the struct packing on x86_64
/// macOS which <see cref="IsGssFramework"/> selects.
/// </remarks>
/// <param name="module">The loaded library handle, ownership passes to the provider.</param>
/// <param name="isGssFramework">Whether the library is the macOS GSS.framework rather than MIT or Heimdal.</param>
/// <exception cref="EntryPointNotFoundException">The library is missing one of the required exports.</exception>
internal sealed unsafe partial class GssapiProvider(IntPtr module, bool isGssFramework) : IDisposable
{
    private const uint GSS_S_COMPLETE = 0;
    private const uint GSS_S_CONTINUE_NEEDED = 1;

    private IntPtr _module = module;

    /// <summary>Whether the library is the macOS GSS.framework.</summary>
    public bool IsGssFramework { get; } = isGssFramework;

    /// <summary>Whether the library is Heimdal based, which includes GSS.framework.</summary>
    /// <remarks>
    /// Heimdal exports <c>krb5_xfree</c> as a real function while MIT only has it as a macro, and dlsym searches a
    /// library's dependencies so the symbol is found through libgssapi's link to libkrb5.
    /// </remarks>
    public bool IsHeimdal { get; } = NativeLibrary.TryGetExport(module, "krb5_xfree", out _);

    private static void* GetExport(IntPtr module, string name)
        => (void*)NativeLibrary.GetExport(module, name);

    /// <summary>The symbol to resolve for an IOV export, GSS.framework only exposes them under a private name.</summary>
    private static string IovExport(bool isGssFramework, string name)
        => isGssFramework ? $"__ApplePrivate_{name}" : name;

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

    ~GssapiProvider() => Dispose(false);
}
