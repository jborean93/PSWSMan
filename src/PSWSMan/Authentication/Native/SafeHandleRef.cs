using System;
using System.Runtime.InteropServices;

namespace PSWSMan.Authentication.Native;

/// <summary>Keeps a <see cref="SafeHandle"/> alive and un-released for the duration of a native call.</summary>
/// <remarks>
/// Unmanaged function pointers take raw pointers so the reference counting the P/Invoke marshaller would normally
/// do for a <see cref="SafeHandle"/> parameter has to be done by hand. Create one of these in a <c>using</c> before
/// the call and pass <see cref="Value"/> or <see cref="As{T}"/> to the native function. A <c>null</c> handle is
/// allowed and yields a null pointer, which covers the "no credential" and "no context" cases.
/// </remarks>
internal readonly ref struct SafeHandleRef
{
    private readonly SafeHandle? _handle;
    private readonly bool _added;

    public SafeHandleRef(SafeHandle? handle)
    {
        _handle = handle;
        _added = false;
        handle?.DangerousAddRef(ref _added);
    }

    /// <summary>The raw handle value, or <see cref="IntPtr.Zero"/> when no handle was supplied.</summary>
    public IntPtr Value => _added ? _handle!.DangerousGetHandle() : IntPtr.Zero;

    /// <summary>The raw handle value as an untyped pointer, for opaque handle types.</summary>
    public unsafe void* Pointer => (void*)Value;

    /// <summary>The raw handle value as a typed pointer.</summary>
    public unsafe T* As<T>() where T : unmanaged => (T*)Value;

    public void Dispose()
    {
        if (_added)
        {
            _handle!.DangerousRelease();
        }
    }
}
