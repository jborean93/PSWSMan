using System;
using System.Runtime.InteropServices;

namespace PSWSMan.Authentication.Native;

/// <summary>Owns a <c>gss_cred_id_t</c>.</summary>
internal sealed class SafeGssapiCred : SafeHandle
{
    private readonly GssapiProvider _provider;

    internal SafeGssapiCred(GssapiProvider provider, IntPtr handle) : base(handle, true)
    {
        _provider = provider;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override unsafe bool ReleaseHandle()
    {
        void* cred = (void*)handle;
        return _provider.ReleaseCred(&cred) == 0;
    }
}

/// <summary>Owns a <c>gss_name_t</c>.</summary>
internal sealed class SafeGssapiName : SafeHandle
{
    private readonly GssapiProvider _provider;

    internal SafeGssapiName(GssapiProvider provider, IntPtr handle) : base(handle, true)
    {
        _provider = provider;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override unsafe bool ReleaseHandle()
    {
        void* name = (void*)handle;
        return _provider.ReleaseName(&name) == 0;
    }
}

/// <summary>Owns a <c>gss_OID_set</c>.</summary>
internal sealed class SafeGssapiOidSet : SafeHandle
{
    private readonly GssapiProvider _provider;

    internal SafeGssapiOidSet(GssapiProvider provider, IntPtr handle) : base(handle, true)
    {
        _provider = provider;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    /// <summary>Records the new location of the set after the library reallocated it.</summary>
    internal void UpdateHandle(IntPtr newHandle) => SetHandle(newHandle);

    protected override unsafe bool ReleaseHandle()
    {
        Helpers.gss_OID_set_desc* set = (Helpers.gss_OID_set_desc*)handle;
        return _provider.ReleaseOidSet(&set) == 0;
    }
}

/// <summary>Owns a <c>gss_ctx_id_t</c>.</summary>
/// <remarks>
/// Starts out as <c>GSS_C_NO_CONTEXT</c>, <c>InitSecContext</c> fills it in on the first call and keeps it in step
/// with the library on every call after that.
/// </remarks>
internal sealed class SafeGssapiSecContext : SafeHandle
{
    private readonly GssapiProvider _provider;

    internal SafeGssapiSecContext(GssapiProvider provider) : base(IntPtr.Zero, true)
    {
        _provider = provider;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    internal void SetContextHandle(IntPtr contextHandle) => SetHandle(contextHandle);

    protected override unsafe bool ReleaseHandle()
    {
        void* context = (void*)handle;
        return _provider.DeleteSecContext(&context, null) == 0;
    }
}
