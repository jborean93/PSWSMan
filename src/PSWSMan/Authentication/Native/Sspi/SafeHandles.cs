using System;
using System.Runtime.InteropServices;

namespace PSWSMan.Authentication.Native;

/// <summary>Owns the memory of a <c>CredHandle</c> and frees the credential once SSPI has filled it in.</summary>
internal sealed class SafeSspiCredentialHandle : SafeHandle
{
    private readonly SspiProvider _provider;

    /// <summary>Set once SSPI has populated the handle so <c>FreeCredentialsHandle</c> is called on release.</summary>
    internal bool SSPIFree = false;

    internal SafeSspiCredentialHandle(SspiProvider provider)
        : base(Marshal.AllocHGlobal(Marshal.SizeOf<Helpers.SecHandle>()), true)
    {
        _provider = provider;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override unsafe bool ReleaseHandle()
    {
        if (SSPIFree)
        {
            _provider.FreeCredentialsHandle((Helpers.SecHandle*)handle);
        }
        Marshal.FreeHGlobal(handle);

        return true;
    }
}

/// <summary>Owns the memory of a <c>CtxtHandle</c> and deletes the context once SSPI has filled it in.</summary>
internal sealed class SafeSspiContextHandle : SafeHandle
{
    private readonly SspiProvider _provider;

    /// <summary>Set once SSPI has populated the handle so <c>DeleteSecurityContext</c> is called on release.</summary>
    internal bool SSPIFree = false;

    internal SafeSspiContextHandle(SspiProvider provider)
        : base(Marshal.AllocHGlobal(Marshal.SizeOf<Helpers.SecHandle>()), true)
    {
        _provider = provider;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override unsafe bool ReleaseHandle()
    {
        if (SSPIFree)
        {
            _provider.DeleteSecurityContext((Helpers.SecHandle*)handle);
        }
        Marshal.FreeHGlobal(handle);

        return true;
    }
}
