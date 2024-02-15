using PSWSMan.Shared;
using PSWSMan.Shared.Authentication.Native;

namespace PSWSMan;

internal static class GlobalState
{
    /// <summary>The loaded DevolutionsSspi library.</summary>
    internal static SspiProvider DevolutionsSspi = default!;

    /// <summary>The loaded SSPI library on Windows.</summary>
    internal static SspiProvider? WinSspi = null;

    /// <summary>The loaded GSSAPI library on Linux.</summary>
    internal static GssapiProvider? Gssapi = null;

    /// <summary>The default authentication provider set for the process.</summary>
    internal static AuthenticationProvider DefaultProvider = AuthenticationProvider.System;
}
