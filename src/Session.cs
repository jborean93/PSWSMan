using System;

namespace PSWSMan;

internal static class GlobalState
{
    /// <summary>The GSSAPI/SSPI provider that is used.</summary>
    public static GssapiProvider GssapiProvider;
}
