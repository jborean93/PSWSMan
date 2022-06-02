using System;

namespace PSWSMan;

internal static class GlobalState
{
    /// <summary>The GSSAPI/SSPI provider that is used.</summary>
    public static GssapiProvider GssapiProvider;

    /// <summary>The loaded GSSAPI library on Linux.</summary>
    internal static LibraryInfo? GssapiLib;
}
