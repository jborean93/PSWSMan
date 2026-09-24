using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;

namespace PSWSMan.Authentication.Native;

/// <summary>Loads and caches the native authentication libraries used by the module.</summary>
/// <remarks>
/// Each provider is loaded at most once per process and shared by every runspace, so every accessor takes a lock
/// around its load and cache lookup. A provider that fails to load is not cached, a later call retries the load
/// so a library installed after the first attempt is picked up. Every failure is reported as an exception whose
/// message names the library and the loader's reason, with the original loader exception as its inner exception.
/// </remarks>
internal static class ProviderLibs
{
    private const string MacosGssFramework = "/System/Library/Frameworks/GSS.framework/GSS";

    private static readonly object s_devolutionsLock = new();
    private static SspiProvider? s_devolutionsSspi;

    private static readonly object s_systemSspiLock = new();
    private static SspiProvider? s_systemSspi;

    private static readonly object s_gssapiLock = new();
    private static GssapiProvider? s_systemGssapi;
    private static readonly Dictionary<string, GssapiProvider> s_gssapiCache = new(StringComparer.Ordinal);

    public static string LibPrefix { get; } = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "" : "lib";

    public static string LibExt { get; } = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? "dll"
        : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "dylib" : "so";

    public static string OsName { get; } = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? "win"
        : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx" : "linux";

    /// <summary>Gets the Devolutions SSPI library bundled with the module.</summary>
    /// <param name="provider">The loaded provider.</param>
    /// <param name="error">Why the library could not be loaded.</param>
    /// <returns>Whether the library is available.</returns>
    public static bool TryGetDevolutionsSspi(
        [NotNullWhen(true)] out SspiProvider? provider,
        [NotNullWhen(false)] out Exception? error)
    {
        lock (s_devolutionsLock)
        {
            if (s_devolutionsSspi is not null)
            {
                provider = s_devolutionsSspi;
                error = null;
                return true;
            }

            string devolutionsPath = Path.Combine(
                Path.GetDirectoryName(typeof(ProviderLibs).Assembly.Location) ?? "",
                "..",
                "runtimes",
                $"{OsName}-{RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()}",
                "native",
                $"{LibPrefix}DevolutionsSspi.{LibExt}");

            if (TryLoadProvider("Devolutions SSPI", devolutionsPath, h => new SspiProvider(h), out provider, out error))
            {
                s_devolutionsSspi = provider;
                return true;
            }

            return false;
        }
    }

    /// <summary>Gets the Windows SSPI library, or null when not running on Windows.</summary>
    public static SspiProvider? GetSystemSspi()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return null;
        }

        lock (s_systemSspiLock)
        {
            return s_systemSspi ??= new SspiProvider(NativeLibrary.Load("Secur32.dll"));
        }
    }

    /// <summary>Gets the GSSAPI library shipped by the OS.</summary>
    /// <remarks>
    /// On macOS this is GSS.framework. Elsewhere the well known MIT krb5 and Heimdal library names are tried in
    /// turn and the first that loads is used. Windows has no GSSAPI library and always fails.
    /// </remarks>
    /// <param name="provider">The loaded provider.</param>
    /// <param name="error">Why no library could be loaded, listing the reason for each name that was tried.</param>
    /// <returns>Whether a library is available.</returns>
    public static bool TryGetSystemGssapi(
        [NotNullWhen(true)] out GssapiProvider? provider,
        [NotNullWhen(false)] out Exception? error)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            provider = null;
            error = new PlatformNotSupportedException("Windows has no GSSAPI library, SSPI is used instead");
            return false;
        }

        lock (s_gssapiLock)
        {
            if (s_systemGssapi is not null)
            {
                provider = s_systemGssapi;
                error = null;
                return true;
            }

            string[] gssapiLibs = RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? [MacosGssFramework]
                : [
                    "libgssapi_krb5.so.2", // MIT krb5
                    "libgssapi.so.3", "libgssapi.so", // Heimdal
                ];

            List<Exception> failures = [];
            foreach (string lib in gssapiLibs)
            {
                if (TryGetGssapiUnlocked(lib, out provider, out Exception? libError))
                {
                    // Only a successful probe is remembered so a library
                    // installed later is found on the next call.
                    s_systemGssapi = provider;
                    error = null;
                    return true;
                }

                failures.Add(libError);
            }

            string msg = "Failed to find a system GSSAPI library, install MIT krb5 or Heimdal, set GssapiLib to " +
                "the library path with Set-PSWSManAuth, or use the Devolutions AuthProvider. Attempted:" +
                string.Concat(failures.ConvertAll(f => $"{Environment.NewLine}  {f.Message}"));
            provider = null;
            error = new DllNotFoundException(msg, new AggregateException(failures));
            return false;
        }
    }

    /// <summary>Gets the GSSAPI provider for a library name or path, loading and caching it on first use.</summary>
    /// <param name="gssapiLib">The library name or path as accepted by <see cref="NativeLibrary.Load(string)"/>.</param>
    /// <param name="provider">The loaded provider, shared with every other caller that used the same name.</param>
    /// <param name="error">Why the library could not be used, either it did not load or lacks a required export.</param>
    /// <returns>Whether the library could be loaded and exposes every required GSSAPI export.</returns>
    public static bool TryGetGssapi(
        string gssapiLib,
        [NotNullWhen(true)] out GssapiProvider? provider,
        [NotNullWhen(false)] out Exception? error)
    {
        lock (s_gssapiLock)
        {
            return TryGetGssapiUnlocked(gssapiLib, out provider, out error);
        }
    }

    /// <summary>The body of <see cref="TryGetGssapi"/>, the caller must hold <see cref="s_gssapiLock"/>.</summary>
    private static bool TryGetGssapiUnlocked(
        string gssapiLib,
        [NotNullWhen(true)] out GssapiProvider? provider,
        [NotNullWhen(false)] out Exception? error)
    {
        if (s_gssapiCache.TryGetValue(gssapiLib, out provider))
        {
            error = null;
            return true;
        }

        bool isGssFramework = IsGssFramework(gssapiLib);
        if (TryLoadProvider("GSSAPI", gssapiLib, h => new GssapiProvider(h, isGssFramework), out provider, out error))
        {
            s_gssapiCache[gssapiLib] = provider;
            return true;
        }

        return false;
    }

    /// <summary>Loads a native library and builds its provider, describing any failure.</summary>
    /// <param name="kind">What the library is, used in the failure message.</param>
    /// <param name="lib">The library name or path to load.</param>
    /// <param name="factory">Builds the provider from the loaded handle and takes ownership of it.</param>
    /// <param name="provider">The built provider.</param>
    /// <param name="error">Why the library could not be loaded or is missing a required export.</param>
    private static bool TryLoadProvider<T>(
        string kind,
        string lib,
        Func<IntPtr, T> factory,
        [NotNullWhen(true)] out T? provider,
        [NotNullWhen(false)] out Exception? error)
        where T : class
    {
        IntPtr handle;
        try
        {
            handle = NativeLibrary.Load(lib);
        }
        catch (Exception e) when (e is DllNotFoundException or BadImageFormatException)
        {
            provider = null;
            error = new DllNotFoundException($"Failed to load {kind} library '{lib}': {LoaderReason(e)}", e);
            return false;
        }

        try
        {
            provider = factory(handle);
            error = null;
            return true;
        }
        catch (EntryPointNotFoundException e)
        {
            // The library loaded but is not a usable implementation. The
            // provider never took ownership of the handle so it is freed here.
            NativeLibrary.Free(handle);
            provider = null;
            error = new EntryPointNotFoundException($"{kind} library '{lib}' is missing a required export: {e.Message}", e);
            return false;
        }
    }

    /// <summary>The loader's own reason for a failure, without the generic diagnostic advice .NET prepends.</summary>
    /// <remarks>
    /// On Linux and macOS the runtime's message ends with the dlopen error on its own line, for example
    /// <c>cannot open shared object file: No such file or directory</c>. On Windows the message is a single line
    /// ending in the Win32 error. The last non-empty line is the useful part in every case.
    /// </remarks>
    private static string LoaderReason(Exception e)
    {
        string[] lines = e.Message.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return lines.Length > 0 ? lines[^1] : e.Message;
    }

    /// <summary>Whether a library name refers to the macOS GSS.framework rather than MIT krb5 or Heimdal.</summary>
    private static bool IsGssFramework(string gssapiLib)
        => RuntimeInformation.IsOSPlatform(OSPlatform.OSX) &&
            (gssapiLib == MacosGssFramework || gssapiLib.EndsWith("/GSS.framework/GSS", StringComparison.Ordinal));
}
