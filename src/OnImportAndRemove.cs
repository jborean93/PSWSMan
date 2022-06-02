using PSWSMan.Native;
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace PSWSMan;

internal sealed class LibraryInfo : IDisposable
{
    public string Id { get; }
    public string Path { get; }
    public IntPtr Handle { get; }

    public LibraryInfo(string id, string path)
    {
        Id = id;
        Path = path;
        Handle = NativeLibrary.Load(path);
    }

    public void Dispose()
    {
        if (Handle != IntPtr.Zero)
            NativeLibrary.Free(Handle);
    }
    ~LibraryInfo() { Dispose(); }
}

internal sealed class NativeResolver : IDisposable
{
    private readonly Dictionary<string, LibraryInfo> NativeHandles = new();

    public NativeResolver()
    {
        AssemblyLoadContext.Default.ResolvingUnmanagedDll += ImportResolver;
    }

    public LibraryInfo? CacheLibrary(string id, string[] paths)
    {
        string? envOverride = Environment.GetEnvironmentVariable(id.ToUpperInvariant().Replace(".", "_"));
        if (!string.IsNullOrWhiteSpace(envOverride))
            paths = new[] { envOverride };

        foreach (string libPath in paths)
        {
            try
            {
                NativeHandles[id] = new LibraryInfo(id, libPath);
                return NativeHandles[id];
            }
            catch (DllNotFoundException) { }
        }

        return null;
    }

    private IntPtr ImportResolver(Assembly assembly, string libraryName)
    {
        if (NativeHandles.ContainsKey(libraryName))
            return NativeHandles[libraryName].Handle;

        return IntPtr.Zero;
    }

    public void Dispose()
    {
        foreach (KeyValuePair<string, LibraryInfo> native in NativeHandles)
            native.Value.Dispose();

        AssemblyLoadContext.Default.ResolvingUnmanagedDll -= ImportResolver;
        GC.SuppressFinalize(this);
    }
    ~NativeResolver() { Dispose(); }
}

public class OnModuleImportAndRemove : IModuleAssemblyInitializer, IModuleAssemblyCleanup
{
    internal const string MACOS_GSS_FRAMEWORK = "/System/Library/Frameworks/GSS.framework/GSS";

    internal NativeResolver? Resolver;

    public void OnImport()
    {
        Resolver = new NativeResolver();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            GlobalState.GssapiProvider = GssapiProvider.SSPI;
        }
        else
        {
            GlobalState.GssapiLib = Resolver.CacheLibrary(GSSAPI.LIB_GSSAPI, new[] {
                MACOS_GSS_FRAMEWORK, // macOS GSS Framework (technically Heimdal)
                "libgssapi_krb5.so.2", // MIT krb5
                "libgssapi.so.3", "libgssapi.so", // Heimdal
            });

            if (GlobalState.GssapiLib is null)
            {
                GlobalState.GssapiProvider = GssapiProvider.None;
            }
            else if (GlobalState.GssapiLib.Path == MACOS_GSS_FRAMEWORK)
            {
                GlobalState.GssapiProvider = GssapiProvider.GSSFramework;
            }
            else if (NativeLibrary.TryGetExport(GlobalState.GssapiLib.Handle, "krb5_xfree", out var _))
            {
                // While technically exported by the krb5 lib the Heimdal GSSAPI lib depends on it so the same
                // symbol will be exported there and we can use that to detect if Heimdal is in use.
                GlobalState.GssapiProvider = GssapiProvider.Heimdal;
            }
            else
            {
                GlobalState.GssapiProvider = GssapiProvider.MIT;
            }
        }
    }

    public void OnRemove(PSModuleInfo module)
    {
        Resolver?.Dispose();
    }
}
