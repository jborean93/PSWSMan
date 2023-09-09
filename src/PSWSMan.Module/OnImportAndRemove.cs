using PSWSMan.Authentication.Native;
using System;
using System.IO;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace PSWSMan.Module;

public class OnModuleImportAndRemove : IModuleAssemblyInitializer, IModuleAssemblyCleanup
{
    internal const string MACOS_GSS_FRAMEWORK = "/System/Library/Frameworks/GSS.framework/GSS";

    public void OnImport()
    {
        string osName;
        string libExt;
        string libPrefix = "";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            osName = "win";
            libExt = "dll";

            GlobalState.WinSspi = new(LoadLibrary("PSWSMan.SSPI", new[] { "Secur32.dll" }, required: true));
        }
        else
        {
            libPrefix = "lib";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                osName = "osx";
                libExt = "dylib";
            }
            else
            {
                // FUTURE: Check musl vs glibc
                osName = "linux";
                libExt = "so";
            }

            IntPtr gssapiLib = LoadLibrary("PSWSMan.GSSAPI", new[]
            {
                MACOS_GSS_FRAMEWORK
            });
            if (gssapiLib != IntPtr.Zero)
            {
                GlobalState.Gssapi = new GSSFrameworkProvider(gssapiLib);
            }
            else
            {
                gssapiLib = LoadLibrary("PSWSMan.GSSAPI", new[]
                {
                    "libgssapi_krb5.so.2", // MIT krb5
                    "libgssapi.so.3", "libgssapi.so", // Heimdal
                });
                if (gssapiLib != IntPtr.Zero)
                {
                    GlobalState.Gssapi = new(gssapiLib);
                }
            }
        }

        string devolutionsPaths = Path.Combine(
            Path.GetDirectoryName(typeof(OnModuleImportAndRemove).Assembly.Location) ?? "",
            "..",
            "runtimes",
            $"{osName}-{RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()}",
            "native",
            $"{libPrefix}DevolutionsSspi.{libExt}");
        GlobalState.DevolutionsSspi = new(LoadLibrary("PSWSMan.Devolutions", new[] { devolutionsPaths },
            required: true));
    }

    public void OnRemove(PSModuleInfo module)
    {
        GlobalState.DevolutionsSspi?.Dispose();
        GlobalState.WinSspi?.Dispose();
        GlobalState.Gssapi?.Dispose();
    }

    private IntPtr LoadLibrary(string id, string[] paths, bool required = false)
    {
        string? envOverride = Environment.GetEnvironmentVariable(id.ToUpperInvariant().Replace(".", "_"));
        if (!string.IsNullOrWhiteSpace(envOverride))
            paths = new[] { envOverride };


        foreach (string libPath in paths)
        {
            if (NativeLibrary.TryLoad(libPath, out var lib))
            {
                return lib;
            }
        }

        if (required)
        {
            string searchPaths = string.Join("', '", paths);
            throw new DllNotFoundException($"Failed to find required lib {id}, searched paths: '{searchPaths}'");
        }

        return IntPtr.Zero;
    }
}
