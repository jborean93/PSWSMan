#if NET6_0_OR_GREATER
using System;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;

namespace PSWSMan.Loader;

public class LoadContext : AssemblyLoadContext
{
    private static LoadContext? s_instance;
    private static readonly object s_sync = new();

    private readonly Assembly _thisAssembly;
    private readonly AssemblyName _thisAssemblyName;
    private readonly Assembly _moduleAssembly;
    private readonly AssemblyDependencyResolver _resolver;

    private LoadContext(string name, string mainModulePathAssemblyPath)
        : base(name: name, isCollectible: false)
    {
        // Uses the module's .deps.json to find dependencies, including RID
        // specific and native assets under runtimes/.
        _resolver = new AssemblyDependencyResolver(mainModulePathAssemblyPath);
        _thisAssembly = typeof(LoadContext).Assembly;
        _thisAssemblyName = _thisAssembly.GetName();
        _moduleAssembly = LoadFromAssemblyPath(mainModulePathAssemblyPath);
    }

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        if (AssemblyName.ReferenceMatchesDefinition(_thisAssemblyName, assemblyName))
        {
            return _thisAssembly;
        }

        string? asmPath = _resolver.ResolveAssemblyToPath(assemblyName);
        return asmPath is null ? null : LoadFromAssemblyPath(asmPath);
    }

    protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
    {
        string? libPath = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
        return libPath is null ? IntPtr.Zero : LoadUnmanagedDllFromPath(libPath);
    }

    public static Assembly Initialize(string alcName)
    {
        lock (s_sync)
        {
            if (s_instance is null)
            {
                string assemblyPath = typeof(LoadContext).Assembly.Location;
                string assemblyName = Path.GetFileNameWithoutExtension(assemblyPath);

                string moduleName = assemblyName[..assemblyName.LastIndexOf('.')];
                string modulePath = Path.Combine(
                    Path.GetDirectoryName(assemblyPath)!,
                    $"{moduleName}.dll"
                );

                s_instance = new LoadContext(alcName, modulePath);
            }

            return s_instance._moduleAssembly;
        }
    }
}
#endif
