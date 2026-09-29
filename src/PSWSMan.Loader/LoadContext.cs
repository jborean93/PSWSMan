#if NET6_0_OR_GREATER
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
    private readonly string _assemblyDir;

    private LoadContext(string name, string mainModulePathAssemblyPath)
        : base(name: name, isCollectible: false)
    {
        _assemblyDir = Path.GetDirectoryName(mainModulePathAssemblyPath) ?? "";
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

        string asmPath = Path.Join(_assemblyDir, $"{assemblyName.Name}.dll");
        if (File.Exists(asmPath))
        {
            return LoadFromAssemblyPath(asmPath);
        }
        else
        {
            return null;
        }
    }

    public static Assembly Initialize(string alcName)
    {
        LoadContext? instance = s_instance;
        if (instance is not null)
        {
            return instance._moduleAssembly;
        }

        lock (s_sync)
        {
            if (s_instance is not null)
            {
                return s_instance._moduleAssembly;
            }

            string assemblyPath = typeof(LoadContext).Assembly.Location;
            string assemblyName = Path.GetFileNameWithoutExtension(assemblyPath);

            string moduleName = assemblyName[..assemblyName.LastIndexOf('.')];
            string modulePath = Path.Combine(
                Path.GetDirectoryName(assemblyPath)!,
                $"{moduleName}.dll"
            );

            s_instance = new LoadContext(alcName, modulePath);
            return s_instance._moduleAssembly;
        }
    }
}
#endif
