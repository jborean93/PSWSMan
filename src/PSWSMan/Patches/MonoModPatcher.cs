using MonoMod.RuntimeDetour;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace PSWSMan.Module.Patches;

internal sealed class MonoModPatcher : IDisposable
{
    private List<Hook> _hooks = new();
    private bool _disposed;

    public MonoModPatcher()
    { }

    public void PatchAll()
    {
        _hooks.AddRange(PSWSMan_WSManApiDataCommon.GenerateHooks());
        _hooks.AddRange(PSWSMan_WSManClientSessionTransportManager.GenerateHooks());
        _hooks.AddRange(PSWSMan_WSManClientCommandTransportManager.GenerateHooks());
        _hooks.AddRange(PSWSMan_WSManConnectionInfo.GenerateHooks());
    }

    public void UnpatchAll()
    {
        foreach (Hook h in _hooks)
        {
            h.Dispose();
        }
        _hooks.Clear();
    }

    internal static ConstructorInfo GetConstructor(
        Type type,
        Type[] args,
        BindingFlags bindingFlags
    )
    {
        return type.GetConstructor(
            bindingFlags,
            args
        ) ?? throw new NullReferenceException($"Failed to find constructor for {type.FullName}");
    }

    internal static FieldInfo GetField(
        Type type,
        string name,
        BindingFlags bindingFlags
    )
    {
        return type.GetField(
            name,
            bindingFlags
        ) ?? throw new NullReferenceException($"Failed to find find field {type.FullName}.{name}");
    }

    internal static MethodInfo GetMethod(
        Type type,
        string name,
        Type[] args,
        BindingFlags bindingFlags
    )
    {
        return type.GetMethod(
            name,
            bindingFlags,
            args
        ) ?? throw new NullReferenceException($"Failed to find method {type.FullName}.{name}({GetArgumentDef(args)})");
    }

    internal static PropertyInfo GetProperty(
        Type type,
        string name,
        BindingFlags bindingFlags
    )
    {
        return type.GetProperty(
            name,
            bindingFlags
        ) ?? throw new NullReferenceException($"Failed to find property {type.FullName}.{name}");
    }

    private static string GetArgumentDef(Type[] args)
    {
        return string.Join(", ", args.Select(a => a.Name));
    }

    public void Dispose() => Dispose(true);

    internal void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (!_disposed)
            {
                UnpatchAll();
            }
            _disposed = true;
        }
    }

    ~MonoModPatcher() => Dispose(false);
}
