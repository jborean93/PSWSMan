using MonoMod.RuntimeDetour;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace PSWSMan.Patches;

internal sealed class MonoModPatcher : IDisposable
{
    private List<Hook> _hooks = new();
    private bool _disposed;

    public MonoModPatcher()
    { }

    public void PatchAll()
    {
        // Bind every UnsafeAccessor up front. The runtime otherwise resolves
        // the member name on the accessor's first call, which would turn a
        // renamed S.M.A member into a failure part way through a session.
        PrepareAccessors(typeof(PSWSMan_WSManApiDataCommon));
        PrepareAccessors(typeof(PSWSMan_WSManClientSessionTransportManager));
        PrepareAccessors(typeof(PSWSMan_WSManClientCommandTransportManager));

        _hooks.AddRange(PSWSMan_WSManApiDataCommon.GenerateHooks());
        _hooks.AddRange(PSWSMan_WSManClientSessionTransportManager.GenerateHooks());
        _hooks.AddRange(PSWSMan_WSManClientCommandTransportManager.GenerateHooks());
        _hooks.AddRange(PSWSMan_WSManConnectionInfo.GenerateHooks());
        _hooks.AddRange(PSWSMan_InternalDeserializer.GenerateHooks());
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

    internal static void PrepareAccessors(Type patchType)
    {
        foreach (MethodInfo method in patchType.GetMethods(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public))
        {
            if (!method.IsDefined(typeof(UnsafeAccessorAttribute), inherit: false))
            {
                continue;
            }

            try
            {
                RuntimeHelpers.PrepareMethod(method.MethodHandle);
            }
            catch (Exception e) when (e is MissingMemberException or TypeLoadException)
            {
                string name = method.GetCustomAttribute<UnsafeAccessorAttribute>()?.Name ?? method.Name;
                Type target = method.GetParameters()[0].ParameterType;
                throw new MissingMemberException(
                    $"Failed to bind PSWSMan accessor {patchType.Name}.{method.Name} to {target.FullName}.{name}: {e.Message}",
                    e);
            }
        }
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
