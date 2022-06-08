using System;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Reflection;

namespace PSWSMan.Reflection;

internal static class SMARemotingReflection
{
    private const BindingFlags InstanceBindingFlags =
        BindingFlags.FlattenHierarchy | BindingFlags.Public | BindingFlags.NonPublic
        | BindingFlags.IgnoreCase | BindingFlags.Instance;

    private const BindingFlags StaticBindingFlags =
        BindingFlags.FlattenHierarchy | BindingFlags.Public | BindingFlags.NonPublic
        | BindingFlags.IgnoreCase | BindingFlags.Static;

    private readonly static Assembly SMAAssembly = typeof(PSObject).Assembly;

    #region TransportErrorOccuredEventArgs

    private static readonly Lazy<Type> TransportMethodEnumType = new(() =>
    {
        // FUTURE: This was made public in pwsh 7.3
        const string typeName = "System.Management.Automation.Remoting.TransportMethodEnum";
        return GetType(SMAAssembly, typeName);
    });

    private static readonly Lazy<Type> TransportErrorOccuredEventArgsType = new(() =>
    {
        // FUTURE: This was made public in pwsh 7.3
        const string typeName = "System.Management.Automation.Remoting.TransportErrorOccuredEventArgs";
        return GetType(SMAAssembly, typeName);
    });

    private static readonly Lazy<ConstructorInfo> TransportErrorOccuredEventArgsCstor = new(() =>
    {
        return GetConstructor(TransportErrorOccuredEventArgsType.Value, new Type[] {
            typeof(PSRemotingTransportException),
            TransportMethodEnumType.Value
        });
    });

    public static EventArgs NewTransportErrorOccuredEventArgs(PSRemotingTransportException e, int transportMethod)
    {
        return (EventArgs)TransportErrorOccuredEventArgsCstor.Value.Invoke(new object[] {e, transportMethod});
    }

    #endregion

    #region WSManClientSessionTransportManager

    private static readonly Lazy<Type> WSManClientSessionTransportManagerType = new(() =>
    {
        const string typeName = "System.Management.Automation.Remoting.Client.WSManClientSessionTransportManager";
        return GetType(SMAAssembly, typeName);
    });

    private static readonly Lazy<MethodInfo> ProcessWSManTransportErrorMeth = new(
        GetMethod(WSManClientSessionTransportManagerType.Value, "ProcessWSManTransportError"));

    public static void ProcessWSManTransportError(object instance, EventArgs eventArgs)
    {
        ProcessWSManTransportErrorMeth.Value.Invoke(instance, new object[] { eventArgs });
    }

    #endregion

    private static Type GetType(Assembly assembly, string typeName)
    {
        return assembly.GetType(typeName)
            ?? throw new TypeLoadException($"Failed to find type {typeName}");
    }

    private static ConstructorInfo GetConstructor(Type type, Type[] paramTypes)
    {
        return type.GetConstructor(InstanceBindingFlags, paramTypes)
            ?? throw new TypeLoadException($"Failed to find constructor for {type.Name}");
    }

    private static MethodInfo GetMethod(Type type, string name)
    {
        return type.GetMethod(name, InstanceBindingFlags)
            ?? throw new TypeLoadException($"Failed to find {name} for {type.Name}");
    }

    private static object InvokeMethod(MethodBase method, object[] args)
    {
        return method.Invoke(null, args) ?? throw new ArgumentException($"Failed to invoke {method.Name}");
    }
}
