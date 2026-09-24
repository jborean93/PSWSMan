using MonoMod.RuntimeDetour;
using System;
using System.Management.Automation;
using System.Management.Automation.Remoting.Client;
using System.Reflection;

namespace PSWSMan.Patches;

internal static class PSWSMan_InternalDeserializer
{
    private static MethodInfo? _rehydrateCimInstanceMeth;

    private const string CimClassMetadataProperty = "__ClassMetadata";
    private const string CimInstanceMetadataProperty = "__InstanceMetadata";

    private static PSObject RehydrateCimInstancePatch(
        Func<InternalDeserializer, PSObject, PSObject> orig,
        InternalDeserializer self,
        PSObject deserializedObject
    )
    {
        /*
            Called by the deserializer for any object whose type names mark it
            as a serialized CimInstance. PowerShell rebuilds a live CimInstance
            from the __ClassMetadata note the server attached: it initializes
            the MI application, parses each class schema (MiXml) with the
            native deserializer, allocates a native instance and sets every
            property through libmi. Without libmi the first native call
            throws DllNotFoundException, PowerShell wraps it as a transport
            error and the whole pipeline fails.

            This hook is installed on every platform other than Windows, where
            the MI library is part of the OS. It keeps the deserialized
            property bag PowerShell already built, which is exactly what
            RehydrateCimInstance falls back to when the class metadata is
            unusable, and drops the metadata notes that are only meaningful to
            the native rehydration. The result formats and behaves like any
            other deserialized object and does not depend on libmi being
            present or loadable.

            https://github.com/PowerShell/PowerShell/blob/v7.4.0/src/System.Management.Automation/engine/serialization.cs#L3426
        */
        if (deserializedObject.BaseObject is not PSCustomObject)
        {
            return deserializedObject;
        }

        deserializedObject.Properties.Remove(CimClassMetadataProperty);
        deserializedObject.Properties.Remove(CimInstanceMetadataProperty);

        return deserializedObject;
    }

    public static Hook[] GenerateHooks()
    {
        if (OperatingSystem.IsWindows())
        {
            return [];
        }

        return new[]
        {
            new Hook(
                _rehydrateCimInstanceMeth ??= MonoModPatcher.GetMethod(
                    typeof(InternalDeserializer),
                    "RehydrateCimInstance",
                    new[] { typeof(PSObject) },
                    BindingFlags.Instance | BindingFlags.NonPublic
                ),
                RehydrateCimInstancePatch
            ),
        };
    }
}
