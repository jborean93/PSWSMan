using MonoMod.RuntimeDetour;
using System;
using System.Management.Automation.Remoting.Client;
using System.Reflection;

namespace PSWSMan.Patches;

internal static class PSWSMan_WSManApiDataCommon
{
    private static ConstructorInfo? _cstor;
    private static MethodInfo? _dispose;
    private static FieldInfo? _handleField;

    private static FieldInfo HandleField
    {
        get
        {
            return _handleField ??= MonoModPatcher.GetField(
                typeof(WSManClientSessionTransportManager.WSManAPIDataCommon),
                "_handle",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    private static void CstorPatch(
        Action<WSManClientSessionTransportManager.WSManAPIDataCommon> orig,
        WSManClientSessionTransportManager.WSManAPIDataCommon self
    )
    {
        /*
            WSManClientSessionTransportManager calls WSManAPIDataCommon()
            which does the following:

            - Calls WSManInitialize to init the native client and assigns the handle to WSManAPIHandle
            - Sets the input/output streams to 'stdin pr' and 'stdout'
            - Sets the base option set to include 'protocolversion=2.3'

            Instead this client will just set the WSManAPIHandle to a known
            constant in order to satisfy further null checks.

            https://github.com/PowerShell/PowerShell/blob/042765dd1c4d46a86a4545e7e0df0a7ee19f4dd6/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L2661-L2706

        */
        HandleField.SetValue(self, (nint)(-1));
    }

    private static void DisposePatch(
        Action<WSManClientSessionTransportManager.WSManAPIDataCommon> orig,
        WSManClientSessionTransportManager.WSManAPIDataCommon self
    )
    {
        /*
            The current dispose method tries to clear out various fields and
            properties that are not set anymore. This clears out the handle
            and skips the rest of the work.

            https://github.com/PowerShell/PowerShell/blob/042765dd1c4d46a86a4545e7e0df0a7ee19f4dd6/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L2725-L2760
        */
        HandleField.SetValue(self, IntPtr.Zero);
    }

    public static Hook[] GenerateHooks()
    {
        return new[]
        {
            new Hook(
                _cstor ??= MonoModPatcher.GetConstructor(
                    typeof(WSManClientSessionTransportManager.WSManAPIDataCommon),
                    Array.Empty<Type>(),
                    BindingFlags.Instance | BindingFlags.NonPublic
                ),
                CstorPatch
            ),
            new Hook(
                _dispose ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientSessionTransportManager.WSManAPIDataCommon),
                    nameof(WSManClientSessionTransportManager.WSManAPIData.Dispose),
                    Array.Empty<Type>(),
                    BindingFlags.Instance | BindingFlags.Public
                ),
                DisposePatch
            )
        };
    }
}
