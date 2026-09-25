using MonoMod.RuntimeDetour;
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;

namespace PSWSMan.Patches;

internal static class PSWSMan_RemoteRunspace
{
    private static MethodInfo? _getCapabilitiesMeth;

    private static RunspaceCapability GetCapabilitiesPatch(
        Func<RemoteRunspace, RunspaceCapability> orig,
        RemoteRunspace self
    )
    {
        /*
            CommandCompletion.CompleteInput treats a RemoteRunspace whose
            capabilities are exactly Default as a pre-PSv3 server without
            TabExpansion2 and skips tab completion entirely. The WSMan
            transport only escapes Default by reporting SupportsDisconnect,
            which pwsh reads from the native shell create flags this module
            never produces. Claiming SupportsDisconnect is not an option as
            it makes Disconnect-PSSession, Invoke-Command -InDisconnectedSession
            and the shutdown path (CloseOrDisconnectRunspaceOperationHelper)
            call into the unimplemented disconnect operations instead of
            closing the session.

            Instead the runspace is reported as a CustomTransport, the same
            capability pwsh assigns to any third party connection type.
            Nothing in pwsh acts on that bit, it only stops the capabilities
            from being Default. Once enabled every WSManConnectionInfo based
            runspace is served by this module so no other check is needed.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/client/remoterunspace.cs#L929
            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/CommandCompletion/CommandCompletion.cs#L187
        */
        RunspaceCapability capabilities = orig(self);
        if (self.ConnectionInfo is WSManConnectionInfo)
        {
            capabilities |= RunspaceCapability.CustomTransport;
        }

        return capabilities;
    }

    public static Hook[] GenerateHooks()
    {
        return new[]
        {
            new Hook(
                _getCapabilitiesMeth ??= MonoModPatcher.GetMethod(
                    typeof(RemoteRunspace),
                    nameof(RemoteRunspace.GetCapabilities),
                    Array.Empty<Type>(),
                    BindingFlags.Instance | BindingFlags.Public
                ),
                GetCapabilitiesPatch
            ),
        };
    }
}
