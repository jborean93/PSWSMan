using System;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Runtime.CompilerServices;
using Microsoft.PowerShell.Commands;
using MonoMod.RuntimeDetour;

namespace PSWSMan.Patches;

internal static class PSWSMan_EnterPSSessionCommand
{
    private static MethodInfo? s_createTemporaryRemoteRunspaceMeth;
    private static MethodInfo? s_openMeth;

    [ThreadStatic]
    private static EnterPSSessionCommand? s_openingCommand;

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_tempRunspace")]
    private static extern ref RemoteRunspace? TempRunspace(EnterPSSessionCommand self);

    private static RemoteRunspace? CreateTemporaryRemoteRunspacePatch(
        Func<EnterPSSessionCommand, PSHost, WSManConnectionInfo, RemoteRunspace?> orig,
        EnterPSSessionCommand self,
        PSHost host,
        WSManConnectionInfo connectionInfo
    )
    {
        /*
            StopProcessing only closes the runspace being opened when it is
            stored in _tempRunspace, which pwsh only does for SSH connections.
            For WSMan it pops the host runspace instead which does nothing
            while Open() is still blocked, so Ctrl+C is ignored until the
            connection fails on its own. The runspace is created inside this
            method so mark the command for the Open patch to store it.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/commands/PushRunspaceCommand.cs#L541
            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/commands/PushRunspaceCommand.cs#L577
        */
        EnterPSSessionCommand? previous = s_openingCommand;
        s_openingCommand = self;
        try
        {
            return orig(self, host, connectionInfo);
        }
        finally
        {
            s_openingCommand = previous;
        }
    }

    private static void OpenPatch(
        Action<RemoteRunspace> orig,
        RemoteRunspace self
    )
    {
        EnterPSSessionCommand? command = s_openingCommand;
        if (command is null)
        {
            orig(self);
            return;
        }

        // Cleared before orig runs so a nested Open on this thread is not mistaken for the Enter-PSSession one.
        s_openingCommand = null;
        TempRunspace(command) = self;
        try
        {
            orig(self);
        }
        finally
        {
            TempRunspace(command) = null;
        }
    }

    public static Hook[] GenerateHooks()
    {
        return new[]
        {
            new Hook(
                s_createTemporaryRemoteRunspaceMeth ??= MonoModPatcher.GetMethod(
                    typeof(EnterPSSessionCommand),
                    "CreateTemporaryRemoteRunspace",
                    new[] { typeof(PSHost), typeof(WSManConnectionInfo) },
                    BindingFlags.Instance | BindingFlags.NonPublic
                ),
                CreateTemporaryRemoteRunspacePatch
            ),
            new Hook(
                s_openMeth ??= MonoModPatcher.GetMethod(
                    typeof(RemoteRunspace),
                    nameof(RemoteRunspace.Open),
                    Array.Empty<Type>(),
                    BindingFlags.Instance | BindingFlags.Public
                ),
                OpenPatch
            ),
        };
    }
}
