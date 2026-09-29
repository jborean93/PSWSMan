using System;
using System.Management.Automation.Host;
using System.Management.Automation.Remoting;
using System.Reflection;
using MonoMod.RuntimeDetour;

namespace PSWSMan.Patches;

internal static class PSWSMan_RemoteHostCall
{
    private static MethodInfo? s_executeVoidMethodMeth;

    private static void ExecuteVoidMethodPatch(
        Action<RemoteHostCall, PSHost> orig,
        RemoteHostCall self,
        PSHost clientHost
    )
    {
        /*
            Clear-Host on a Windows server moves the cursor to 0,0 and calls
            RawUI.SetBufferContents with a rectangle of -1 and a space fill
            which means clear the whole screen. The console host on non-Windows does not
            implement SetBufferContents at all so the remote Clear-Host only
            moves the cursor and fails with 'The method or operation is not
            implemented'.

            The host is still called first rather than matching on the method
            and its arguments up front. Any host that does implement
            SetBufferContents, the Windows console host or a custom host,
            keeps its own behaviour and only the not implemented failure for
            the full screen clear is replaced. Console.Clear() is what the
            console host would do for this call and matches the local
            Clear-Host on non-Windows. It is skipped when stdout is redirected
            as there is no screen to clear, Unix treats that as a no-op but
            Windows throws.

            This patch should be removed if/when PowerShell fixes the problem.

            https://github.com/PowerShell/PowerShell/issues/28115
            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/InitialSessionState.cs#L4090
            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/common/WireDataFormat/RemoteHost.cs#L169
        */
        try
        {
            orig(self, clientHost);
        }
        catch (TargetInvocationException e) when (
            e.InnerException is NotImplementedException &&
            self.MethodId == RemoteHostMethodId.SetBufferContents1 &&
            self.Parameters.Length > 1 &&
            self.Parameters[0] is Rectangle { Left: -1, Top: -1, Right: -1, Bottom: -1 } &&
            self.Parameters[1] is BufferCell { Character: ' ' }
        )
        {
            if (!Console.IsOutputRedirected)
            {
                Console.Clear();
            }
        }
    }

    public static Hook[] GenerateHooks()
    {
        return new[]
        {
            new Hook(
                s_executeVoidMethodMeth ??= MonoModPatcher.GetMethod(
                    typeof(RemoteHostCall),
                    nameof(RemoteHostCall.ExecuteVoidMethod),
                    new[] { typeof(PSHost) },
                    BindingFlags.Instance | BindingFlags.NonPublic
                ),
                ExecuteVoidMethodPatch
            ),
        };
    }
}
