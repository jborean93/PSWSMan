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
        // The Enable-PSWSMan half of RemoteClearHost, the builtin cmdlets create the runspace with their own host so
        // it cannot be wrapped like the WinRM session cmdlets do.
        try
        {
            orig(self, clientHost);
        }
        catch (TargetInvocationException e) when (
            e.InnerException is NotImplementedException &&
            self.MethodId == RemoteHostMethodId.SetBufferContents1 &&
            self.Parameters.Length > 1 &&
            self.Parameters[0] is Rectangle rectangle &&
            self.Parameters[1] is BufferCell fill &&
            RemoteClearHost.IsClearScreen(rectangle, fill)
        )
        {
            RemoteClearHost.Clear();
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
