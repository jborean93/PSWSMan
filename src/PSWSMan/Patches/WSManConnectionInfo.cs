using MonoMod.RuntimeDetour;
using PSWSMan.Shared;
using System;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Runspaces;
using System.Reflection;

namespace PSWSMan.Module.Patches;

internal static class PSWSMan_WSManConnectionInfo
{
    private static MethodInfo? _copyMeth;
    private static MethodInfo? _setSessionOptionsMeth;

    private static WSManConnectionInfo CopyPatch(
        Func<WSManConnectionInfo, WSManConnectionInfo> orig,
        WSManConnectionInfo self
    )
    {
        /*
            PowerShell makes copies of this instance so this ensures the ETS
            member holding the extra session options are also copied across to
            the new copy.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/common/RunspaceConnectionInfo.cs#L1071
        */

        WSManConnectionInfo result = orig(self);
        CopyPSProperty(self, result, PSWSManSessionOption.PSWSMAN_SESSION_OPTION_PROP);

        return result;
    }

    private static void SetSessionOptionsPatch(
        Action<WSManConnectionInfo, PSSessionOption> orig,
        WSManConnectionInfo self,
        PSSessionOption options
    )
    {
        /*
            Ensures the extra PSWSMan session options that might be present on
            the connection object are also transferred to the
            WSManConnectionInfo instance.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/common/RunspaceConnectionInfo.cs#L1021
        */
        orig(self, options);
        CopyPSProperty(options, self, PSWSManSessionOption.PSWSMAN_SESSION_OPTION_PROP);
    }

    public static Hook[] GenerateHooks()
    {
        return new[]
        {
            new Hook(
                _copyMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManConnectionInfo),
                    nameof(WSManConnectionInfo.Copy),
                    Array.Empty<Type>(),
                    BindingFlags.Instance | BindingFlags.Public
                ),
                CopyPatch
            ),
            new Hook(
                _setSessionOptionsMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManConnectionInfo),
                    nameof(WSManConnectionInfo.SetSessionOptions),
                    new[] { typeof(PSSessionOption) },
                    BindingFlags.Instance | BindingFlags.Public
                ),
                SetSessionOptionsPatch
            )
        };
    }

    private static void CopyPSProperty(object src, object dst, string name)
    {
        PSPropertyInfo? property = PSObject.AsPSObject(src).Properties[name];
        if (property is not null)
        {
            PSObject.AsPSObject(dst).Properties.Add(property);
        }
    }
}
