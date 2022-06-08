using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Runspaces;
using HarmonyLib;

namespace PSWSMan.Patches;

[HarmonyPatch(typeof(WSManConnectionInfo))]
internal static class Pwsh_WSManConnectionInfo
{
    [HarmonyPatch(nameof(WSManConnectionInfo.SetSessionOptions))]
    static void Postfix(WSManConnectionInfo __instance, PSSessionOption options)
    {
        /*
            Ensures the extra PSWSMan session options that might be present on the connection object are also tranfered
            to the WSManConnectionInfo instance
        */
        CopyPSProperty(options, __instance, PSWSManSessionOption.PSWSMAN_SESSION_OPTION_PROP);
    }

    [HarmonyPatch(nameof(WSManConnectionInfo.Copy))]
    static void Postfix(WSManConnectionInfo __instance, ref WSManConnectionInfo __result)
    {
        /*
            PowerShell makes copies of this instance so this ensures the ETS member holding the extra session options
            are also copied across to the new copy.
        */
        CopyPSProperty(__instance, __result, PSWSManSessionOption.PSWSMAN_SESSION_OPTION_PROP);
    }

    static void CopyPSProperty(object src, object dst, string name)
    {
        PSPropertyInfo? property = PSObject.AsPSObject(src).Properties[name];
        if (property is not null)
        {
            PSObject.AsPSObject(dst).Properties.Add(property);
        }
    }
}
