using System;
using System.Management.Automation.Remoting.Client;
using HarmonyLib;

namespace PSWSMan.Patches;

[HarmonyPatch(typeof(WSManClientSessionTransportManager.WSManAPIDataCommon))]
[HarmonyPatch(MethodType.Constructor)]
internal static class Pwsh_WSManApiDataCommonCstor
{
    static bool Prefix(ref IntPtr ____handle)
    {
        /*
            WSManClientSessionTransportManager calls WSManAPIDataCommon() which does the following:
            - Calls WSManInitialize to init the native client and assigns the handle to WSManAPIHandle
            - Sets the input/output streams to 'stdin pr' and 'stdout'
            - Sets the base option set to include 'protocolversion=2.3'

            Instead this client will just set the WSManAPIHandle to a known constant in order to satisfy further null
            checks.

            https://github.com/PowerShell/PowerShell/blob/042765dd1c4d46a86a4545e7e0df0a7ee19f4dd6/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L2661-L2706

        */
        ____handle = (IntPtr)(-1);
        return false;
    }
}

[HarmonyPatch(typeof(WSManClientSessionTransportManager.WSManAPIDataCommon))]
[HarmonyPatch(nameof(WSManClientSessionTransportManager.WSManAPIDataCommon.Dispose))]
internal static class Pwsh_WSManApiDataCommonDispose
{
    static bool Prefix(ref IntPtr ____handle)
    {
        /*
            The current dispose method tries to clear out various fields and properties that are not set anymore. This
            clears out the handle and skips the rest of the work.

            https://github.com/PowerShell/PowerShell/blob/042765dd1c4d46a86a4545e7e0df0a7ee19f4dd6/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L2725-L2760
        */
        ____handle = IntPtr.Zero;
        return false;
    }
}
