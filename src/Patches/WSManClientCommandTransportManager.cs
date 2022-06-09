using System;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Management.Automation.Runspaces;
using System.Reflection;
using HarmonyLib;

namespace PSWSMan.Patches;

[HarmonyPatch(typeof(WSManClientCommandTransportManager))]
[HarmonyPatch(nameof(WSManClientCommandTransportManager.CreateAsync))]
internal static class Pwsh_WSManClientCommandTransportManagerCreateAsync
{
    static bool Prefix(WSManClientCommandTransportManager __instance, IntPtr ____wsManShellOperationHandle,
        SerializedDataStream ___serializedPipeline, WSManClientSessionTransportManager ____sessnTm,
        Guid ___powershellInstanceId)
    {
        WSManPSRPShim session = WSManCompatState.SessionInfo[____sessnTm.SessionHandle];
        byte[] cmdPart1 = ___serializedPipeline.ReadOrRegisterCallback(null) ?? Array.Empty<byte>();

        try
        {
            session.CreateCommandAsync(___powershellInstanceId, cmdPart1).GetAwaiter().GetResult();
        }
        catch (Exception e)
        {
            TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                TransportMethodEnum.RunShellCommandEx);
            __instance.ProcessWSManTransportError(err);
        }

        session.StartReceiveTask(____sessnTm, commandId: ___powershellInstanceId);

        // FIXME: Send more packets if available
        // __instance.SendOneItem();
        //byte[]? data = ___dataToBeSent.ReadOrRegisterCallback(____onDataAvailableToSendCallback, out _);

        // SendOneItem

        return false;
    }
}
