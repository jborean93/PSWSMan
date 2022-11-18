using System;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using HarmonyLib;

namespace PSWSMan.Patches;


[HarmonyPatch(typeof(WSManClientCommandTransportManager))]
[HarmonyPatch(nameof(WSManClientCommandTransportManager.CreateAsync))]
internal static class Pwsh_WSManClientCommandTransportManagerCreateAsync
{
    static bool Prefix(WSManClientCommandTransportManager __instance, IntPtr ____wsManShellOperationHandle,
        SerializedDataStream ___serializedPipeline, WSManClientSessionTransportManager ____sessnTm,
        Guid ___powershellInstanceId, PSTraceSource ___tracer)
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

        session.StartReceiveTask(__instance, ___tracer, commandId: ___powershellInstanceId);

        // FIXME: Send more packets if available
        // __instance.SendOneItem();
        //byte[]? data = ___dataToBeSent.ReadOrRegisterCallback(____onDataAvailableToSendCallback, out _);

        // SendOneItem

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientCommandTransportManager))]
[HarmonyPatch(nameof(WSManClientCommandTransportManager.SendStopSignal))]
internal static class Pwsh_WSmanClientCommandTransportManagerSendStopSignal
{
    static bool Prefix(WSManClientCommandTransportManager __instance)
    {
        return false;
    }
}

[HarmonyPatch(typeof(WSManClientCommandTransportManager))]
[HarmonyPatch(nameof(WSManClientCommandTransportManager.CloseAsync))]
internal static class Pwsh_WSmanClientCommandTransportManagerCloseAsync
{
    static bool Prefix(WSManClientCommandTransportManager __instance, WSManClientSessionTransportManager ____sessnTm,
        Guid ___powershellInstanceId, object ___syncObject, ref bool ___isClosed)
    {
        lock (___syncObject)
        {
            if (___isClosed)
            {
                return false;
            }

            ___isClosed = true;
        }
        WSManPSRPShim session = WSManCompatState.SessionInfo[____sessnTm.SessionHandle];


        try
        {
            session.CloseCommandAsync(___powershellInstanceId).GetAwaiter().GetResult();
        }
        catch (Exception e)
        {
            TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                TransportMethodEnum.RunShellCommandEx);
            __instance.ProcessWSManTransportError(err);
        }

        __instance.RaiseCloseCompleted();

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientCommandTransportManager))]
[HarmonyPatch(nameof(WSManClientCommandTransportManager.Dispose))]
internal static class Pwsh_WSmanClientCommandTransportManagerDispose
{
    static bool Prefix(WSManClientCommandTransportManager __instance)
    {
        /*
            Called after CloseAsync to free up any unmanaged resources. There's nothing to do in the patched method.
        */
        return false;
    }
}
