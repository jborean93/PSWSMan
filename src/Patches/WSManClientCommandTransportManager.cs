using HarmonyLib;
using System;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Reflection;

namespace PSWSMan.Patches;


[HarmonyPatch(typeof(WSManClientCommandTransportManager))]
[HarmonyPatch(nameof(WSManClientCommandTransportManager.CreateAsync))]
internal static class Pwsh_WSManClientCommandTransportManagerCreateAsync
{
    static bool Prefix(WSManClientCommandTransportManager __instance, SerializedDataStream ___serializedPipeline,
        WSManClientSessionTransportManager ____sessnTm, Guid ___powershellInstanceId, PSTraceSource ___tracer)
    {
        /*
            Called when a pipeline is to be created. This simply does:
            - Sends the WSMan Command payload
            - Starts a new thread with a receive task
            - Sends remaining data (if any)
        */
        ___tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.CreateAsync - Called");

        try
        {
            WSManPSRPShim session = WSManCompatState.SessionInfo[____sessnTm.SessionHandle];
            byte[] cmdPart1 = ___serializedPipeline.ReadOrRegisterCallback(null) ?? Array.Empty<byte>();

            ___tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.CreateAsync - Sending Command Create for {0} CmdId {1}",
                session.RunspacePoolId, ___powershellInstanceId);
            try
            {
                session.CreateCommandAsync(___powershellInstanceId, cmdPart1).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                ___tracer.WriteLine(
                    "PSWSMan: WSManClientCommandTransportManager.CreateAsync - Shell Command failed for {0} CmdId {1}\n{2}",
                    session.RunspacePoolId, ___powershellInstanceId, e);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.RunShellCommandEx);
                __instance.ProcessWSManTransportError(err);
                return false;
            }

            session.StartReceiveTask(__instance, ___tracer, commandId: ___powershellInstanceId);

            typeof(WSManClientCommandTransportManager).GetMethod(
                "SendOneItem",
                BindingFlags.NonPublic | BindingFlags.Instance)
                ?.Invoke(__instance, Array.Empty<Type>());
        }
        catch (Exception e)
        {
            ___tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.CreateAsync - Error\n{0}", e.ToString());
        }

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientCommandTransportManager))]
[HarmonyPatch(nameof(WSManClientCommandTransportManager.SendStopSignal))]
internal static class Pwsh_WSmanClientCommandTransportManagerSendStopSignal
{
    static bool Prefix(WSManClientCommandTransportManager __instance, WSManClientSessionTransportManager ____sessnTm,
        Guid ___powershellInstanceId, PSTraceSource ___tracer)
    {
        /*
            Called when pwsh is attempting to stop a running pipeline.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.SendStopSignal - Called");

        try
        {
            WSManPSRPShim session = WSManCompatState.SessionInfo[____sessnTm.SessionHandle];

            ___tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.SendStopSignal - Sending Stop for {0} CmdId {1}",
                session.RunspacePoolId, ___powershellInstanceId);
            try
            {
                session.StopCommandAsync(___powershellInstanceId).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                ___tracer.WriteLine(
                    "PSWSMan: WSManClientCommandTransportManager.SendStopSignal - Send failed for {0} CmdId {1}\n{2}",
                    session.RunspacePoolId, ___powershellInstanceId, e);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.RunShellCommandEx);
                __instance.ProcessWSManTransportError(err);
                return false;
            }

            __instance.EnqueueAndStartProcessingThread(null, null, true);
        }
        catch (Exception e)
        {
            ___tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.SendStopSignal - Error\n{0}",
                e.ToString());
            throw;
        }

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientCommandTransportManager))]
[HarmonyPatch(nameof(WSManClientCommandTransportManager.CloseAsync))]
internal static class Pwsh_WSmanClientCommandTransportManagerCloseAsync
{
    static bool Prefix(WSManClientCommandTransportManager __instance, WSManClientSessionTransportManager ____sessnTm,
        Guid ___powershellInstanceId, PSTraceSource ___tracer, object ___syncObject, ref bool ___isClosed)
    {
        /*
            Called when a pipeline is being closed, WSMan needs to send the Terminal Signal to clear up any resources.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.CloseAsync - Called");

        try
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
            ___tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.CloseAsync - Sending Stop for {0} CmdId {1}",
                session.RunspacePoolId, ___powershellInstanceId);

            try
            {
                session.CloseCommandAsync(___powershellInstanceId).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                ___tracer.WriteLine(
                    "PSWSMan: WSManClientCommandTransportManager.CloseAsync - Send failed for {0} CmdId {1}\n{2}",
                    session.RunspacePoolId, ___powershellInstanceId, e);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.RunShellCommandEx);
                __instance.ProcessWSManTransportError(err);
            }

            __instance.RaiseCloseCompleted();
        }
        catch (Exception e)
        {
            ___tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.CloseAsync - Error\n{0}",
                e.ToString());
            throw;
        }

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientCommandTransportManager))]
[HarmonyPatch(nameof(WSManClientCommandTransportManager.Dispose))]
internal static class Pwsh_WSmanClientCommandTransportManagerDispose
{
    static bool Prefix(WSManClientCommandTransportManager __instance, PSTraceSource ___tracer)
    {
        /*
            Called after CloseAsync to free up any unmanaged resources. There's nothing to do in the patched method.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.Dispose - Called");

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientCommandTransportManager))]
[HarmonyPatch("SendData")]
internal static class Pwsh_WSmanClientCommandTransportManagerSendData
{
    static bool Prefix(WSManClientCommandTransportManager __instance, WSManClientSessionTransportManager ____sessnTm,
        Guid ___powershellInstanceId, PSTraceSource ___tracer, byte[] data, DataPriorityType priorityType)
    {
        /*
            Called after CloseAsync to free up any unmanaged resources. There's nothing to do in the patched method.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.SendData - Called");

        try
        {
            WSManPSRPShim session = WSManCompatState.SessionInfo[____sessnTm.SessionHandle];

            ___tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.SendData - Sending Data for {0} CmdId {1}",
                session.RunspacePoolId, ___powershellInstanceId);
            try
            {
                session.SendAsync(priorityType == DataPriorityType.Default ? "stdin" : "pr", data,
                    commandId: ___powershellInstanceId).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                ___tracer.WriteLine(
                    "PSWSMan: WSManClientCommandTransportManager.SendData - Send failed for {0} CmdId {1}\n{2}",
                    session.RunspacePoolId, ___powershellInstanceId, e);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.RunShellCommandEx);
                __instance.ProcessWSManTransportError(err);
                return false;
            }

            typeof(WSManClientCommandTransportManager).GetMethod(
                "SendOneItem",
                BindingFlags.NonPublic | BindingFlags.Instance)
                ?.Invoke(__instance, Array.Empty<Type>());
        }
        catch (Exception e)
        {
            ___tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.SendData - Error\n{0}", e.ToString());
            throw;
        }

        return false;
    }
}


[HarmonyPatch(typeof(WSManClientCommandTransportManager))]
[HarmonyPatch(nameof(WSManClientCommandTransportManager.StartReceivingData))]
internal static class Pwsh_WSmanClientCommandTransportManagerStartReceivingData
{
    static bool Prefix(WSManClientCommandTransportManager __instance, PSTraceSource ___tracer)
    {
        /*
            Called after CloseAsync to free up any unmanaged resources. There's nothing to do in the patched method.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.StartReceivingData - Called");

        return false;
    }
}
