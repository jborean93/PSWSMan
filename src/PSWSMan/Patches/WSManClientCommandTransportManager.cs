using MonoMod.RuntimeDetour;
using System;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace PSWSMan.Patches;

internal static class PSWSMan_WSManClientCommandTransportManager
{
    private static MethodInfo? _closeAsyncMeth;
    private static MethodInfo? _createAsyncMeth;
    private static MethodInfo? _disposeMeth;
    private static MethodInfo? _sendDataMeth;
    private static MethodInfo? _sendStopSignalMeth;
    private static MethodInfo? _startReceivingDataMeth;

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "powershellInstanceId")]
    private static extern ref Guid PowershellInstanceId(BaseClientCommandTransportManager self);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "serializedPipeline")]
    private static extern ref SerializedDataStream SerializedPipeline(BaseClientCommandTransportManager self);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_sessnTm")]
    private static extern ref WSManClientSessionTransportManager SessnTm(WSManClientCommandTransportManager self);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "SendOneItem")]
    private static extern void SendOneItem(WSManClientCommandTransportManager self);

    private static void CloseAsyncPatch(
        Action<WSManClientCommandTransportManager> orig,
        WSManClientCommandTransportManager self
    )
    {
        /*
            Called when a pipeline is being closed, WSMan needs to send the
            Terminal Signal to clear up any resources.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L3153
        */
        PSTraceSource tracer = BaseClientTransportManager.tracer;
        tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.CloseAsync - Called");

        try
        {
            Guid pwshInstanceId = PowershellInstanceId(self);
            nint sessionHandle = SessnTm(self).SessionHandle;

            lock (self.syncObject)
            {
                if (self.isClosed)
                {
                    return;
                }

                self.isClosed = true;
            }

            WSManPSRPSession session = WSManSessionState.Get(sessionHandle);
            tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.CloseAsync - Sending Stop for {0} CmdId {1}",
                session.RunspacePoolId, pwshInstanceId);

            try
            {
                session.CloseCommand(pwshInstanceId);
            }
            catch (Exception e)
            {
                tracer.WriteLine(
                    "PSWSMan: WSManClientCommandTransportManager.CloseAsync - Send failed for {0} CmdId {1}\n{2}",
                    session.RunspacePoolId, pwshInstanceId, e);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.CloseShellOperationEx);
                self.RaiseErrorHandler(err);
                return;
            }

            self.RaiseCloseCompleted();
        }
        catch (Exception e)
        {
            tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.CloseAsync - Error\n{0}",
                e.ToString());
            throw;
        }
    }

    private static void CreateAsyncPatch(
        Action<WSManClientCommandTransportManager> orig,
        WSManClientCommandTransportManager self
    )
    {
        /*
            Called when a pipeline is to be created. This simply does:
            - Sends the WSMan Command payload
            - Starts a new thread with a receive task
            - Sends remaining data (if any)

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L3024
        */
        PSTraceSource tracer = BaseClientTransportManager.tracer;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.CreateAsync - Called");

            Guid pwshInstanceId = PowershellInstanceId(self);
            SerializedDataStream serializedPipeline = SerializedPipeline(self);
            nint sessionHandle = SessnTm(self).SessionHandle;

            WSManPSRPSession session = WSManSessionState.Get(sessionHandle);
            byte[] cmdPart1 = serializedPipeline.ReadOrRegisterCallback(null) ?? Array.Empty<byte>();

            tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.CreateAsync - Sending Command Create for {0} CmdId {1}",
                session.RunspacePoolId, pwshInstanceId);
            try
            {
                session.CreateCommand(pwshInstanceId, cmdPart1);
            }
            catch (Exception e)
            {
                tracer.WriteLine(
                    "PSWSMan: WSManClientCommandTransportManager.CreateAsync - Shell Command failed for {0} CmdId {1}\n{2}",
                    session.RunspacePoolId, pwshInstanceId, e);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.RunShellCommandEx);
                self.ProcessWSManTransportError(err);
                return;
            }

            session.StartReceive(self, commandId: pwshInstanceId);

            SendOneItem(self);
        }
        catch (Exception e)
        {
            tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.CreateAsync - Error\n{0}", e.ToString());
        }
    }

    private static void DisposePatch(
        Action<WSManClientCommandTransportManager, bool> orig,
        WSManClientCommandTransportManager self,
        bool isDisposing
    )
    {
        /*
            Called after CloseAsync to free up any unmanaged resources.
            There's nothing to do in the patched method.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L4093
        */
        PSTraceSource tracer = BaseClientTransportManager.tracer;
        tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.Dispose - Called");
    }

    private static void SendDataPatch(
        Action<WSManClientCommandTransportManager, byte[], DataPriorityType> orig,
        WSManClientCommandTransportManager self,
        byte[] data,
        DataPriorityType priorityType
    )
    {
        /*
            Called when data needs to be sent to the Command/Pipeline.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L4003
        */
        PSTraceSource tracer = BaseClientTransportManager.tracer;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.SendData - Called");

            Guid pwshInstanceId = PowershellInstanceId(self);
            nint sessionHandle = SessnTm(self).SessionHandle;

            WSManPSRPSession session = WSManSessionState.Get(sessionHandle);

            tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.SendData - Sending Data for {0} CmdId {1}",
                session.RunspacePoolId, pwshInstanceId);
            try
            {
                session.Send(priorityType == DataPriorityType.Default ? "stdin" : "pr", data,
                    commandId: pwshInstanceId);
            }
            catch (Exception e)
            {
                tracer.WriteLine(
                    "PSWSMan: WSManClientCommandTransportManager.SendData - Send failed for {0} CmdId {1}\n{2}",
                    session.RunspacePoolId, pwshInstanceId, e);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.RunShellCommandEx);
                self.ProcessWSManTransportError(err);
                return;
            }

            SendOneItem(self);
        }
        catch (Exception e)
        {
            tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.SendData - Error\n{0}", e.ToString());
            throw;
        }
    }

    private static void SendStopSignalPatch(
        Action<WSManClientCommandTransportManager> orig,
        WSManClientCommandTransportManager self
    )
    {
        /*
            Called when pwsh is attempting to stop a running pipeline.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L3114
        */
        PSTraceSource tracer = BaseClientTransportManager.tracer;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.SendStopSignal - Called");

            Guid pwshInstanceId = PowershellInstanceId(self);
            nint sessionHandle = SessnTm(self).SessionHandle;

            WSManPSRPSession session = WSManSessionState.Get(sessionHandle);

            tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.SendStopSignal - Sending Stop for {0} CmdId {1}",
                session.RunspacePoolId, pwshInstanceId);
            try
            {
                session.StopCommand(pwshInstanceId);
            }
            catch (Exception e)
            {
                tracer.WriteLine(
                    "PSWSMan: WSManClientCommandTransportManager.SendStopSignal - Send failed for {0} CmdId {1}\n{2}",
                    session.RunspacePoolId, pwshInstanceId, e);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.RunShellCommandEx);
                self.ProcessWSManTransportError(err);
                return;
            }

            self.EnqueueAndStartProcessingThread(null, null, true);
        }
        catch (Exception e)
        {
            tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.SendStopSignal - Error\n{0}",
                e.ToString());
            throw;
        }
    }

    private static void StartReceivingDataPatch(
        Action<WSManClientCommandTransportManager> orig,
        WSManClientCommandTransportManager self
    )
    {
        /*
            Called after CloseAsync to free up any unmanaged resources.
            There's nothing to do in the patched method.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L4055
        */
        PSTraceSource tracer = BaseClientTransportManager.tracer;
        tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.StartReceivingData - Called");
    }

    public static Hook[] GenerateHooks()
    {
        return new[]
        {
            new Hook(
                _closeAsyncMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientCommandTransportManager),
                    nameof(WSManClientCommandTransportManager.CloseAsync),
                    Array.Empty<Type>(),
                    // 7.2 has it as NonPublic, 7.3 made it Public
                    BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public
                ),
                CloseAsyncPatch
            ),
            new Hook(
                _createAsyncMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientCommandTransportManager),
                    nameof(WSManClientCommandTransportManager.CreateAsync),
                    Array.Empty<Type>(),
                    // 7.2 has it as NonPublic, 7.3 made it Public
                    BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public
                ),
                CreateAsyncPatch
            ),
            new Hook(
                _disposeMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientCommandTransportManager),
                    nameof(WSManClientCommandTransportManager.Dispose),
                    new[] { typeof(bool) },
                    BindingFlags.Instance | BindingFlags.NonPublic
                ),
                DisposePatch
            ),
            new Hook(
                _sendDataMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientCommandTransportManager),
                    "SendData",
                    new[] { typeof(byte[]), typeof(DataPriorityType) },
                    BindingFlags.Instance | BindingFlags.NonPublic
                ),
                SendDataPatch
            ),
            new Hook(
                _sendStopSignalMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientCommandTransportManager),
                    nameof(WSManClientCommandTransportManager.SendStopSignal),
                    Array.Empty<Type>(),
                    BindingFlags.Instance | BindingFlags.NonPublic
                ),
                SendStopSignalPatch
            ),
            new Hook(
                _startReceivingDataMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientCommandTransportManager),
                    nameof(WSManClientCommandTransportManager.StartReceivingData),
                    Array.Empty<Type>(),
                    BindingFlags.Instance | BindingFlags.NonPublic
                ),
                StartReceivingDataPatch
            )
        };
    }
}
