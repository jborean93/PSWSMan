using MonoMod.RuntimeDetour;
using System;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Reflection;

namespace PSWSMan.Module.Patches;

internal static class PSWSMan_WSManClientCommandTransportManager
{
    private static FieldInfo? _isClosedField;
    private static FieldInfo? _powershellInstanceIdField;
    private static FieldInfo? _serializedPipelineField;
    private static FieldInfo? _sessnTmField;
    private static FieldInfo? _syncObjectField;
    private static FieldInfo? _tracerField;

    private static MethodInfo? _closeAsyncMeth;
    private static MethodInfo? _createAsyncMeth;
    private static MethodInfo? _disposeMeth;
    private static MethodInfo? _sendOneItemMeth;
    private static MethodInfo? _sendDataMeth;
    private static MethodInfo? _sendStopSignalMeth;
    private static MethodInfo? _startReceivingDataMeth;

    #region Fields/Methods/Properties of WSManClientCommandTransportManager

    private static FieldInfo IsClosedField
    {
        get
        {
            return _isClosedField ??= MonoModPatcher.GetField(
                typeof(WSManClientCommandTransportManager),
                "isClosed",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    private static FieldInfo PowershellInstanceIdField
    {
        get
        {
            return _powershellInstanceIdField ??= MonoModPatcher.GetField(
                typeof(WSManClientCommandTransportManager),
                "powershellInstanceId",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    private static FieldInfo SerializedPipelineField
    {
        get
        {
            return _serializedPipelineField ??= MonoModPatcher.GetField(
                typeof(WSManClientCommandTransportManager),
                "serializedPipeline",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    private static FieldInfo SessnTmField
    {
        get
        {
            return _sessnTmField ??= MonoModPatcher.GetField(
                typeof(WSManClientCommandTransportManager),
                "_sessnTm",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    private static FieldInfo TracerField
    {
        get
        {
            return _tracerField ??= MonoModPatcher.GetField(
                typeof(BaseClientTransportManager),
                "tracer",
                 BindingFlags.NonPublic | BindingFlags.Static
            );
        }
    }

    private static FieldInfo SyncObjectField
    {
        get
        {
            return _syncObjectField ??= MonoModPatcher.GetField(
                typeof(WSManClientCommandTransportManager),
                "syncObject",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    private static MethodInfo SendOneItemMeth
    {
        get
        {
            return _sendOneItemMeth ??= MonoModPatcher.GetMethod(
                typeof(WSManClientCommandTransportManager),
                "SendOneItem",
                Array.Empty<Type>(),
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    #endregion

    #region Patched methods

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
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;
        tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.CloseAsync - Called");

        try
        {
            bool isClosed = (bool)IsClosedField.GetValue(self)!;
            Guid pwshInstanceId = (Guid)PowershellInstanceIdField.GetValue(self)!;
            nint sessionHandle = ((WSManClientSessionTransportManager)SessnTmField.GetValue(self)!).SessionHandle;
            object syncObject = SyncObjectField.GetValue(self)!;

            lock (syncObject)
            {
                if (isClosed)
                {
                    return;
                }

                IsClosedField.SetValue(self, true);
            }

            WSManPSRPShim session = WSManCompatState.SessionInfo[sessionHandle];
            tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.CloseAsync - Sending Stop for {0} CmdId {1}",
                session.RunspacePoolId, pwshInstanceId);

            try
            {
                session.CloseCommandAsync(pwshInstanceId).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                tracer.WriteLine(
                    "PSWSMan: WSManClientCommandTransportManager.CloseAsync - Send failed for {0} CmdId {1}\n{2}",
                    session.RunspacePoolId, pwshInstanceId, e);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.RunShellCommandEx);
                self.ProcessWSManTransportError(err);
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
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.CreateAsync - Called");

            Guid pwshInstanceId = (Guid)PowershellInstanceIdField.GetValue(self)!;
            SerializedDataStream serializedPipeline = (SerializedDataStream)SerializedPipelineField.GetValue(self)!;
            nint sessionHandle = ((WSManClientSessionTransportManager)SessnTmField.GetValue(self)!).SessionHandle;

            WSManPSRPShim session = WSManCompatState.SessionInfo[sessionHandle];
            byte[] cmdPart1 = serializedPipeline.ReadOrRegisterCallback(null) ?? Array.Empty<byte>();

            tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.CreateAsync - Sending Command Create for {0} CmdId {1}",
                session.RunspacePoolId, pwshInstanceId);
            try
            {
                session.CreateCommandAsync(pwshInstanceId, cmdPart1).GetAwaiter().GetResult();
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

            session.StartReceiveTask(self, tracer, commandId: pwshInstanceId);

            SendOneItemMeth.Invoke(self, Array.Empty<Type>());
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
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;
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
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.SendData - Called");

            Guid pwshInstanceId = (Guid)PowershellInstanceIdField.GetValue(self)!;
            nint sessionHandle = ((WSManClientSessionTransportManager)SessnTmField.GetValue(self)!).SessionHandle;

            WSManPSRPShim session = WSManCompatState.SessionInfo[sessionHandle];

            tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.SendData - Sending Data for {0} CmdId {1}",
                session.RunspacePoolId, pwshInstanceId);
            try
            {
                session.SendAsync(priorityType == DataPriorityType.Default ? "stdin" : "pr", data,
                    commandId: pwshInstanceId).GetAwaiter().GetResult();
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

            SendOneItemMeth.Invoke(self, Array.Empty<Type>());
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
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.SendStopSignal - Called");

            Guid pwshInstanceId = (Guid)PowershellInstanceIdField.GetValue(self)!;
            nint sessionHandle = ((WSManClientSessionTransportManager)SessnTmField.GetValue(self)!).SessionHandle;

            WSManPSRPShim session = WSManCompatState.SessionInfo[sessionHandle];

            tracer.WriteLine(
                "PSWSMan: WSManClientCommandTransportManager.SendStopSignal - Sending Stop for {0} CmdId {1}",
                session.RunspacePoolId, pwshInstanceId);
            try
            {
                session.StopCommandAsync(pwshInstanceId).GetAwaiter().GetResult();
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
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;
        tracer.WriteLine("PSWSMan: WSManClientCommandTransportManager.StartReceivingData - Called");
    }

    #endregion

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
