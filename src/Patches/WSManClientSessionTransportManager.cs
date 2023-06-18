using MonoMod.RuntimeDetour;
using System;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Management.Automation.Runspaces;
using System.Reflection;

namespace PSWSMan.Patches;

internal static class PSWSMan_WSManClientSessionTransportManager
{
    private static FieldInfo? _dataToBeSentField;
    private static FieldInfo? _syncObjectField;
    private static FieldInfo? _tracerField;
    private static FieldInfo? _wsManSessionHandleField;
    private static FieldInfo? _wsManShellOperationHandleField;

    private static MethodInfo? _adjustForProtocolVariationsMeth;
    private static MethodInfo? _closeAsyncMeth;
    private static MethodInfo? _closeSessionAndClearResourcesMeth;
    private static MethodInfo? _createAsyncMeth;
    private static MethodInfo? _disposeMeth;
    private static MethodInfo? _initializeMeth;
    private static MethodInfo? _sendOneItemMeth;
    private static MethodInfo? _sendDataMeth;
    private static MethodInfo? _startReceivingDataMeth;

    private static PropertyInfo? _connectionInfoProp;
    private static PropertyInfo? _supportedDisconnectProp;

    #region Fields/Methods/Properties of WSManClientSessionTransportManager

    private static FieldInfo DataToBeSentField
    {
        get
        {
            return _dataToBeSentField ??= MonoModPatcher.GetField(
                typeof(WSManClientSessionTransportManager),
                "dataToBeSent",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    private static FieldInfo SyncObjectField
    {
        get
        {
            return _syncObjectField ??= MonoModPatcher.GetField(
                typeof(WSManClientSessionTransportManager),
                "syncObject",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    private static FieldInfo WSManSessionHandleField
    {
        get
        {
            return _wsManSessionHandleField ??= MonoModPatcher.GetField(
                typeof(WSManClientSessionTransportManager),
                "_wsManSessionHandle",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    private static FieldInfo WSManShellOperationHandleField
    {
        get
        {
            return _wsManShellOperationHandleField ??= MonoModPatcher.GetField(
                typeof(WSManClientSessionTransportManager),
                "_wsManShellOperationHandle",
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

    private static MethodInfo SendOneItemMeth
    {
        get
        {
            return _sendOneItemMeth ??= MonoModPatcher.GetMethod(
                typeof(WSManClientSessionTransportManager),
                "SendOneItem",
                Array.Empty<Type>(),
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    private static PropertyInfo ConnectionInfoProperty
    {
        get
        {
            return _connectionInfoProp ??= MonoModPatcher.GetProperty(
                typeof(WSManClientSessionTransportManager),
                nameof(WSManClientSessionTransportManager.ConnectionInfo),
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    private static PropertyInfo SupportsDisconnectProperty
    {
        get
        {
            return _supportedDisconnectProp ??= MonoModPatcher.GetProperty(
                typeof(WSManClientSessionTransportManager),
                "SupportsDisconnect",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
        }
    }

    #endregion

    #region Patched methods

    private static void AdjustForProtocolVariationsPatch(
        Action<WSManClientSessionTransportManager, Version> orig,
        WSManClientSessionTransportManager self,
        Version serverProtocolVersion
    )
    {
        /*
            Called when PowerShell receives the server's session capability
            message. It uses this message to adjust the MaxEnvelopeSize if
            it's talking to a newer host (Win 8/Server 2012+) so it can send
            larger fragments.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L1259
        */
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;

        try
        {
            tracer.WriteLine(
                "PSWSMan: WSManClientSessionTransportManager.AdjustForProtocolVariations - Called with {0}",
                serverProtocolVersion);

            nint wsManSessionHandle = (nint)WSManSessionHandleField.GetValue(self)!;
            if (wsManSessionHandle == IntPtr.Zero)
            {
                return;
            }

            WSManPSRPShim session = WSManCompatState.SessionInfo[wsManSessionHandle];
            if (serverProtocolVersion > new Version("2.1") && session.GetMaxEnvelopeSize() == WSManSessionOption.DefaultMaxEnvelopeSize)
            {
                tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.AdjustForProtocolVariations - Updating max fragmenent size to 500KiB for {0}",
                    session.RunspacePoolId);

                int newEnvelopeSize = 500 << 10;
                session.SetMaxEnvelopeSize(newEnvelopeSize);

                // The fragmenter size needs to fit a base64 encoded value of
                // those bytes into the WSMan envelope. Use 2048 as a high
                // level envelope size and (_ / 4) * 3 to get the max length
                // that can fit in a base64 encoded string in the envelope.
                self.Fragmentor.FragmentSize = (newEnvelopeSize - 2048) / 4 * 3;
            }
        }
        catch (Exception e)
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.AdjustForProtocolVariations - Error\n{0}",
                e.ToString());
            throw;
        }
    }

    private static void CloseAsyncPatch(
        Action<WSManClientSessionTransportManager> orig,
        WSManClientSessionTransportManager self
    )
    {
        /*
            Called when closing the Runspace, simply send the Delete operation
            and wait for the response.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L3153C25-L3153C25
        */
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.CloseAsync - Called");

            nint wsManSessionHandle = (nint)WSManSessionHandleField.GetValue(self)!;
            if (wsManSessionHandle != IntPtr.Zero)
            {
                WSManPSRPShim session = WSManCompatState.SessionInfo[wsManSessionHandle];

                tracer.WriteLine(
                    "PSWSMan: WSManClientSessionTransportManager.CloseAsync - Sending Shell Delete for {0}",
                    session.RunspacePoolId);
                try
                {
                    session.CloseShellAsync().GetAwaiter().GetResult();
                }
                catch (Exception e)
                {
                    tracer.WriteLine(
                        "PSWSMan: WSManClientSessionTransportManager.CloseAsync - Delete failed for {0}\n{1}",
                        session.RunspacePoolId, e);

                    WSManCompatState.SessionInfo.Remove(wsManSessionHandle);
                    WSManSessionHandleField.SetValue(self, IntPtr.Zero);

                    TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                        TransportMethodEnum.RunShellCommandEx);
                    self.ProcessWSManTransportError(err);
                }
            }

            self.RaiseCloseCompleted();
        }
        catch (Exception e)
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.CloseAsync - Error\n{0}", e.ToString());
            throw;
        }
    }

    private static void CloseSessionAndClearResourcesPatch(
        Action<WSManClientSessionTransportManager> orig,
        WSManClientSessionTransportManager self
    )
    {
        /*
            Called in a few places but our cleanup happens elsewhere so just
            ignore it.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L2567
        */
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;
        tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.CloseSessionAndClearResources - Called");
    }

    private static void CreateAsyncPatch(
        Action<WSManClientSessionTransportManager> orig,
        WSManClientSessionTransportManager self
    )
    {
        /*
            This method sends the WSMan Create message. In Pwsh it returns
            early and the native API invokes a callback function that
            handles the response. As this library has finer control the
            callback mess is avoided the response is also processed here.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L3024
        */
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.CreateAsync - Called");

            nint wsManSessionHandle = (nint)WSManSessionHandleField.GetValue(self)!;
            WSManPSRPShim session = WSManCompatState.SessionInfo[wsManSessionHandle];

            PrioritySendDataCollection dataToBeSent = (PrioritySendDataCollection)DataToBeSentField.GetValue(self)!;
            byte[] additionalData = dataToBeSent.ReadOrRegisterCallback(null, out var _);

            tracer.WriteLine(
                "PSWSMan: WSManClientSessionTransportManager.CreateAsync - Sending Shell Create for {0}",
                session.RunspacePoolId);
            try
            {
                session.CreateShellAsync(additionalData ?? Array.Empty<byte>()).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                tracer.WriteLine(
                    "PSWSMan: WSManClientSessionTransportManager.CreateAsync - Shell Create failed for {0}\n{1}",
                    session.RunspacePoolId, e);

                WSManCompatState.SessionInfo.Remove(wsManSessionHandle);
                WSManSessionHandleField.SetValue(self, IntPtr.Zero);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.CreateShellEx);
                self.ProcessWSManTransportError(err);
                return;
            }

            // Satifies some Debug.Assert statements in pwsh
            WSManShellOperationHandleField.SetValue(self, (nint)1);

            // FUTURE: Add disconnect support
            SupportsDisconnectProperty.SetValue(self, false);

            self.RaiseCreateCompleted(new CreateCompleteEventArgs(self.ConnectionInfo.Copy()));

            // Start the receive thread that continuously polls the receive output. The first message expected back
            // is the SessionCapability which will fire the AdjustForProtocolVariations and StartReceivingData methods
            // where the remaining Runspace creation messages (if any) are sent.
            session.StartReceiveTask(self, tracer);
        }
        catch (Exception e)
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.CreateAsync - Error\n{0}", e.ToString());
            throw;
        }
    }

    private static void DisposePatch(
        Action<WSManClientSessionTransportManager, bool> orig,
        WSManClientSessionTransportManager self,
        bool isDisposing
    )
    {
        /*
            Called after the Runspace has been closed. Just need to remove the
            shim from the global state.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L2725
        */
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.Dispose - Called");

            nint wsManSessionHandle = (nint)WSManSessionHandleField.GetValue(self)!;
            if (wsManSessionHandle != IntPtr.Zero)
            {
                WSManPSRPShim session = WSManCompatState.SessionInfo[wsManSessionHandle];
                session.Dispose();

                WSManCompatState.SessionInfo.Remove(wsManSessionHandle);
                WSManSessionHandleField.SetValue(self, IntPtr.Zero);
            }
        }
        catch (Exception e)
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.Dispose - Error\n{0}", e.ToString());
            throw;
        }
    }

    private static void InitializePatch(
        Action<WSManClientSessionTransportManager, Uri, WSManConnectionInfo> orig,
        WSManClientSessionTransportManager self,
        Uri connectionUri,
        WSManConnectionInfo connectionInfo
    )
    {
        /*
            WSManClientSessionTransportManager.Initialize() is called by the
            constructor and for redirected requests and does the following:

            - Adds extra query params to the connection Uri based on a few different parameters
            - Sets up the authentication information
            - Sets up the proxy information
            - Creates a WSMan session handle
            - Sets the various connection options like timeouts and cert checks

            The patched code sets the same properties as Initialize and stores
            the mapping of the connection details into a global state for
            later referencing. Building the actual connection and setting the
            options is done later on when the connection is being created.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L1376
        */

        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.Initialized - Called");

            object syncObject = SyncObjectField.GetValue(self)!;

            PSWSManSessionOption? extraOptions = (PSWSManSessionOption?)PSObject
                .AsPSObject(connectionInfo)
                .Properties[PSWSManSessionOption.PSWSMAN_SESSION_OPTION_PROP]
                ?.Value;

            Guid runspacePoolId = self.RunspacePoolInstanceId;

            ConnectionInfoProperty.SetValue(self, connectionInfo);
            self.Fragmentor.FragmentSize = WSManSessionOption.DefaultMaxEnvelopeSize;

            // The connection URI needs to be rewritten if this flag is set so that it uses the default WSMan port
            // rather than 80/443.
            if (connectionInfo.UseDefaultWSManPort)
            {
                UriBuilder uriBuilder = new(connectionInfo.ConnectionUri)
                {
                    Port = connectionInfo.ConnectionUri.Scheme == Uri.UriSchemeHttps ? 5986 : 5985,
                };
                connectionUri = uriBuilder.Uri;
            }

            tracer.WriteLine(
                "PSWSMan: WSManClientSessionTransportManager.Initialized - Creating PSRP Shim for {0} RPID {1}",
                connectionUri, runspacePoolId);
            WSManPSRPShim session = WSManPSRPShim.Create(
                runspacePoolId,
                connectionUri,
                connectionInfo,
                extraOptions,
                WSManSessionOption.DefaultMaxEnvelopeSize
            );
            lock (syncObject)
            {
                nint nextSessionId = WSManCompatState.StoreSession(session);
                WSManSessionHandleField.SetValue(self, nextSessionId);
            }
        }
        catch (Exception e)
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.Initialized - Error\n{0}", e.ToString());
            throw;
        }
    }

    private static void SendDataPatch(
        Action<WSManClientSessionTransportManager, byte[], DataPriorityType> orig,
        WSManClientSessionTransportManager self,
        byte[] data,
        DataPriorityType priorityType
    )
    {
        /*
            Called when data needs to be sent to the Runspace.

            https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L2486
        */
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.SendData - Called");

            nint wsManSessionHandle = (nint)WSManSessionHandleField.GetValue(self)!;
            if (wsManSessionHandle == IntPtr.Zero)
            {
                return;
            }

            WSManPSRPShim session = WSManCompatState.SessionInfo[wsManSessionHandle];

            tracer.WriteLine(
                "PSWSMan: WSManClientSessionTransportManager.SendData - Sending Shell Send for {0}",
                session.RunspacePoolId);
            try
            {
                session.SendAsync(priorityType == DataPriorityType.Default ? "stdin" : "pr",
                    data).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                tracer.WriteLine(
                    "PSWSMan: WSManClientSessionTransportManager.SendData - Send failed for {0}\n{1}",
                    session.RunspacePoolId, e);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.RunShellCommandEx);
                self.ProcessWSManTransportError(err);
                return;
            }

            // Will continue to send data if there is more available
            SendOneItemMeth.Invoke(self, Array.Empty<Type>());
        }
        catch (Exception e)
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.SendData - Error\n{0}", e.ToString());
            throw;
        }
    }

    private static void StartReceivingDataPatch(
        Action<WSManClientSessionTransportManager> orig,
        WSManClientSessionTransportManager self
    )
    {
        /*
            Explicitly called by pwsh once the SessionCapability message has been received and processed. At this point
            we need to check if there is more data to send to create the Runspace. It is imperative this is called
            after the first receive has a response to avoid a race condition on the WSMan server.
        */
        PSTraceSource tracer = (PSTraceSource)TracerField.GetValue(null)!;

        try
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.StartReceivingData - Called");
            SendOneItemMeth.Invoke(self, Array.Empty<Type>());
        }
        catch (Exception e)
        {
            tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.StartReceivingData - Error\n{0}",
                e.ToString());
            throw;
        }
    }

    #endregion

    public static Hook[] GenerateHooks()
    {
        return new[]
        {
            new Hook(
                _adjustForProtocolVariationsMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientSessionTransportManager),
                    nameof(WSManClientSessionTransportManager.AdjustForProtocolVariations),
                    new[] { typeof(Version) },
                    BindingFlags.Instance | BindingFlags.NonPublic
                ),
                AdjustForProtocolVariationsPatch
            ),
            new Hook(
                _closeAsyncMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientSessionTransportManager),
                    nameof(WSManClientSessionTransportManager.CloseAsync),
                    Array.Empty<Type>(),
                    // 7.2 has it as NonPublic, 7.3 made it Public
                    BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public
                ),
                CloseAsyncPatch
            ),
            new Hook(
                _closeSessionAndClearResourcesMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientSessionTransportManager),
                    "CloseSessionAndClearResources",
                    Array.Empty<Type>(),
                    BindingFlags.Instance | BindingFlags.NonPublic
                ),
                CloseSessionAndClearResourcesPatch
            ),
            new Hook(
                _createAsyncMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientSessionTransportManager),
                    nameof(WSManClientSessionTransportManager.CreateAsync),
                    Array.Empty<Type>(),
                    // 7.2 has it as NonPublic, 7.3 made it Public
                    BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public
                ),
                CreateAsyncPatch
            ),
            new Hook(
                _disposeMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientSessionTransportManager),
                    nameof(WSManClientSessionTransportManager.Dispose),
                    new[] { typeof(bool) },
                    BindingFlags.Instance | BindingFlags.NonPublic
                ),
                DisposePatch
            ),
            new Hook(
                _initializeMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientSessionTransportManager),
                    "Initialize",
                    new[] { typeof(Uri), typeof(WSManConnectionInfo) },
                    BindingFlags.Instance | BindingFlags.NonPublic

                ),
                InitializePatch
            ),
            new Hook(
                _sendDataMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientSessionTransportManager),
                    "SendData",
                    new[] { typeof(byte[]), typeof(DataPriorityType) },
                    BindingFlags.Instance | BindingFlags.NonPublic

                ),
                SendDataPatch
            ),
            new Hook(
                _startReceivingDataMeth ??= MonoModPatcher.GetMethod(
                    typeof(WSManClientSessionTransportManager),
                    nameof(WSManClientSessionTransportManager.StartReceivingData),
                    Array.Empty<Type>(),
                    BindingFlags.Instance | BindingFlags.NonPublic

                ),
                StartReceivingDataPatch
            )
        };
    }
}
