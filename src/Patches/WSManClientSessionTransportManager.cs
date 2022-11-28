using HarmonyLib;
using System;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Management.Automation.Runspaces;
using System.Reflection;

namespace PSWSMan.Patches;

[HarmonyPatch(typeof(WSManClientSessionTransportManager))]
[HarmonyPatch("Initialize")]
internal static class Pwsh_WSManClientSessionTransportManagerInitialize
{
    static bool Prefix(WSManClientSessionTransportManager __instance, object ___syncObject,
        ref IntPtr ____wsManSessionHandle, PSTraceSource ___tracer, Uri connectionUri,
        WSManConnectionInfo connectionInfo)
    {
        /*
            WSManClientSessionTransportManager.Initialize() is called by the constructor and for redirected requests
            and does the following:
            - Adds extra query params to the connection Uri based on a few different parameters
            - Sets up the authentication information
            - Sets up the proxy information
            - Creates a WSMan session handle
            - Sets the various connection options like timeouts and cert checks

            The patched code sets the same properties as Initialize and stores the mapping of the connection details
            into a global state for later referencing. Building the actual connection and setting the options is done
            later on when the connection is being created.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.Initialized - Called");
        try
        {
            PSWSManSessionOption? extraOptions = (PSWSManSessionOption?)PSObject
                .AsPSObject(connectionInfo)
                .Properties[PSWSManSessionOption.PSWSMAN_SESSION_OPTION_PROP]
                ?.Value;

            Guid runspacePoolId = __instance.RunspacePoolInstanceId;

            __instance.GetType()
                .GetProperty("ConnectionInfo", BindingFlags.NonPublic | BindingFlags.Instance)
                ?.SetValue(__instance, connectionInfo);
            __instance.Fragmentor.FragmentSize = WSManSessionOption.DefaultMaxEnvelopeSize;

            // The connection URI needs to be rewritten if this flag is set so that it uses the default WSMan port
            // rather than 80/443.
            if (connectionInfo.UseDefaultWSManPort)
            {
                UriBuilder uriBuilder = new(connectionInfo.ConnectionUri);
                uriBuilder.Port = connectionInfo.ConnectionUri.Scheme == Uri.UriSchemeHttps ? 5986 : 5985;
                connectionUri = uriBuilder.Uri;
            }

            ___tracer.WriteLine(
                "PSWSMan: WSManClientSessionTransportManager.Initialized - Creating PSRP Shim for {0} RPID {1}",
                connectionUri, runspacePoolId);
            WSManPSRPShim session = WSManPSRPShim.Create(runspacePoolId, connectionUri, connectionInfo, extraOptions,
                WSManSessionOption.DefaultMaxEnvelopeSize);
            lock (___syncObject)
            {
                ____wsManSessionHandle = WSManCompatState.StoreSession(session);
            }
        }
        catch (Exception e)
        {
            ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.Initialized - Error\n{0}", e.ToString());
            throw;
        }

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientSessionTransportManager))]
[HarmonyPatch(nameof(WSManClientSessionTransportManager.CreateAsync))]
internal static class Pwsh_WSManClientSessionTransportManagerCreateAsync
{
    static bool Prefix(WSManClientSessionTransportManager __instance, ref IntPtr ____wsManSessionHandle,
        ref IntPtr ____wsManShellOperationHandle, PrioritySendDataCollection ___dataToBeSent,
        PrioritySendDataCollection.OnDataAvailableCallback ____onDataAvailableToSendCallback, PSTraceSource ___tracer)
    {
        /*
            This method sends the WSMan Create message. In Pwsh it returns early and the native API invokes a callback
            function that handles the response. As this library has finer control the callback mess is avoided the
            response is also processed here.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.CreateAsync - Called");
        try
        {
            WSManPSRPShim session = WSManCompatState.SessionInfo[____wsManSessionHandle];
            byte[] additionalData = ___dataToBeSent.ReadOrRegisterCallback(null, out var _);

            ___tracer.WriteLine(
                "PSWSMan: WSManClientSessionTransportManager.CreateAsync - Sending Shell Create for {0}",
                session.RunspacePoolId);
            try
            {
                session.CreateShellAsync(additionalData ?? Array.Empty<byte>()).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                ___tracer.WriteLine(
                    "PSWSMan: WSManClientSessionTransportManager.CreateAsync - Shell Create failed for {0}\n{1}",
                    session.RunspacePoolId, e);

                WSManCompatState.SessionInfo.Remove(____wsManSessionHandle);
                ____wsManSessionHandle = IntPtr.Zero;

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.CreateShellEx);
                __instance.ProcessWSManTransportError(err);
                return false;
            }

            // Satifies some Debug.Assert statements in pwsh
            ____wsManShellOperationHandle = (IntPtr)1;

            // FUTURE: Add disconnect support
            __instance.GetType()
                .GetProperty("SupportsDisconnect", BindingFlags.NonPublic | BindingFlags.Instance)
                ?.SetValue(__instance, false);

            __instance.RaiseCreateCompleted(new CreateCompleteEventArgs(__instance.ConnectionInfo.Copy()));

            // Start the receive thread that continuously polls the receive output. The first message expected back
            // is the SessionCapability which will fire the AdjustForProtocolVariations and StartReceivingData methods
            // where the remaining Runspace creation messages (if any) are sent.
            session.StartReceiveTask(__instance, ___tracer);
        }
        catch (Exception e)
        {
            ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.CreateAsync - Error\n{0}", e.ToString());
            throw;
        }

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientSessionTransportManager))]
[HarmonyPatch(nameof(WSManClientSessionTransportManager.CloseAsync))]
internal static class Pwsh_WSManClientSessionTransportManagerCloseAsync
{
    static bool Prefix(WSManClientSessionTransportManager __instance, ref IntPtr ____wsManSessionHandle,
        PSTraceSource ___tracer)
    {
        /*
            Called when closing the Runspace, simply send the Delete operation and wait for the response.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.CloseAsync - Called");

        try
        {
            if (____wsManSessionHandle != IntPtr.Zero)
            {
                WSManPSRPShim session = WSManCompatState.SessionInfo[____wsManSessionHandle];

                ___tracer.WriteLine(
                    "PSWSMan: WSManClientSessionTransportManager.CloseAsync - Sending Shell Delete for {0}",
                    session.RunspacePoolId);
                try
                {
                    session.CloseShellAsync().GetAwaiter().GetResult();
                }
                catch (Exception e)
                {
                    ___tracer.WriteLine(
                        "PSWSMan: WSManClientSessionTransportManager.CloseAsync - Delete failed for {0}\n{1}",
                        session.RunspacePoolId, e);

                    WSManCompatState.SessionInfo.Remove(____wsManSessionHandle);
                    ____wsManSessionHandle = IntPtr.Zero;

                    TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                        TransportMethodEnum.RunShellCommandEx);
                    __instance.ProcessWSManTransportError(err);
                }
            }

            __instance.RaiseCloseCompleted();
        }
        catch (Exception e)
        {
            ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.CloseAsync - Error\n{0}", e.ToString());
            throw;
        }

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientSessionTransportManager))]
[HarmonyPatch(nameof(WSManClientSessionTransportManager.Dispose))]
internal static class Pwsh_WSManClientSessionTransportManagerDispose
{
    static bool Prefix(WSManClientSessionTransportManager __instance, ref IntPtr ____wsManSessionHandle,
        PSTraceSource ___tracer)
    {
        /*
            Called after the Runspace has been closed. Just need to remove the shim from the global state.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.Dispose - Called");

        try
        {
            if (____wsManSessionHandle != IntPtr.Zero)
            {
                WSManPSRPShim session = WSManCompatState.SessionInfo[____wsManSessionHandle];
                session.Dispose();

                WSManCompatState.SessionInfo.Remove(____wsManSessionHandle);
                ____wsManSessionHandle = IntPtr.Zero;
            }
        }
        catch (Exception e)
        {
            ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.Dispose - Error\n{0}", e.ToString());
            throw;
        }

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientSessionTransportManager))]
[HarmonyPatch("SendData")]
internal static class Pwsh_WSManClientSessionTransportManagerSendData
{
    static bool Prefix(WSManClientSessionTransportManager __instance, byte[] data, DataPriorityType priorityType,
        IntPtr ____wsManSessionHandle, PSTraceSource ___tracer)
    {
        /*
            Called when data needs to be sent to the Runspace.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.SendData - Called");

        try
        {
            if (____wsManSessionHandle == IntPtr.Zero)
            {
                return false;
            }

            WSManPSRPShim session = WSManCompatState.SessionInfo[____wsManSessionHandle];

            ___tracer.WriteLine(
                "PSWSMan: WSManClientSessionTransportManager.SendData - Sending Shell Send for {0}",
                session.RunspacePoolId);
            try
            {
                session.SendAsync(priorityType == DataPriorityType.Default ? "stdin" : "pr",
                    data).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                ___tracer.WriteLine(
                    "PSWSMan: WSManClientSessionTransportManager.SendData - Send failed for {0}\n{1}",
                    session.RunspacePoolId, e);

                TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                    TransportMethodEnum.RunShellCommandEx);
                __instance.ProcessWSManTransportError(err);
                return false;
            }

            // Will continue to send data if there is more available
            typeof(WSManClientSessionTransportManager).GetMethod(
                "SendOneItem",
                BindingFlags.NonPublic | BindingFlags.Instance)
                ?.Invoke(__instance, Array.Empty<Type>());
        }
        catch (Exception e)
        {
            ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.SendData - Error\n{0}", e.ToString());
            throw;
        }

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientSessionTransportManager))]
[HarmonyPatch(nameof(WSManClientSessionTransportManager.AdjustForProtocolVariations))]
internal static class Pwsh_WSManClientSessionTransportManagerAdjustForProtocolVariations
{
    static bool Prefix(WSManClientSessionTransportManager __instance, Version serverProtocolVersion,
        IntPtr ____wsManSessionHandle, PSTraceSource ___tracer)
    {
        /*
            Called when PowerShell receives the server's session capability message. It uses this message to adjust
            the MaxEnvelopeSize if it's talking to a newer host (Win 8/Server 2012+) so it can send larger fragments.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.AdjustForProtocolVariations - Called with {0}",
            serverProtocolVersion);

        try
        {
            if (____wsManSessionHandle == IntPtr.Zero)
            {
                return false;
            }

            WSManPSRPShim session = WSManCompatState.SessionInfo[____wsManSessionHandle];
            if (serverProtocolVersion > new Version("2.1") && session.GetMaxEnvelopeSize() == WSManSessionOption.DefaultMaxEnvelopeSize)
            {
                ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.AdjustForProtocolVariations - Updating max fragmenent size to 500KiB for {0}",
                    session.RunspacePoolId);

                int newEnvelopeSize = 500 << 10;
                session.SetMaxEnvelopeSize(newEnvelopeSize);

                // The fragmenter size needs to fit a base64 encoded value of those bytes into the WSMan envelope. Use
                // 2048 as a high level envelope size and (_ / 4) * 3 to get the max length that can fit in a base64
                // encoded string in the envelope.
                __instance.Fragmentor.FragmentSize = ((newEnvelopeSize - 2048) / 4) * 3;
            }
        }
        catch (Exception e)
        {
            ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.AdjustForProtocolVariations - Error\n{0}",
                e.ToString());
            throw;
        }

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientSessionTransportManager))]
[HarmonyPatch(nameof(WSManClientSessionTransportManager.StartReceivingData))]
internal static class Pwsh_WSManClientSessionTransportManagerStartReceivingData
{
    static bool Prefix(WSManClientSessionTransportManager __instance, PSTraceSource ___tracer)
    {
        /*
            Explicitly called by pwsh once the SessionCapability message has been received and processed. At this point
            we need to check if there is more data to send to create the Runspace. It is imperative this is called
            after the first receive has a response to avoid a race condition on the WSMan server.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.StartReceivingData - Called");

        try
        {
            typeof(WSManClientSessionTransportManager).GetMethod(
                    "SendOneItem",
                    BindingFlags.NonPublic | BindingFlags.Instance)
                    ?.Invoke(__instance, Array.Empty<Type>());
        }
        catch (Exception e)
        {
            ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.StartReceivingData - Error\n{0}",
                e.ToString());
            throw;
        }
        return false;
    }
}

[HarmonyPatch(typeof(WSManClientSessionTransportManager))]
[HarmonyPatch("CloseSessionAndClearResources")]
internal static class Pwsh_WSManClientSessionTransportManagerCloseSessionAndClearResources
{
    static bool Prefix(WSManClientSessionTransportManager __instance, PSTraceSource ___tracer)
    {
        /*
            Called in a few places that still need to work but we need to close the existing session we managed
            ourselves instead.
        */
        ___tracer.WriteLine("PSWSMan: WSManClientSessionTransportManager.CloseSessionAndClearResources - Called");
        return false;
    }
}
