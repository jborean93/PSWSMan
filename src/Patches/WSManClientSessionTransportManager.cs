using System;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Management.Automation.Runspaces;
using System.Reflection;
using HarmonyLib;

namespace PSWSMan.Patches;

[HarmonyPatch(typeof(WSManClientSessionTransportManager))]
[HarmonyPatch("Initialize")]
internal static class Pwsh_WSManClientSessionTransportManagerInitialize
{
    static bool Prefix(WSManClientSessionTransportManager __instance, object ___syncObject,
        ref IntPtr ____wsManSessionHandle, Uri connectionUri, WSManConnectionInfo connectionInfo)
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

            https://github.com/PowerShell/PowerShell/blob/042765dd1c4d46a86a4545e7e0df0a7ee19f4dd6/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L1361-L1627
        */
        PSWSManSessionOption? extraOptions = (PSWSManSessionOption?)PSObject
            .AsPSObject(connectionInfo)
            .Properties[PSWSManSessionOption.PSWSMAN_SESSION_OPTION_PROP]
            ?.Value;

        Guid runspacePoolId = __instance.RunspacePoolInstanceId;

        __instance.GetType()
            .GetProperty("ConnectionInfo", BindingFlags.NonPublic | BindingFlags.Instance)
            ?.SetValue(__instance, connectionInfo);

        const int maxEnvelopeSize = 153600;
        __instance.Fragmentor.FragmentSize = maxEnvelopeSize;

        // The connection URI needs to be rewritten if this flag is set so that it uses the default WSMan port rather
        // than 80/443.
        if (connectionInfo.UseDefaultWSManPort)
        {
            UriBuilder uriBuilder = new(connectionInfo.ConnectionUri);
            uriBuilder.Port = connectionInfo.ConnectionUri.Scheme == Uri.UriSchemeHttps ? 5986 : 5985;
            connectionUri = uriBuilder.Uri;
        }

        WSManPSRPShim session = WSManPSRPShim.Create(runspacePoolId, connectionUri, connectionInfo, extraOptions,
            maxEnvelopeSize);
        lock (___syncObject)
        {
            ____wsManSessionHandle = WSManCompatState.StoreSession(session);
        }

        return false;
    }
}

[HarmonyPatch(typeof(WSManClientSessionTransportManager))]
[HarmonyPatch(nameof(WSManClientSessionTransportManager.CreateAsync))]
internal static class Pwsh_WSManClientSessionTransportManagerCreateAsync
{
    static bool Prefix(WSManClientSessionTransportManager __instance, ref IntPtr ____wsManSessionHandle,
        PrioritySendDataCollection ___dataToBeSent)
    {
        /*
            This method sends the WSMan Create message. In Pwsh it returns early and the native API invokes a callback
            function that handles the response. As this library has finer control the callback mess is avoided the
            response is also processed here.
        */
        WSManPSRPShim session = WSManCompatState.SessionInfo[____wsManSessionHandle];
        byte[] additionalData = ___dataToBeSent.ReadOrRegisterCallback(null, out var _);

        try
        {
            session.CreateShellAsync(additionalData ?? Array.Empty<byte>()).GetAwaiter().GetResult();
        }
        catch (Exception e)
        {
            TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                TransportMethodEnum.CreateShellEx);
            __instance.ProcessWSManTransportError(err);
        }

        // FUTURE: Add disconnect support
        __instance.GetType()
            .GetProperty("SupportsDisconnect", BindingFlags.NonPublic | BindingFlags.Instance)
            ?.SetValue(__instance, false);

        __instance.RaiseCreateCompleted(new CreateCompleteEventArgs(__instance.ConnectionInfo.Copy()));

        // __instance.StartReceivingData();
        // Start the receive thread that continuously polls the receive output
        session.StartReceiveTask(__instance);

        // __instance.SendOneItem();
        byte[]? data = ___dataToBeSent.ReadOrRegisterCallback(OnDataAvailable, out _);
        // Send if data is available

        return false;
    }

    static void OnDataAvailable(byte[] data, DataPriorityType priorityType)
    {
        // Send data
    }
}
