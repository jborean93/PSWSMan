using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using HarmonyLib;

namespace PSWSMan;

[HarmonyPatch]
class Pwsh_WSManApiDataCommon
{
    static MethodBase TargetMethod()
    {
        const string className = "System.Management.Automation.Remoting.Client.WSManClientSessionTransportManager+WSManAPIDataCommon";
        return typeof(PSObject)
            .Assembly
            .GetType(className)
            ?.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, Array.Empty<Type>())
            ?? throw new Exception($"Failed to find constructor for '{className}'");
    }

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

[HarmonyPatch]
class Pwsh_WSManClientSessionTransportManager
{
    static IEnumerable<MethodBase> TargetMethods()
    {
        const string className = "System.Management.Automation.Remoting.Client.WSManClientSessionTransportManager";
        BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Instance;

        Type? classType = typeof(PSObject).Assembly.GetType(className);

        yield return classType?.GetMethod("Initialize", flags)
            ?? throw new Exception("Failed to find Initialize() for '{className}'");

        // Pwsh 7.3 made this method public
        yield return classType?.GetMethod("CreateAsync", flags | BindingFlags.Public)
            ?? throw new Exception("Failed to find CreateAsync() for '{className}'");
    }

    static bool Prefix(object __instance, MethodBase __originalMethod, object[] __args,
        ref IntPtr ____wsManSessionHandle)
    {
        return __originalMethod.Name switch
        {
            "Initialize" => PrefixInitialize(__instance, __args, ref ____wsManSessionHandle),
            "CreateAsync" => PrefixCreateAsync(__instance),
            _ => true,
        };
    }

    static bool PrefixInitialize(object _this, object[] args, ref IntPtr wsmanSessionHandle)
    {
        /*
            WSManClientSessionTransportManager.Initialize() is called by the constructor and for redirected requests
            and does the following:
            - Adds extra query params to the connection Uri based on a few different parameters
            - Sets up the authentication information
            - Sets up the proxy information
            - Creates a WSMan session handle
            - Sets the various connection options like timeoutes and cert checks

            The patched code sets the same properties as Initialize and stores the mapping of the connection details
            into a global state for later referencing. Building the actual connection and setting the options is done
            later on when the connection is being created.

            https://github.com/PowerShell/PowerShell/blob/042765dd1c4d46a86a4545e7e0df0a7ee19f4dd6/src/System.Management.Automation/engine/remoting/fanin/WSManTransportManager.cs#L1361-L1627
        */
        Uri connectionUri = (Uri)args[0];
        WSManConnectionInfo connectionInfo = (WSManConnectionInfo)args[1];
        PSWSManSessionOption? extraOptions = (PSWSManSessionOption?)PSObject
            .AsPSObject(connectionInfo)
            .Properties[PSWSManSessionOption.PSWSMAN_SESSION_OPTION_PROP]
            ?.Value;

        // TODO: Look at building out WSManSession object here here
        /*
        WSManSessionFactory.Create(
            Uri uri,
            bool isTls,
            string resourceUri,
            AuthenticationMethod authMethod,
            PSCredential? credential,
            WinRSSessionOption sessionOption)
        */

        _this.GetType()
            .GetProperty("ConnectionInfo", BindingFlags.NonPublic | BindingFlags.Instance)
            ?.SetValue(_this, connectionInfo);

        // Set Fragmentor.FragmentSize = 153600; // 150KiB

        Random random = new();
        while (wsmanSessionHandle == IntPtr.Zero)
        {
            wsmanSessionHandle = new(random.NextInt64());
        }
        WSManCompatState.SessionInfo[wsmanSessionHandle] = (connectionUri, connectionInfo);

        return false;
    }

    static bool PrefixCreateAsync(object _this)
    {
        /*
            TODO: This needs to send the WSMan Create request and handle the response + maybe set up the receiving
            threads.
        */
        return true;
    }
}

[HarmonyPatch]
class Pwsh_WSManConnectionInfo
{
    [HarmonyPatch(typeof(WSManConnectionInfo), "SetSessionOptions")]
    static void Postfix(object __instance, object[] __args)
    {
        /*
            Ensures the extra PSWSMan session options that might be present on the connection object are also tranfered
            to the WSManConnectionInfo instance
        */
        CopyPSProperty(__args[0], __instance, PSWSManSessionOption.PSWSMAN_SESSION_OPTION_PROP);
    }

    [HarmonyPatch(typeof(WSManConnectionInfo), "Copy")]
    static void Postfix(object __instance, ref WSManConnectionInfo __result)
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

internal static class WSManCompatState
{
    public static Dictionary<IntPtr, (Uri, WSManConnectionInfo)> SessionInfo = new();
}


public class PSWSManSessionOption
{
    public const string PSWSMAN_SESSION_OPTION_PROP = "_PSWSManSessionOption";

    public AuthenticationMethod AuthMethod { get; set; } = AuthenticationMethod.Default;
    public string? SPNService { get; set; }
    public string? SPNHostName { get; set; }
    public bool RequestKerberosDelegate { get; set; }
    public SslClientAuthenticationOptions? TlsOption { get; set; }
    public AuthenticationMethod CredSSPAuthMethod { get; set; } = AuthenticationMethod.Default;
    public SslClientAuthenticationOptions? CredSSPTlsOption { get; set; }
}
