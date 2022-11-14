using System;
using System.Collections.Generic;
using System.Management.Automation.Runspaces;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PSWSMan;

internal class WSManPSRPShim
{
    private readonly Guid _runspacePoolId;
    private readonly WSManSession _session;
    private readonly WSManConnectionInfo _connInfo;
    private List<Task> _receiveThreads = new();

    private WSManPSRPShim(Guid runspacePoolId, WSManSession session, WSManConnectionInfo connInfo)
    {
        _runspacePoolId = runspacePoolId;
        _session = session;
        _connInfo = connInfo;
    }

    public static WSManPSRPShim Create(
        Guid runspacePoolId,
        Uri connectionUri,
        WSManConnectionInfo connInfo,
        PSWSManSessionOption? extraConnInfo,
        int maxEnvelopeSize)
    {
        SslClientAuthenticationOptions? tlsOptions = null;
        if (connectionUri.Scheme == Uri.UriSchemeHttps)
        {
            tlsOptions = extraConnInfo?.TlsOption ?? new()
            {
                TargetHost = connectionUri.DnsSafeHost,
                CertificateRevocationCheckMode = connInfo.SkipRevocationCheck
                    ? X509RevocationMode.NoCheck : X509RevocationMode.Offline,
            };

            if (extraConnInfo?.TlsOption is null && (connInfo.SkipCACheck || connInfo.SkipCNCheck))
            {
                tlsOptions.RemoteCertificateValidationCallback = ((_1, _2, _3, sslPolicyErrors) =>
                {
                    if (connInfo.SkipCACheck)
                    {
                        sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateChainErrors;
                    }
                    if (connInfo.SkipCNCheck)
                    {
                        sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateNameMismatch;
                    }

                    return sslPolicyErrors == SslPolicyErrors.None;
                });
            }
        }

        // Use the extra options auth method if set, otherwise map the builtin methods to our known enum.
        AuthenticationMethod authMethod = extraConnInfo?.AuthMethod ?? AuthenticationMethod.Default;
        if (authMethod == AuthenticationMethod.Default)
        {
            authMethod = connInfo.AuthenticationMechanism switch
            {
                AuthenticationMechanism.Basic => AuthenticationMethod.Basic,
                AuthenticationMechanism.Credssp => AuthenticationMethod.CredSSP,
                AuthenticationMechanism.Kerberos => AuthenticationMethod.Kerberos,
                AuthenticationMechanism.Negotiate => AuthenticationMethod.Negotiate,
                AuthenticationMechanism.NegotiateWithImplicitCredential => AuthenticationMethod.Negotiate,
                _ => AuthenticationMethod.Default,
            };
        }

        WSManSessionOption options = new(connectionUri, connInfo.OperationTimeout,
            connInfo.Culture.Name)
        {
            MaxEnvelopeSize = maxEnvelopeSize,
            TlsOptions = tlsOptions,
            AuthMethod = authMethod,
            UserName = connInfo.Credential?.UserName,
            Password = connInfo.Credential?.GetNetworkCredential()?.Password,
            NoEncryption = connInfo.NoEncryption,
            SPNService = extraConnInfo?.SPNService,
            SPNHostName = extraConnInfo?.SPNHostName,
            RequestKerberosDelegate = extraConnInfo?.RequestKerberosDelegate ?? false,
            CredSSPTlsOptions = extraConnInfo?.CredSSPTlsOption,
            CredSSPAuthMethod = extraConnInfo?.CredSSPAuthMethod ?? AuthenticationMethod.Negotiate,
            // FIXME: ClientCertificate
        };
        if (connInfo.UICulture is not null)
        {
            options.DataLocale = connInfo.UICulture.Name;
        }

        return new(runspacePoolId, options.CreateSession(), connInfo);
    }

    public async Task CreateShellAsync(byte[] psrpFragment)
    {
        string psrpPayload = Convert.ToBase64String(psrpFragment);
        XElement extraContent = new(WSManNamespace.pwsh + "creationXml", psrpPayload);
        OptionSet shellOptions = new();
        shellOptions.Add("protocolversion", "2.3");

        if (_connInfo.NoMachineProfile)
        {
            shellOptions.Add("WINRS_NOPROFILE", "1", new() { { "mustComply", true } });
        }

        string payload = _session.WinRS.Create(
            _connInfo.ShellUri,
            inputStreams: "stdin pr",
            outputStreams: "stdout",
            shellId: _runspacePoolId,
            extra: extraContent,
            options: shellOptions);

        await _session.PostRequest<WSManCreateResponse>(payload);
    }

    public async Task CloseShellAsync()
    {
        string payload = _session.WinRS.Delete();
        await _session.PostRequest<WSManDeleteResponse>(payload);
    }

    public async Task CreateCommandAsync(Guid commandId, byte[] psrpFragment)
    {
        string psrpPayload = Convert.ToBase64String(psrpFragment);

        string payload = _session.WinRS.Command("", new[] { psrpPayload }, commandId: commandId);
        await _session.PostRequest<WSManCommandResponse>(payload);
    }

    public async Task CloseCommandAsync(Guid commandId)
    {
        string payload = _session.WinRS.Signal(SignalCode.Terminate, commandId: commandId);
        await _session.PostRequest<WSManSignalResponse>(payload);
    }

    public void StartReceiveTask(BaseClientTransportManager tm, Guid? commandId = null)
    {
        _receiveThreads.Add(Task.Run(() =>
        {
            using WSManSession session = _session.Copy();
            while (true)
            {
                try
                {
                    string payload = session.WinRS.Receive("stdout", commandId: commandId);
                    WSManReceiveResponse response = session.PostRequest<WSManReceiveResponse>(payload)
                        .GetAwaiter().GetResult();

                    foreach (KeyValuePair<string, byte[][]> entry in response.Streams)
                    {
                        foreach (byte[] stream in entry.Value)
                        {
                            // Console.WriteLine($"Received CmdId: '{commandId}' - {entry.Key} - {Convert.ToBase64String(stream)}");
                            tm.ProcessRawData(stream, entry.Key);
                        }
                    }

                    if (response.State == CommandState.Done)
                    {
                        // Console.WriteLine($"Received CmdId '{commandId}' done");
                        break;
                    }
                }
                catch (WSManFault e) when (e.WSManFaultCode == 0x80338029)
                {
                    // ERROR_WSMAN_OPERATION_TIMEDOUT - try it again
                    continue;
                }
                catch (WSManFault e) when (
                    e.WSManFaultCode == 0x000003E3 ||
                    e.WSManFaultCode == 0x000004C7 ||
                    e.WSManFaultCode == 0x8033805B ||
                    e.WSManFaultCode == 0x803381DE ||
                    e.WSManFaultCode == 0x803381C4
                )
                {
                    // ERROR_OPERATION_ABORTED - 0x000003E3 - The shell or cmd has been closed
                    // ERROR_CANCELLED - 0x000004C7
                    // ERROR_WSMAN_UNEXPECTED_SELECTORS - 0x8033805B
                    // ERROR_WSMAN_SERVICE_STREAM_DISCONNECTED - 0x803381DE
                    // ERROR_WINRS_SHELL_DISCONNECTED - 0x803381C4
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Receive Task failure: {e.Message}\n{e}");
                    TransportErrorOccuredEventArgs err = new(new PSRemotingTransportException(e.Message, e),
                        TransportMethodEnum.CreateShellEx);
                    if (tm is WSManClientSessionTransportManager clientTM)
                    {
                        clientTM.ProcessWSManTransportError(err);
                    }
                    if (tm is WSManClientCommandTransportManager cmdTm)
                    {
                        cmdTm.ProcessWSManTransportError(err);
                    }
                    break;
                }
            }
        }));
    }
}

internal static class WSManCompatState
{
    internal static Int64 _nextSessionId = 1;

    public static Dictionary<IntPtr, WSManPSRPShim> SessionInfo = new();

    public static IntPtr StoreSession(WSManPSRPShim session)
    {
        IntPtr sessionId = new(_nextSessionId++);
        SessionInfo.Add(sessionId, session);
        return sessionId;
    }
}

/// <summary>Used as a way to extend New-PSSessionOption by adding in extra options available in this lib.</summary>
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

    // FIXME: Add X509Certificate property for cert auth
}
