using PSWSMan.Authentication;
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PSWSMan.Module;

internal class WSManPSRPShim : IDisposable
{
    private readonly WSManSession _session;
    private readonly WSManSessionOption _options;
    private readonly WinRSClient _winrs;
    private readonly Guid _runspacePoolId;
    private readonly bool _noMachineProfile;
    private readonly string _shellUri;

    private List<Task> _receiveThreads = new();

    public Guid RunspacePoolId => _runspacePoolId;

    private WSManPSRPShim(WSManSessionOption options, Guid runspacePoolId, bool noMachineProfile,
        string shellId, WinRSClient? client = null)
    {
        _session = CreateSession(options);
        _options = options;
        _winrs = client ?? new(_session.Client);
        _runspacePoolId = runspacePoolId;
        _noMachineProfile = noMachineProfile;
        _shellUri = shellId;
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
            };

            if (extraConnInfo?.TlsOption is null)
            {
                if (connInfo.SkipCACheck || connInfo.SkipCNCheck)
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

                if (!string.IsNullOrWhiteSpace(connInfo.CertificateThumbprint))
                {
                    bool found = false;
                    foreach (StoreLocation location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
                    {
                        using X509Store store = new(StoreName.My, StoreLocation.CurrentUser, OpenFlags.ReadOnly);
                        foreach (X509Certificate2 cert in store.Certificates)
                        {
                            if (string.Equals(cert.Thumbprint, connInfo.CertificateThumbprint,
                                StringComparison.InvariantCultureIgnoreCase))
                            {
                                tlsOptions.ClientCertificates = new(new[] { cert });
                                found = true;
                                break;
                            }
                        }
                    }

                    if (!found)
                    {
                        string errMsg = $"WinRM failed to find certificate with the thumbprint requested '{connInfo.CertificateThumbprint}'";
                        throw new AuthenticationException(errMsg);
                    }
                }
                else if (extraConnInfo?.ClientCertificate != null)
                {
                    tlsOptions.ClientCertificates = new(new[] { extraConnInfo.ClientCertificate });
                }
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

        NegotiateOptions negoOptions = new()
        {
            Flags = NegotiateRequestFlags.Default,
            SPNHostName = extraConnInfo?.SPNHostName ?? connectionUri.DnsSafeHost,
            SPNService = extraConnInfo?.SPNService,
        };
        if (extraConnInfo?.RequestKerberosDelegate == true)
        {
            negoOptions.Flags |= NegotiateRequestFlags.Delegate;
        }

        WSManCredential credential = GenerateWSManCredential(
            authMethod,
            extraConnInfo?.AuthProvider ?? AuthenticationProvider.Default,
            connInfo.Credential?.UserName,
            connInfo.Credential?.GetNetworkCredential()?.Password,
            tlsOptions,
            extraConnInfo?.CredSSPTlsOption,
            extraConnInfo?.CredSSPAuthMethod ?? AuthenticationMethod.Default
        );
        WSManSessionOption options = new(connectionUri, connInfo.OpenTimeout, connInfo.OperationTimeout,
            connInfo.Culture.Name, credential)
        {
            MaxEnvelopeSize = maxEnvelopeSize,
            TlsOptions = tlsOptions,
            NoEncryption = connInfo.NoEncryption,
            NegotiateOptions = negoOptions,
        };
        if (connInfo.UICulture is not null)
        {
            options.DataLocale = connInfo.UICulture.Name;
        }

        return new(options, runspacePoolId, connInfo.NoMachineProfile, connInfo.ShellUri);
    }

    public async Task CreateShellAsync(byte[] psrpFragment)
    {
        string psrpPayload = Convert.ToBase64String(psrpFragment);
        XElement extraContent = new(WSManNamespace.pwsh + "creationXml", psrpPayload);
        OptionSet shellOptions = new();
        shellOptions.Add("protocolversion", "2.3");

        if (_noMachineProfile)
        {
            shellOptions.Add("WINRS_NOPROFILE", "1", new() { { "mustComply", true } });
        }

        string payload = _winrs.Create(
            _shellUri,
            inputStreams: "stdin pr",
            outputStreams: "stdout",
            shellId: _runspacePoolId,
            extra: extraContent,
            options: shellOptions);

        WSManCreateResponse resp = await _session.PostRequest<WSManCreateResponse>(payload);
        _winrs.ProcessCreateResponse(resp);
    }

    public async Task CloseShellAsync()
    {
        string payload = _winrs.Delete();
        await _session.PostRequest<WSManDeleteResponse>(payload);
    }

    public async Task CreateCommandAsync(Guid commandId, byte[] psrpFragment)
    {
        string psrpPayload = Convert.ToBase64String(psrpFragment);

        string payload = _winrs.Command("", new[] { psrpPayload }, commandId: commandId);
        await _session.PostRequest<WSManCommandResponse>(payload);
    }

    public async Task CloseCommandAsync(Guid commandId)
    {
        string payload = _winrs.Signal(SignalCode.Terminate, commandId: commandId);
        await _session.PostRequest<WSManSignalResponse>(payload);
    }

    public async Task<WSManReceiveResponse> Receive(string stream, Guid? commandId = null)
    {
        string payload = _winrs.Receive(stream, commandId: commandId);
        return await _session.PostRequest<WSManReceiveResponse>(payload);
    }

    public async Task SendAsync(string stream, byte[] data, Guid? commandId = null)
    {
        string payload = _winrs.Send(stream, data, commandId: commandId);
        await _session.PostRequest<WSManSendResponse>(payload);
    }

    public async Task StopCommandAsync(Guid commandId)
    {
        string payload = _winrs.Signal(SignalCode.PSCtrlC, commandId: commandId);
        await _session.PostRequest<WSManSignalResponse>(payload);
    }

    public void StartReceiveTask(BaseClientTransportManager tm, PSTraceSource tracer, Guid? commandId = null)
    {
        _receiveThreads.Add(Task.Run(() =>
        {
            using WSManPSRPShim client = new(_options, _runspacePoolId, _noMachineProfile, _shellUri, client: _winrs);

            while (true)
            {
                try
                {
                    tracer.WriteLine("PSWSMan Receive Task sending Receive Request. CmdId: '{0}'", commandId);
                    WSManReceiveResponse response = client.Receive("stdout", commandId: commandId)
                        .GetAwaiter().GetResult();
                    tracer.WriteLine("PSWSMan Received Response. CmdId: '{0}'", commandId);

                    foreach (KeyValuePair<string, byte[][]> entry in response.Streams)
                    {
                        foreach (byte[] stream in entry.Value)
                        {
                            tm.ProcessRawData(stream, entry.Key);
                        }
                    }

                    if (response.State == CommandState.Done)
                    {
                        tracer.WriteLine("PSWSMan Receive Task Complete. CmdId: '{0}'", commandId);
                        break;
                    }
                }
                catch (WSManFault e) when (e.WSManFaultCode == unchecked((int)0x80338029))
                {
                    // ERROR_WSMAN_OPERATION_TIMEDOUT - try it again
                    tracer.WriteLine("PSWSMan Received Operation Timeout and will try again. CmdId: '{0}'\n{1}",
                        commandId, e);
                    continue;
                }
                catch (WSManFault e) when (
                    e.WSManFaultCode == 0x000003E3 || // ERROR_OPERATION_ABORTED - 0x000003E3
                    e.WSManFaultCode == 0x000004C7 || // ERROR_CANCELLED - 0x000004C7
                    e.WSManFaultCode == unchecked((int)0x8033805B) || // ERROR_WSMAN_UNEXPECTED_SELECTORS - 0x8033805B
                    e.WSManFaultCode == unchecked((int)0x803381C4) || // ERROR_WINRS_SHELL_DISCONNECTED - 0x803381C4
                    e.WSManFaultCode == unchecked((int)0x803381DE) // ERROR_WSMAN_SERVICE_STREAM_DISCONNECTED - 0x803381DE
                )
                {
                    tracer.WriteLine("PSWSMan Received Task Shutdown WSMan Fault Received CmdId: '{0}'\n{1}",
                        commandId, e);
                    break;
                }
                catch (Exception e)
                {
                    tracer.WriteLine("PSWSMan Receive Task Failure CmdId: '{0}'\n{1}", commandId, e);

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

    internal int GetMaxEnvelopeSize() => _session.Client.MaxEnvelopeSize;

    internal void SetMaxEnvelopeSize(int size)
    {
        // Updates options as well so that new sessions use the new value
        _session.Client.MaxEnvelopeSize = size;
        _options.MaxEnvelopeSize = size;
    }

    private WSManSession CreateSession(WSManSessionOption option)
    {
        bool encrypt = !(option.ConnectionUri.Scheme == Uri.UriSchemeHttps || option.NoEncryption);

        // Until net7 is the minimum we need to rewrite the URI so that the scheme is always http. This allows the
        // connection handler to wrap it's own TLS stream used to get the channel binding token information for
        // authentication. When setting net7 as the minimum this can be removed as it adds an instance check for
        // SslStream and doesn't try and wrap it again.
        // https://github.com/dotnet/runtime/pull/63851
        UriBuilder uriBuilder = new(option.ConnectionUri);
        uriBuilder.Scheme = "http";

        TimeSpan? connectTimeout = null;
        if (option.OpenTimeout != 0)
        {
            connectTimeout = new(((long)option.OpenTimeout) * TimeSpan.TicksPerMillisecond);
        }

        WSManConnection connection = new(uriBuilder.Uri, option.Credential, option.NegotiateOptions ?? new(),
            option.TlsOptions, encrypt, connectTimeout);
        WSManClient client = new(option.ConnectionUri, option.MaxEnvelopeSize, option.OperationTimeout, option.Locale,
            dataLocale: option.DataLocale);

        return new(connection, client);
    }

    private static WSManCredential GenerateWSManCredential(AuthenticationMethod authMethod,
        AuthenticationProvider authProvider, string? userName, string? password,
        SslClientAuthenticationOptions? tlsOptions, SslClientAuthenticationOptions? credSSPTlsOptions,
        AuthenticationMethod credSSPAuthMethod)
    {
        if (authMethod == AuthenticationMethod.Default)
        {
            if ((tlsOptions?.ClientCertificates?.Count ?? 0) > 0)
            {
                return new CertificateCredential();
            }

            authMethod = AuthenticationMethod.Negotiate;
        }

        if (authMethod == AuthenticationMethod.Basic)
        {
            return new BasicCredential(userName, password);
        }

        if (authMethod == AuthenticationMethod.CredSSP)
        {
            if (userName is null || password is null)
            {
                throw new ArgumentException("Username and password must be set for CredSSP authentication");
            }

            WSManCredential negoCredential = GetNegotiateCredential(credSSPAuthMethod, authProvider, userName,
                password);

            string domainName = "";
            string username = userName;
            if (username.Contains('\\'))
            {
                string[] stringSplit = username.Split('\\', 2);
                domainName = stringSplit[0];
                username = stringSplit[1];
            }
            TSPasswordCreds credSSPCreds = new(domainName, username, password);
            return new CredSSPCredential(credSSPCreds, negoCredential, credSSPTlsOptions);
        }
        else
        {
            return GetNegotiateCredential(authMethod, authProvider, userName, password);
        }
    }

    private static WSManCredential GetNegotiateCredential(AuthenticationMethod method, AuthenticationProvider provider,
        string? userName, string? password)
    {
        NegotiateMethod negoMethod = method switch
        {
            AuthenticationMethod.NTLM => NegotiateMethod.NTLM,
            AuthenticationMethod.Kerberos => NegotiateMethod.Kerberos,
            _ => NegotiateMethod.Negotiate,
        };

        bool isDefault = false;
        if (provider == AuthenticationProvider.Default)
        {
            isDefault = true;
            provider = GlobalState.DefaultProvider;
        }

        if (provider == AuthenticationProvider.System)
        {
            if (GlobalState.Gssapi != null)
            {
                return new GssapiCredential(GlobalState.Gssapi, userName, password, negoMethod);
            }
            else if (GlobalState.WinSspi != null)
            {
                return new SspiCredential(GlobalState.WinSspi, userName, password, negoMethod);
            }
            else if (!isDefault)
            {
                string msg = "Failed to find System SSPI/GSSAPI library, can only use Default or Devolutions for Negotiate auth.";
                throw new ArgumentException(msg);
            }
        }

        return new SspiCredential(GlobalState.DevolutionsSspi, userName, password, negoMethod);
    }

    public void Dispose()
    {
        _session?.Dispose();
        GC.SuppressFinalize(this);
    }
    ~WSManPSRPShim() { Dispose(); }
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
