using PSWSMan.Authentication;
using PSWSMan.Authentication.Native;
using PSWSMan.Connection;
using PSWSMan.Lib;
using System;
using System.Collections.Concurrent;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Management.Automation.Runspaces;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Xml.Linq;

namespace PSWSMan;

/// <summary>Bridges one PowerShell runspace pool to a WinRS shell over the connection pool.</summary>
/// <remarks>
/// Every method is synchronous and blocks the calling transport manager thread until the server answers, which is
/// what the patched transport manager methods expect. Receive pumps deliver data straight into the transport
/// manager on their own threads.
/// </remarks>
internal sealed class WSManPSRPSession : IDisposable
{
    internal const int DefaultMaxEnvelopeSize = 153600;

    // Extra time on top of the server side operation timeout before a request is considered lost.
    private static readonly TimeSpan s_requestTimeoutGrace = TimeSpan.FromSeconds(30);

    private readonly WSManConnectionPool _pool;
    private readonly WSManClient _client;
    private readonly WinRSShell _shell;
    private readonly bool _noMachineProfile;

    public Guid RunspacePoolId { get; }

    public int MaxEnvelopeSize => _client.MaxEnvelopeSize;

    /// <summary>Whether the shell has been closed or aborted locally.</summary>
    public bool IsClosed => _shell.IsClosed;

    private WSManPSRPSession(
        WSManConnectionPool pool,
        WSManClient client,
        Guid runspacePoolId,
        string shellUri,
        bool noMachineProfile,
        PSTraceSource tracer)
    {
        _pool = pool;
        _client = client;
        _noMachineProfile = noMachineProfile;
        RunspacePoolId = runspacePoolId;
        _shell = new WinRSShell(pool, client, shellUri, tracer.WriteLine);
    }

    public static WSManPSRPSession Create(
        Guid runspacePoolId,
        Uri connectionUri,
        WSManConnectionInfo connInfo,
        PSWSManSessionOption? extraConnInfo,
        int maxEnvelopeSize,
        PSTraceSource tracer)
    {
        SslClientAuthenticationOptions? tlsOptions = null;
        if (connectionUri.Scheme == Uri.UriSchemeHttps)
        {
            tlsOptions = extraConnInfo?.TlsOption ?? BuildTlsOptions(connectionUri, connInfo, extraConnInfo);
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
            extraConnInfo?.CredSSPAuthMethod ?? AuthenticationMethod.Default,
            negoOptions
        );

        // The PowerShell timeouts are in milliseconds, 0 means the default.
        TimeSpan connectTimeout = connInfo.OpenTimeout > 0
            ? TimeSpan.FromMilliseconds(connInfo.OpenTimeout)
            : TimeSpan.FromSeconds(10);
        TimeSpan operationTimeout = connInfo.OperationTimeout > 0
            ? TimeSpan.FromMilliseconds(connInfo.OperationTimeout)
            : TimeSpan.FromSeconds(180);

        bool encrypt = !(connectionUri.Scheme == Uri.UriSchemeHttps || connInfo.NoEncryption);
        WSManConnectionOptions options = new(connectionUri, credential)
        {
            TlsOptions = tlsOptions,
            Encrypt = encrypt,
            ConnectTimeout = connectTimeout,
            RequestTimeout = operationTimeout + s_requestTimeoutGrace,
        };

        WSManConnectionPool pool = new(options);
        WSManClient client = new(
            connectionUri,
            maxEnvelopeSize,
            operationTimeout,
            connInfo.Culture.Name,
            dataLocale: connInfo.UICulture?.Name);

        return new(pool, client, runspacePoolId, connInfo.ShellUri, connInfo.NoMachineProfile, tracer);
    }

    public void SetMaxEnvelopeSize(int size) => _client.UpdateMaxEnvelopeSize(size);

    public void CreateShell(byte[] psrpFragment, CancellationToken cancellationToken = default)
    {
        string psrpPayload = Convert.ToBase64String(psrpFragment);
        XElement extraContent = new(WSManNamespace.pwsh + "creationXml", psrpPayload);
        OptionSet shellOptions = new();
        shellOptions.Add("protocolversion", "2.3", new() { { "MustComply", "true" } });

        if (_noMachineProfile)
        {
            shellOptions.Add("WINRS_NOPROFILE", "1", new() { { "MustComply", "true" } });
        }

        _shell.Open(
            inputStreams: "stdin pr",
            outputStreams: "stdout",
            shellId: RunspacePoolId,
            extra: extraContent,
            options: shellOptions,
            cancellationToken: cancellationToken);
    }

    public void CloseShell(CancellationToken cancellationToken = default) => _shell.Close(cancellationToken);

    public void CreateCommand(Guid commandId, byte[] psrpFragment, CancellationToken cancellationToken = default)
    {
        string psrpPayload = Convert.ToBase64String(psrpFragment);
        _shell.RunCommand("", new[] { psrpPayload }, commandId: commandId, cancellationToken: cancellationToken);
    }

    public void CloseCommand(Guid commandId, CancellationToken cancellationToken = default)
        => _shell.Signal(SignalCode.Terminate, commandId, cancellationToken);

    public void StopCommand(Guid commandId, CancellationToken cancellationToken = default)
        => _shell.Signal(SignalCode.PSCtrlC, commandId, cancellationToken);

    public void Send(string stream, byte[] data, Guid? commandId = null, CancellationToken cancellationToken = default)
        => _shell.Send(stream, data, commandId, cancellationToken: cancellationToken);

    /// <summary>Starts pumping stdout for the shell or a command into the transport manager.</summary>
    public WinRSReceivePump StartReceive(BaseClientTransportManager tm, Guid? commandId = null)
        => _shell.StartReceive(new TransportManagerSink(tm, _shell, commandId), "stdout", commandId);

    public void Dispose()
    {
        _shell.Dispose();
        _pool.Dispose();
    }

    private static SslClientAuthenticationOptions BuildTlsOptions(Uri connectionUri, WSManConnectionInfo connInfo,
        PSWSManSessionOption? extraConnInfo)
    {
        SslClientAuthenticationOptions tlsOptions = new()
        {
            TargetHost = connectionUri.DnsSafeHost,
        };

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
                using X509Store store = new(StoreName.My, location, OpenFlags.ReadOnly);
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

        return tlsOptions;
    }

    private static WSManCredential GenerateWSManCredential(AuthenticationMethod authMethod,
        AuthenticationProvider authProvider, string? userName, string? password,
        SslClientAuthenticationOptions? tlsOptions, SslClientAuthenticationOptions? credSSPTlsOptions,
        AuthenticationMethod credSSPAuthMethod, NegotiateOptions negoOptions)
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
                password, negoOptions);

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
            return GetNegotiateCredential(authMethod, authProvider, userName, password, negoOptions);
        }
    }

    private static WSManCredential GetNegotiateCredential(AuthenticationMethod method, AuthenticationProvider provider,
        string? userName, string? password, NegotiateOptions negoOptions)
    {
        NegotiateMethod negoMethod = method switch
        {
            AuthenticationMethod.NTLM => NegotiateMethod.NTLM,
            AuthenticationMethod.Kerberos => NegotiateMethod.Kerberos,
            _ => NegotiateMethod.Negotiate,
        };

        if (provider == AuthenticationProvider.Default)
        {
            provider = ModuleSettings.GetFromTLS().DefaultAuthProvider;
        }

        if (provider == AuthenticationProvider.Devolutions)
        {
            if (!ProviderLibs.TryGetDevolutionsSspi(out SspiProvider? devolutionsProvider, out Exception? devolutionsError))
            {
                throw new ArgumentException(devolutionsError.Message, devolutionsError);
            }

            return new SspiCredential(devolutionsProvider, userName, password, negoMethod, negoOptions);
        }

        // This is set when running on Windows
        SspiProvider? systemProvider = ProviderLibs.GetSystemSspi();
        if (systemProvider is not null)
        {
            return new SspiCredential(systemProvider, userName, password, negoMethod, negoOptions);
        }

        // If on non-Windows we first check if a custom GSSAPI library is
        // specified in the module settings. If not we fallback to the system
        // GSSAPI library. Set-PSWSManAuth checks the library when it is set
        // so a failure here means it stopped loading since, the error names
        // the library and the loader's reason.
        ModuleSettings moduleSettings = ModuleSettings.GetFromTLS();
        bool loaded;
        GssapiProvider? gssapiProvider;
        Exception? gssapiError;
        if (moduleSettings.GssapiLib != ModuleSettings.DefaultGssapiLib)
        {
            loaded = ProviderLibs.TryGetGssapi(moduleSettings.GssapiLib, out gssapiProvider, out gssapiError);
        }
        else
        {
            loaded = ProviderLibs.TryGetSystemGssapi(out gssapiProvider, out gssapiError);
        }

        if (!loaded)
        {
            throw new ArgumentException(gssapiError.Message, gssapiError);
        }

        return new GssapiCredential(gssapiProvider, userName, password, negoMethod, negoOptions);
    }

    /// <summary>Delivers pumped output to a transport manager and reports pump failures as transport errors.</summary>
    private sealed class TransportManagerSink : IWinRSOutputSink
    {
        private readonly BaseClientTransportManager _tm;
        private readonly WinRSShell _shell;
        private readonly Guid? _commandId;

        public TransportManagerSink(BaseClientTransportManager tm, WinRSShell shell, Guid? commandId)
        {
            _tm = tm;
            _shell = shell;
            _commandId = commandId;
        }

        public void OnData(string stream, byte[] data)
        {
            _tm.ProcessRawData(data, stream);
        }

        public void OnCompleted(WinRSReceiveCompletion completion)
        {
            if (completion.Reason is WinRSReceiveReason.Done or WinRSReceiveReason.Cancelled || _shell.IsClosed)
            {
                // A normal end, or the shell is being torn down locally and PowerShell already knows.
                return;
            }

            if (completion.Reason == WinRSReceiveReason.ShellClosed)
            {
                // For session-level pumps report the error to PowerShell so it knows the session is dead. Without
                // this, Enter-PSSession stays in a broken state where subsequent input hangs (e.g. after
                // Restart-Computer). Command pumps just end as the command is gone with the shell.
                if (_commandId is null && _tm is WSManClientSessionTransportManager sessionTM)
                {
                    TransportErrorOccuredEventArgs err = new(
                        new PSRemotingTransportException(completion.Error!.Message, completion.Error),
                        TransportMethodEnum.ReceiveShellOutputEx);
                    sessionTM.ProcessWSManTransportError(err);
                }
                return;
            }

            TransportErrorOccuredEventArgs failure = new(
                new PSRemotingTransportException(completion.Error!.Message, completion.Error),
                TransportMethodEnum.CreateShellEx);
            if (_tm is WSManClientSessionTransportManager clientTM)
            {
                clientTM.ProcessWSManTransportError(failure);
            }
            else if (_tm is WSManClientCommandTransportManager cmdTM)
            {
                cmdTM.ProcessWSManTransportError(failure);
            }
        }
    }
}

/// <summary>Maps the fake native session handles PowerShell holds to the sessions behind them.</summary>
internal static class WSManSessionState
{
    private static long s_nextSessionId = 0;

    public static ConcurrentDictionary<nint, WSManPSRPSession> Sessions { get; } = new();

    public static nint Store(WSManPSRPSession session)
    {
        nint sessionId = (nint)Interlocked.Increment(ref s_nextSessionId);
        Sessions[sessionId] = session;
        return sessionId;
    }

    public static WSManPSRPSession Get(nint sessionId)
    {
        return Sessions.TryGetValue(sessionId, out WSManPSRPSession? session)
            ? session
            : throw new InvalidOperationException($"Unknown PSWSMan session handle {sessionId}");
    }

    public static WSManPSRPSession? Remove(nint sessionId)
    {
        return Sessions.TryRemove(sessionId, out WSManPSRPSession? session) ? session : null;
    }
}
