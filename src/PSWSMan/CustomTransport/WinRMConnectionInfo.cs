using PSWSMan.Connection;
using System;
using System.Management.Automation;
using System.Management.Automation.Internal;
using System.Management.Automation.Remoting.Client;
using System.Management.Automation.Runspaces;
using System.Threading;

namespace PSWSMan.CustomTransport;

/// <summary>Connection details for a PSRP session over PSWSMan's own WinRM client.</summary>
/// <remarks>
/// This plugs into PowerShell through the public custom transport API rather than the patched WSMan transport, so
/// nothing in PowerShell is modified to use it.
/// </remarks>
public sealed class WinRMConnectionInfo : RunspaceConnectionInfo
{
    internal WinRMConnectionInfo(Uri connectionUri, string shellUri, PSCredential? credential,
        string? certificateThumbprint, WinRMSessionOption options, AuthenticationMethod authMethod)
    {
        ConnectionUri = connectionUri;
        ShellUri = shellUri;
        Credential = credential!;
        CertificateThumbprint = certificateThumbprint!;
        Options = options;
        AuthMethod = authMethod;

        if (options.Culture is not null)
        {
            Culture = options.Culture;
        }
        if (options.UICulture is not null)
        {
            UICulture = options.UICulture;
        }
        OpenTimeout = ToTimeoutMs(options.OpenTimeout);
        CancelTimeout = ToTimeoutMs(options.CancelTimeout);
        OperationTimeout = ToTimeoutMs(options.OperationTimeout);
    }

    public Uri ConnectionUri { get; private set; }

    public string ShellUri { get; }

    public WinRMSessionOption Options { get; }

    public AuthenticationMethod AuthMethod { get; set; }

    /// <summary>Aborts the connection while it is still being made, e.g. when New-WinRMSession is stopped.</summary>
    /// <remarks>
    /// Closing a runspace that is still opening waits for the open to finish, which can take the whole connect
    /// timeout. Cancelling this makes the transport fail straight away instead.
    /// </remarks>
    internal CancellationToken OpenCancellation { get; init; }

    public override string ComputerName
    {
        get => ConnectionUri.Host;
        set => ConnectionUri = new UriBuilder(ConnectionUri) { Host = value }.Uri;
    }

    public override PSCredential Credential { get; set; }

    public override AuthenticationMechanism AuthenticationMechanism
    {
        get => AuthMethod switch
        {
            AuthenticationMethod.Basic => AuthenticationMechanism.Basic,
            AuthenticationMethod.Negotiate or AuthenticationMethod.NTLM => AuthenticationMechanism.Negotiate,
            AuthenticationMethod.Kerberos => AuthenticationMechanism.Kerberos,
            AuthenticationMethod.CredSSP => AuthenticationMechanism.Credssp,
            _ => AuthenticationMechanism.Default,
        };
        set => AuthMethod = value switch
        {
            AuthenticationMechanism.Basic => AuthenticationMethod.Basic,
            AuthenticationMechanism.Negotiate => AuthenticationMethod.Negotiate,
            AuthenticationMechanism.NegotiateWithImplicitCredential => AuthenticationMethod.Negotiate,
            AuthenticationMechanism.Kerberos => AuthenticationMethod.Kerberos,
            AuthenticationMechanism.Credssp => AuthenticationMethod.CredSSP,
            _ => AuthenticationMethod.Default,
        };
    }

    public override string CertificateThumbprint { get; set; }

    public override RunspaceConnectionInfo Clone() => new WinRMConnectionInfo(ConnectionUri, ShellUri, Credential,
        CertificateThumbprint, Options, AuthMethod)
    {
        OpenCancellation = OpenCancellation,
    };

    public override BaseClientSessionTransportManager CreateClientSessionTransportManager(
        Guid instanceId,
        string sessionName,
        PSRemotingCryptoHelper cryptoHelper)
    {
        return new WinRMClientTransportManager(this, instanceId, cryptoHelper);
    }

    private static int ToTimeoutMs(TimeSpan value) => value.TotalMilliseconds switch
    {
        < 0 => 0,
        > int.MaxValue => int.MaxValue,
        double ms => (int)ms,
    };
}

/// <summary>Hands the OutOfProc packets of a runspace pool to an <see cref="OutOfProcWSManTranslator"/>.</summary>
internal sealed class WinRMClientTransportManager : ClientSessionTransportManagerBase
{
    private readonly WinRMConnectionInfo _connInfo;
    private readonly Guid _runspacePoolId;
    private OutOfProcWSManTranslator? _translator;

    public WinRMClientTransportManager(WinRMConnectionInfo connInfo, Guid runspacePoolId,
        PSRemotingCryptoHelper cryptoHelper) : base(runspacePoolId, cryptoHelper)
    {
        _connInfo = connInfo;
        _runspacePoolId = runspacePoolId;
    }

    public override void CreateAsync()
    {
        WinRMSessionOption options = _connInfo.Options;
        // The internal PowerShell trace sources are off limits here, the TracePath option is the only trace.
        Action<string>? trace = FileTrace.Create(options.TracePath);
        string? thumbprint = string.IsNullOrEmpty(_connInfo.CertificateThumbprint)
            ? null
            : _connInfo.CertificateThumbprint;
        WSManTransport transport = WSManTransportFactory.Create(_connInfo.ConnectionUri, _connInfo.Credential,
            thumbprint, options, WSManPSRPSession.DefaultMaxEnvelopeSize, trace ?? (_ => { }), _connInfo.AuthMethod);

        WSManShellOperations shell = new(transport.Pool, transport.Client, _connInfo.ShellUri,
            Math.Max(options.MaxConnectionRetryCount, 0), trace);
        _translator = new OutOfProcWSManTranslator(
            shell,
            _runspacePoolId,
            options.NoMachineProfile,
            HandleDataReceived,
            e => HandleErrorDataReceived(e.Message),
            trace,
            _connInfo.OpenCancellation);
        SetMessageWriter(_translator.Writer);

        // Sends the first fragment, the session capability and runspace pool init messages, which the translator
        // turns into the WSMan Create.
        SendOneItem();
    }

    protected override void CleanupConnection()
    {
        _translator?.Dispose();
    }

    protected override void Dispose(bool isDisposing)
    {
        base.Dispose(isDisposing);
        if (isDisposing)
        {
            _translator?.Dispose();
        }
    }
}
