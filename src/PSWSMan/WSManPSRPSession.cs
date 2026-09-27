using PSWSMan.Connection;
using PSWSMan.Lib;
using System;
using System.Collections.Concurrent;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Management.Automation.Runspaces;
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
        int receiveRetries,
        PSTraceSource tracer)
    {
        _pool = pool;
        _client = client;
        _noMachineProfile = noMachineProfile;
        RunspacePoolId = runspacePoolId;
        _shell = new WinRSShell(pool, client, shellUri, tracer.WriteLine)
        {
            ReceiveRetries = receiveRetries,
        };
    }

    public static WSManPSRPSession Create(
        Guid runspacePoolId,
        Uri connectionUri,
        WSManConnectionInfo connInfo,
        PSWSManSessionOption? extraConnInfo,
        int maxEnvelopeSize,
        PSTraceSource tracer)
    {
        WSManTransport transport = WSManTransportFactory.Create(connectionUri, connInfo, extraConnInfo,
            maxEnvelopeSize, tracer.WriteLine);

        // PowerShell exposes this as the number of times the native client reconnects after a network failure. Here
        // it bounds how often a lost Receive is resent on a new connection, e.g. when the remote command restarts
        // the network adapter. A negative value is treated as no retries.
        int receiveRetries = Math.Max(connInfo.MaxConnectionRetryCount, 0);

        return new(transport.Pool, transport.Client, runspacePoolId, connInfo.ShellUri, connInfo.NoMachineProfile,
            receiveRetries, tracer);
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
