using PSWSMan.Lib;
using System;
using System.Collections.Generic;
using System.Threading;

namespace PSWSMan.Connection;

/// <summary>Continuously issues Receive requests for a shell or command and pushes the output to a sink.</summary>
/// <remarks>
/// The pump runs on its own dedicated thread and holds one pooled connection for its lifetime, the same model the
/// native WinRM client uses. It stops when the server reports the command is done, the shell goes away, or the
/// shell's cancellation token is triggered by <see cref="WinRSShell.Close"/> or <see cref="WinRSShell.Abort"/>.
/// </remarks>
internal sealed class WinRSReceivePump
{
    private const int ThreadStackSize = 256 * 1024;

    // ERROR_WSMAN_OPERATION_TIMEDOUT - the server hit its operation timeout with no data, just ask again.
    private const int OperationTimedOut = unchecked((int)0x80338029);

    private static readonly HashSet<int> s_shellClosedFaults = new()
    {
        0x000003E3, // ERROR_OPERATION_ABORTED
        0x000004C7, // ERROR_CANCELLED
        unchecked((int)0x8033805B), // ERROR_WSMAN_UNEXPECTED_SELECTORS
        unchecked((int)0x803381C4), // ERROR_WINRS_SHELL_DISCONNECTED
        unchecked((int)0x803381DE), // ERROR_WSMAN_SERVICE_STREAM_DISCONNECTED
    };

    private readonly WinRSShell _shell;
    private readonly WinRSClient _winrs;
    private readonly WSManConnectionPool _pool;
    private readonly IWinRSOutputSink _sink;
    private readonly CancellationToken _token;
    private readonly Action<string>? _trace;
    private readonly Thread _thread;

    /// <summary>The command the pump receives for, null for the shell itself.</summary>
    public Guid? CommandId { get; }

    /// <summary>The streams requested from the server.</summary>
    public string Streams { get; }

    internal WinRSReceivePump(
        WinRSShell shell,
        WinRSClient winrs,
        WSManConnectionPool pool,
        IWinRSOutputSink sink,
        string streams,
        Guid? commandId,
        CancellationToken token,
        Action<string>? trace)
    {
        _shell = shell;
        _winrs = winrs;
        _pool = pool;
        _sink = sink;
        _token = token;
        _trace = trace;
        Streams = streams;
        CommandId = commandId;

        _thread = new Thread(Run, ThreadStackSize)
        {
            IsBackground = true,
            Name = commandId is null
                ? $"PSWSMan Receive Shell {shell.ShellId}"
                : $"PSWSMan Receive Command {commandId}",
        };
    }

    /// <summary>Whether a fault indicates the shell or command no longer exists on the server.</summary>
    /// <param name="fault">The fault to check.</param>
    /// <returns>True if the fault means there is nothing left to receive.</returns>
    public static bool IsShellClosedFault(WSManFault fault)
    {
        return fault.WSManFaultCode is int code && s_shellClosedFaults.Contains(code);
    }

    internal void Start() => _thread.Start();

    /// <summary>Waits for the pump thread to exit.</summary>
    /// <param name="timeout">How long to wait.</param>
    /// <returns>True if the thread exited within the timeout.</returns>
    public bool Join(TimeSpan timeout)
    {
        if (Thread.CurrentThread == _thread)
        {
            // Called from the sink on the pump's own thread, nothing to wait for.
            return false;
        }

        return _thread.Join(timeout);
    }

    private void Run()
    {
        // Nothing may escape a pump thread, an unhandled exception here takes the whole process down.
        WinRSReceiveCompletion completion;
        try
        {
            completion = ReceiveLoop();
        }
        catch (OperationCanceledException)
        {
            Trace("cancelled");
            completion = new(WinRSReceiveReason.Cancelled, null, null);
        }
        catch (WSManFault e) when (IsShellClosedFault(e))
        {
            Trace("shell closed fault received", e);
            completion = new(WinRSReceiveReason.ShellClosed, null, e);
        }
        catch (Exception e)
        {
            Trace("failed", e);
            completion = new(WinRSReceiveReason.Failed, null, e);
        }

        try
        {
            _shell.OnPumpExited(this);
        }
        catch (Exception e)
        {
            Trace("shell OnPumpExited failed", e);
        }

        try
        {
            _sink.OnCompleted(completion);
        }
        catch (Exception e)
        {
            Trace("sink OnCompleted failed", e);
        }
    }

    private WinRSReceiveCompletion ReceiveLoop()
    {
        using WSManConnectionLease lease = _pool.Rent(_token);

        while (true)
        {
            _token.ThrowIfCancellationRequested();

            Trace("sending Receive request");
            WSManRequest request = _winrs.Receive(Streams, commandId: CommandId);
            WSManReceiveResponse response;
            try
            {
                ReadOnlyMemory<byte> raw = lease.Connection.Send(request.Content, _token);
                response = WSManReceiveResponse.Parse(raw.Span, request.MessageId);
            }
            catch (WSManFault e) when (e.WSManFaultCode == OperationTimedOut)
            {
                Trace("operation timeout received, retrying");
                continue;
            }
            Trace("received response");

            foreach (KeyValuePair<string, byte[][]> entry in response.Streams)
            {
                foreach (byte[] chunk in entry.Value)
                {
                    _sink.OnData(entry.Key, chunk);
                }
            }

            if (response.State == CommandState.Done)
            {
                Trace("command state Done");
                return new(WinRSReceiveReason.Done, response.ExitCode, null);
            }
        }
    }

    private void Trace(string message, Exception? error = null)
    {
        if (_trace is null)
        {
            return;
        }

        try
        {
            string suffix = error is null ? "" : "\n" + WinRSShell.DescribeException(error);
            _trace($"PSWSMan Receive Pump [{CommandId?.ToString() ?? "shell"}]: {message}{suffix}");
        }
        catch (Exception)
        {
            // Tracing is best effort, it must never affect the pump.
        }
    }
}
