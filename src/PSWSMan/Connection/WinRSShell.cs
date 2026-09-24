using PSWSMan.Lib;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Xml.Linq;

namespace PSWSMan.Connection;

/// <summary>A WinRS shell on a remote host, driven synchronously over a <see cref="WSManConnectionPool"/>.</summary>
/// <remarks>
/// <para>
/// Every operation takes a cancellation token that is linked to the shell's own lifetime token. Cancelling either
/// aborts the request on whatever thread is blocked in it. <see cref="Close"/> deletes the shell then cancels the
/// lifetime token to stop the receive pumps, <see cref="Abort"/> cancels first and then attempts a best effort
/// delete on a fresh connection so the server does not keep the shell until its idle timeout.
/// </para>
/// <para>
/// The shell does not own the pool so one pool can serve several shells. The caller disposes the pool after the
/// shells that use it.
/// </para>
/// </remarks>
internal sealed class WinRSShell : IDisposable
{
    private static readonly TimeSpan s_pumpJoinTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan s_abortDeleteTimeout = TimeSpan.FromSeconds(10);

    private readonly object _lock = new();
    private readonly WSManConnectionPool _pool;
    private readonly WinRSClient _winrs;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<WinRSReceivePump> _pumps = new();
    private readonly Action<string>? _trace;
    private bool _opened;
    private bool _closed;

    /// <summary>The identifier of the shell once it has been opened or when targeting an existing shell.</summary>
    public Guid? ShellId { get; private set; }

    /// <summary>
    /// How many times a receive pump resends a Receive that failed at the transport level before giving up. Each
    /// retry uses a new connection and the same envelope, see <see cref="WinRSReceivePump"/>.
    /// </summary>
    public int ReceiveRetries { get; init; } = 5;

    /// <summary>The delay before the first Receive retry, it doubles with each subsequent retry.</summary>
    public TimeSpan ReceiveRetryBackoff { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Whether <see cref="Close"/> or <see cref="Abort"/> has been called.</summary>
    public bool IsClosed
    {
        get
        {
            lock (_lock)
            {
                return _closed;
            }
        }
    }

    /// <summary>Creates a shell handle, <see cref="Open"/> creates it on the server.</summary>
    /// <param name="pool">The connection pool for the endpoint.</param>
    /// <param name="client">The envelope builder holding the session id, envelope size and locale.</param>
    /// <param name="resourceUri">The shell resource URI, e.g. the PowerShell or cmd shell URI.</param>
    /// <param name="trace">Optional callback for diagnostic messages.</param>
    public WinRSShell(WSManConnectionPool pool, WSManClient client, string resourceUri, Action<string>? trace = null)
        : this(pool, new WinRSClient(client, resourceUri), trace)
    { }

    private WinRSShell(WSManConnectionPool pool, WinRSClient winrs, Action<string>? trace)
    {
        _pool = pool;
        _winrs = winrs;
        _trace = trace;
    }

    /// <summary>Creates the shell on the server.</summary>
    /// <param name="inputStreams">Space separated list of input stream names.</param>
    /// <param name="outputStreams">Space separated list of output stream names.</param>
    /// <param name="shellId">Optional shell identifier to request.</param>
    /// <param name="extra">Optional extra element to add to the Shell body, e.g. the PSRP creationXml.</param>
    /// <param name="options">Optional WSMan options to add to the header.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The parsed Create response.</returns>
    public WSManCreateResponse Open(
        string inputStreams = "stdin",
        string outputStreams = "stdout stderr",
        Guid? shellId = null,
        XElement? extra = null,
        OptionSet? options = null,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (_opened)
            {
                throw new InvalidOperationException("The shell has already been opened.");
            }
        }

        WSManRequest request = _winrs.Create(inputStreams, outputStreams, shellId, extra, options);
        Trace("sending Create");
        WSManCreateResponse response = Invoke<WSManCreateResponse>(request, cancellationToken);
        _winrs.ProcessCreateResponse(response);

        lock (_lock)
        {
            ShellId = response.ShellId;
            _opened = true;
        }

        return response;
    }

    /// <summary>Starts a command in the shell.</summary>
    /// <param name="executable">The executable or command to run.</param>
    /// <param name="arguments">Optional arguments for the executable.</param>
    /// <param name="noShell">Skip running the command through cmd.exe.</param>
    /// <param name="commandId">Optional command identifier to request.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The identifier of the running command.</returns>
    public Guid RunCommand(
        string executable,
        IList<string>? arguments = null,
        bool noShell = false,
        Guid? commandId = null,
        CancellationToken cancellationToken = default)
    {
        AssertOpened();
        WSManRequest request = _winrs.Command(executable, arguments, noShell, commandId);
        Trace("sending Command");
        WSManCommandResponse response = Invoke<WSManCommandResponse>(request, cancellationToken);

        return response.CommandId;
    }

    /// <summary>Sends input data to the shell or a command.</summary>
    /// <param name="stream">The name of the input stream.</param>
    /// <param name="data">The data to send.</param>
    /// <param name="commandId">The command to send to, null for the shell.</param>
    /// <param name="end">Marks this as the last input for the stream.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public void Send(string stream, byte[] data, Guid? commandId = null, bool end = false,
        CancellationToken cancellationToken = default)
    {
        AssertOpened();
        WSManRequest request = _winrs.Send(stream, data, commandId, end);
        Trace($"sending Send for {commandId?.ToString() ?? "shell"}");
        Invoke<WSManSendResponse>(request, cancellationToken);
    }

    /// <summary>Sends a signal to the shell or a command.</summary>
    /// <param name="code">The signal code URI, see <see cref="SignalCode"/>.</param>
    /// <param name="commandId">The command to signal, null for the shell.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public void Signal(string code, Guid? commandId = null, CancellationToken cancellationToken = default)
    {
        AssertOpened();
        WSManRequest request = _winrs.Signal(code, commandId);
        Trace($"sending Signal {code} for {commandId?.ToString() ?? "shell"}");
        Invoke<WSManSignalResponse>(request, cancellationToken);
    }

    /// <summary>Starts a pump that receives output for the shell or a command on its own thread.</summary>
    /// <param name="sink">Where the output is delivered.</param>
    /// <param name="streams">Space separated list of stream names to receive.</param>
    /// <param name="commandId">The command to receive for, null for the shell.</param>
    /// <returns>The running pump.</returns>
    public WinRSReceivePump StartReceive(IWinRSOutputSink sink, string streams = "stdout stderr",
        Guid? commandId = null)
    {
        AssertOpened();

        if (ReceiveRetries < 0)
        {
            throw new InvalidOperationException("ReceiveRetries cannot be negative.");
        }
        if (ReceiveRetryBackoff < TimeSpan.Zero)
        {
            throw new InvalidOperationException("ReceiveRetryBackoff cannot be negative.");
        }

        WinRSReceivePump pump = new(this, _winrs, _pool, sink, streams, commandId, ReceiveRetries,
            ReceiveRetryBackoff, _cts.Token, _trace);
        lock (_lock)
        {
            if (_closed)
            {
                throw new InvalidOperationException("The shell has been closed.");
            }
            _pumps.Add(pump);
        }

        pump.Start();
        return pump;
    }

    /// <summary>Deletes the shell on the server and stops the receive pumps.</summary>
    /// <param name="cancellationToken">Cancels the Delete request, the pumps are stopped regardless.</param>
    public void Close(CancellationToken cancellationToken = default)
    {
        bool opened;
        lock (_lock)
        {
            if (_closed)
            {
                return;
            }
            _closed = true;
            opened = _opened;
        }

        try
        {
            if (opened)
            {
                Trace("sending Delete");
                Invoke<WSManDeleteResponse>(_winrs.Delete(), cancellationToken);
            }
        }
        finally
        {
            StopPumps();
        }
    }

    /// <summary>Stops everything in flight immediately, then makes a best effort attempt to delete the shell.</summary>
    public void Abort()
    {
        bool opened;
        lock (_lock)
        {
            if (_closed)
            {
                return;
            }
            _closed = true;
            opened = _opened;
        }

        Trace("aborting");
        StopPumps();

        if (opened)
        {
            // The lifetime token is cancelled so this goes straight to the pool with its own deadline.
            using CancellationTokenSource deleteCts = new(s_abortDeleteTimeout);
            try
            {
                Trace("sending best effort Delete");
                _pool.Invoke<WSManDeleteResponse>(_winrs.Delete(), deleteCts.Token);
            }
            catch (Exception e)
            {
                Trace("best effort Delete failed", e);
            }
        }
    }

    /// <summary>Aborts the shell if it has not been closed.</summary>
    public void Dispose()
    {
        Abort();
        _cts.Dispose();
    }

    internal T Invoke<T>(WSManRequest request, CancellationToken cancellationToken) where T : IWSManPayload<T>
    {
        // Every request is cancelled by either the caller's token or the shell being closed.
        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken,
            _cts.Token);
        return _pool.Invoke<T>(request, linked.Token);
    }

    internal void OnPumpExited(WinRSReceivePump pump)
    {
        lock (_lock)
        {
            _pumps.Remove(pump);
        }
    }

    private void StopPumps()
    {
        _cts.Cancel();

        WinRSReceivePump[] pumps;
        lock (_lock)
        {
            pumps = _pumps.ToArray();
        }

        foreach (WinRSReceivePump pump in pumps)
        {
            if (!pump.Join(s_pumpJoinTimeout))
            {
                Trace($"receive pump for {pump.CommandId?.ToString() ?? "shell"} did not stop in time");
            }
        }
    }

    private void AssertOpened()
    {
        lock (_lock)
        {
            if (!_opened)
            {
                throw new InvalidOperationException("The shell has not been opened.");
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
            string suffix = error is null ? "" : "\n" + DescribeException(error);
            _trace($"PSWSMan Shell [{ShellId?.ToString() ?? "unopened"}]: {message}{suffix}");
        }
        catch (Exception)
        {
            // Tracing is best effort, it must never affect the shell.
        }
    }

    /// <summary>Formats an exception for tracing without trusting <see cref="Exception.ToString"/>.</summary>
    /// <remarks>
    /// Walking the stack trace of an exception that passed through detoured or dynamically generated methods can
    /// itself throw inside the runtime, which is fatal on a background thread. The type and message are always
    /// safe, the stack trace is added only if the runtime can produce it.
    /// </remarks>
    internal static string DescribeException(Exception error)
    {
        StringBuilder sb = new();
        Exception? current = error;
        while (current is not null)
        {
            if (sb.Length > 0)
            {
                sb.Append("\n---> ");
            }
            sb.Append(current.GetType().FullName).Append(": ").Append(current.Message);
            current = current.InnerException;
        }

        try
        {
            string? stack = error.StackTrace;
            if (!string.IsNullOrEmpty(stack))
            {
                sb.Append('\n').Append(stack);
            }
        }
        catch (Exception)
        {
            sb.Append("\n<stack trace unavailable>");
        }

        return sb.ToString();
    }
}
