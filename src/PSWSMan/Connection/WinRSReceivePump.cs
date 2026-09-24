using PSWSMan.Lib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;

namespace PSWSMan.Connection;

/// <summary>Continuously issues Receive requests for a shell or command and pushes the output to a sink.</summary>
/// <remarks>
/// <para>
/// The pump runs on its own dedicated thread and holds one pooled connection for its lifetime, the same model the
/// native WinRM client uses. It stops when the server reports the command is done, the shell goes away, or the
/// shell's cancellation token is triggered by <see cref="WinRSShell.Close"/> or <see cref="WinRSShell.Abort"/>.
/// </para>
/// <para>
/// A Receive that fails at the transport level, for example because the command being run bounced the network
/// adapter, is retried on a fresh connection with the exact same envelope. The server keeps the response for each
/// message id it has answered so resending the identical request returns the data that was lost, which is what
/// makes this safe for Receive and not for the other operations.
/// </para>
/// </remarks>
internal sealed class WinRSReceivePump
{
    private const int ThreadStackSize = 256 * 1024;

    private const int OperationTimedOut = unchecked((int)0x80338029);

    // ERROR_INTERNAL_ERROR - what the server answers when a Receive repeats the message id of one it is still
    // processing.
    private const int InternalError = 0x0000054F;

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
    private readonly int _retries;
    private readonly TimeSpan _retryBackoff;

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
        int retries,
        TimeSpan retryBackoff,
        CancellationToken token,
        Action<string>? trace)
    {
        _shell = shell;
        _winrs = winrs;
        _pool = pool;
        _sink = sink;
        _token = token;
        _trace = trace;
        _retries = retries;
        _retryBackoff = retryBackoff;
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

    /// <summary>Whether a Receive failure is a transport problem that a fresh connection may recover from.</summary>
    /// <param name="error">The exception raised by the connection.</param>
    /// <returns>True if the request should be resent on a new connection.</returns>
    /// <remarks>
    /// Timeouts cover both a request that never got its response because the socket silently died and a connect
    /// that fails while the host is still bringing its network back up. The rest are the ways a socket reports
    /// being reset or refused. Cancellation, authentication failures and server faults are never retried.
    /// </remarks>
    public static bool IsRetryableError(Exception error)
    {
        return error is TimeoutException or HttpRequestException or IOException or SocketException;
    }

    /// <summary>The time to wait before a retry attempt, doubling with each attempt.</summary>
    /// <param name="backoff">The delay before the first retry.</param>
    /// <param name="attempt">The 1-based retry attempt.</param>
    /// <returns>The delay to wait before the attempt.</returns>
    public static TimeSpan GetRetryDelay(TimeSpan backoff, int attempt)
    {
        if (attempt < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(attempt), "The retry attempt must be at least 1.");
        }

        // Capped so a large retry count cannot overflow the TimeSpan or produce an absurd wait.
        double multiplier = Math.Pow(2, Math.Min(attempt, 6) - 1);
        return TimeSpan.FromTicks((long)(backoff.Ticks * multiplier));
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
        WSManConnectionLease lease = _pool.Rent(_token);
        try
        {
            while (true)
            {
                _token.ThrowIfCancellationRequested();

                // The same request object is used for every attempt so a retry carries the message id the server
                // has already answered.
                WSManRequest request = _winrs.Receive(Streams, commandId: CommandId);
                WSManReceiveResponse response = SendReceive(request, ref lease);

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
        finally
        {
            lease.Dispose();
        }
    }

    private WSManReceiveResponse SendReceive(WSManRequest request, ref WSManConnectionLease lease)
    {
        int attempt = 0;
        int duplicate = 0;
        long firstSent = Stopwatch.GetTimestamp();
        while (true)
        {
            if (lease.Connection.IsBroken)
            {
                // Returning a broken connection disposes it, the next Rent opens a new socket and authenticates
                // again. Rent may block while the pool is at its limit which is also cancellable.
                lease.Dispose();
                lease = _pool.Rent(_token);
            }

            Trace(attempt == 0 ? "sending Receive request" : $"resending Receive request, retry {attempt}");
            try
            {
                ReadOnlyMemory<byte> raw = lease.Connection.Send(request.Content, _token);
                WSManReceiveResponse response = WSManReceiveResponse.Parse(raw.Span, request.MessageId);
                Trace("received response");
                return response;
            }
            catch (WSManFault e) when (e.WSManFaultCode == OperationTimedOut)
            {
                // ERROR_WSMAN_OPERATION_TIMEDOUT - the server hit its operation timeout with no data, just ask
                // again. This is a new request as the server has finished with the old message id.
                Trace("operation timeout received, retrying");
                request = _winrs.Receive(Streams, commandId: CommandId);
                attempt = 0;
                duplicate = 0;
                firstSent = Stopwatch.GetTimestamp();
            }
            catch (WSManFault e) when (attempt > 0 && e.WSManFaultCode == InternalError &&
                OriginalMayBePending(firstSent, duplicate) && !_token.IsCancellationRequested)
            {
                // The server still holds the original Receive for this message id, it had nothing to deliver when
                // the socket died so it never noticed. It faults the duplicate until that operation produces data
                // or hits its operation timeout, fails to deliver the result to the dead socket and caches it, at
                // which point the same request gets that result.
                duplicate++;
                TimeSpan delay = GetRetryDelay(_retryBackoff, duplicate);
                Trace($"server is still processing the original Receive, resending in {delay}");
                Wait(delay);
            }
            catch (Exception e) when (IsRetryableError(e) && attempt < _retries && !_token.IsCancellationRequested)
            {
                attempt++;
                TimeSpan delay = GetRetryDelay(_retryBackoff, attempt);
                Trace($"Receive failed, retry {attempt}/{_retries} in {delay}", e);
                Wait(delay);
            }
        }
    }

    /// <summary>Whether the server can still be holding the original Receive that a duplicate collided with.</summary>
    /// <remarks>
    /// The request timeout of the pool is the server's operation timeout plus a grace period, so once that much
    /// time has passed since the message id was first sent the server has finished with it one way or another. A
    /// pool without a request timeout falls back to the retry count.
    /// </remarks>
    private bool OriginalMayBePending(long firstSent, int duplicates)
    {
        TimeSpan limit = _pool.Options.RequestTimeout;
        return limit == Timeout.InfiniteTimeSpan
            ? duplicates < _retries
            : Stopwatch.GetElapsedTime(firstSent) < limit;
    }

    private void Wait(TimeSpan delay)
    {
        if (_token.WaitHandle.WaitOne(delay))
        {
            _token.ThrowIfCancellationRequested();
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
