using PSWSMan.Lib;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;

namespace PSWSMan.Connection;

/// <summary>A chunk of output from a <see cref="WinRSCommand"/>.</summary>
internal sealed record WinRSOutput(string Stream, byte[] Data);

/// <summary>
/// A command running in a <see cref="WinRSShell"/>, with its output handed from the receive pump to the thread that
/// consumes it.
/// </summary>
internal sealed class WinRSCommand : IDisposable
{
    // The largest stdin payload sent in one Send request, the base64 of it has to fit well within the envelope size.
    public const int InputChunkSize = 64 * 1024;

    // ERROR_BROKEN_PIPE and ERROR_NO_DATA, what the cmd plugin answers a Send with once the process has exited or
    // closed its stdin.
    private static readonly HashSet<int> s_stdinClosedFaults = [0x0000006D, 0x000000E8];

    private readonly WinRSShell _shell;
    private readonly OutputQueue _queue = new();
    private readonly CancellationTokenSource _receiveCts = new();
    private bool _stdinClosed;
    private bool _disposed;

    private WinRSCommand(WinRSShell shell)
    {
        _shell = shell;
    }

    public Guid CommandId { get; private set; }

    /// <summary>Why the output ended, set once the consumer has read up to the completion.</summary>
    public WinRSReceiveCompletion? Completion { get; private set; }

    /// <summary>Whether input can still reach the process.</summary>
    public bool CanSend => !_stdinClosed && Completion is null;

    /// <summary>Whether the end of stdin has been sent.</summary>
    public bool InputEnded { get; private set; }

    /// <summary>Whether the command has been terminated so the server no longer holds it.</summary>
    public bool IsTerminated { get; private set; }

    /// <summary>The number of bytes sent to stdin.</summary>
    public long StdinLength { get; private set; }

    /// <summary>The number of stdout bytes the consumer has read.</summary>
    public long StdoutLength { get; private set; }

    /// <summary>The number of stderr bytes the consumer has read.</summary>
    public long StderrLength { get; private set; }

    /// <summary>Runs a command line in the shell and starts receiving its stdout and stderr.</summary>
    public static WinRSCommand Start(WinRSShell shell, string commandLine, CancellationToken cancellationToken)
    {
        WinRSCommand command = new(shell);
        command.CommandId = shell.RunCommand(commandLine, cancellationToken: cancellationToken);
        shell.StartReceive(command._queue, "stdout stderr", command.CommandId, command._receiveCts.Token);

        return command;
    }

    /// <summary>Sends data to the command's stdin in chunks the envelope can carry.</summary>
    /// <remarks>
    /// Once the process has exited or closed its stdin there is nobody to read the input so the rest is dropped,
    /// the same way PowerShell ignores the broken pipe when a local native command stops reading before its input
    /// is written. The output reaching completion is one signal, a pipe fault from the server on the Send is the
    /// other as the process can exit between the two.
    /// </remarks>
    public void Send(byte[] data, bool end, CancellationToken cancellationToken)
    {
        if (!CanSend || InputEnded)
        {
            return;
        }

        int offset = 0;
        do
        {
            int length = Math.Min(InputChunkSize, data.Length - offset);
            byte[] chunk = length == data.Length ? data : data.AsSpan(offset, length).ToArray();
            offset += length;
            try
            {
                _shell.Send("stdin", chunk, CommandId, end && offset >= data.Length, cancellationToken);
                StdinLength += chunk.Length;
            }
            catch (WSManFault e) when (e.WSManFaultCode is int code && s_stdinClosedFaults.Contains(code))
            {
                _stdinClosed = true;
                return;
            }
        }
        while (offset < data.Length);

        InputEnded = end;
    }

    /// <summary>Takes output that has already arrived without waiting for more.</summary>
    public bool TryRead([NotNullWhen(true)] out WinRSOutput? output)
    {
        while (Completion is null && _queue.TryTake(out OutputItem? item))
        {
            if (item.Completion is not null)
            {
                Completion = item.Completion;
                break;
            }

            output = Count(item.Output!);
            return true;
        }

        output = null;
        return false;
    }

    /// <summary>Waits for and yields the remaining output until the receive pump reports why it stopped.</summary>
    /// <remarks>Check <see cref="Completion"/> once the enumeration finishes.</remarks>
    public IEnumerable<WinRSOutput> ReadToEnd(CancellationToken cancellationToken)
    {
        if (Completion is not null)
        {
            yield break;
        }

        foreach (OutputItem item in _queue.GetConsumingEnumerable(cancellationToken))
        {
            if (item.Completion is not null)
            {
                Completion = item.Completion;
                yield break;
            }

            yield return Count(item.Output!);
        }
    }

    private WinRSOutput Count(WinRSOutput output)
    {
        if (output.Stream == "stderr")
        {
            StderrLength += output.Data.Length;
        }
        else
        {
            StdoutLength += output.Data.Length;
        }
        return output;
    }

    /// <summary>Throws when the output ended for any reason but the command finishing.</summary>
    public WinRSReceiveCompletion EnsureDone()
    {
        WinRSReceiveCompletion completion = Completion
            ?? throw new WSManTransportException("The receive pump ended without reporting a result.");
        if (completion.Reason != WinRSReceiveReason.Done)
        {
            throw completion.Error
                ?? new WSManTransportException($"The receive pump stopped unexpectedly ({completion.Reason}).");
        }

        return completion;
    }

    /// <summary>Sends a signal to the command, see <see cref="SignalCode"/>.</summary>
    public void Signal(string code, CancellationToken cancellationToken)
    {
        _shell.Signal(code, CommandId, cancellationToken);
    }

    /// <summary>Terminates the finished command so the server releases it and its output buffers.</summary>
    public void Terminate(CancellationToken cancellationToken)
    {
        Signal(SignalCode.Terminate, cancellationToken);
        IsTerminated = true;
    }

    /// <summary>Stops receiving output, the command itself keeps running until it is terminated.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        _receiveCts.Cancel();
        _receiveCts.Dispose();
        _queue.Dispose();
    }

    private sealed record OutputItem(WinRSOutput? Output, WinRSReceiveCompletion? Completion);

    private sealed class OutputQueue : IWinRSOutputSink, IDisposable
    {
        private readonly BlockingCollection<OutputItem> _items = new();

        public IEnumerable<OutputItem> GetConsumingEnumerable(CancellationToken token)
            => _items.GetConsumingEnumerable(token);

        public bool TryTake([NotNullWhen(true)] out OutputItem? item) => _items.TryTake(out item);

        public void OnData(string stream, byte[] data)
        {
            TryAdd(new(new(stream, data), null));
        }

        public void OnCompleted(WinRSReceiveCompletion completion)
        {
            TryAdd(new(null, completion));
        }

        private void TryAdd(OutputItem item)
        {
            try
            {
                _items.Add(item);
            }
            catch (Exception e) when (e is ObjectDisposedException or InvalidOperationException)
            {
                // The consumer has stopped and is tearing the shell down, the output has nowhere to go.
            }
        }

        public void Dispose()
        {
            _items.Dispose();
        }
    }
}
