using Microsoft.PowerShell.Commands;
using PSWSMan.Connection;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Remoting.Client;
using System.Text;
using System.Threading;

namespace PSWSMan.Commands;

/// <summary>The shell and transfer handling shared by the cmdlets that copy files through a WinRS shell.</summary>
public abstract class WinRSFileCmdletBase : WinRSCmdletBase
{
    [Parameter]
    public CompressionMethod Compression { get; set; } = CompressionMethod.Deflate;

    protected override void EndProcessing()
    {
        Guard(CloseShell);
    }

    /// <summary>Resolves a local path without expanding wildcards, it must be on the file system.</summary>
    private protected string GetFileSystemPath(string path)
    {
        string resolved = SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out ProviderInfo provider, out _);
        if (provider.ImplementingType != typeof(FileSystemProvider))
        {
            throw new ArgumentException($"The path '{path}' is not a file system path.");
        }

        return resolved;
    }

    /// <summary>Runs one transfer command, sending the input to its stdin and handing its stdout to a reader.</summary>
    /// <param name="commandLine">The command to run.</param>
    /// <param name="description">What to call the command in verbose messages.</param>
    /// <param name="input">The chunks to send to stdin, stdin is left alone when null.</param>
    /// <param name="readStdout">
    /// Reads stdout as a stream once the input has been sent, whatever it leaves unread is discarded.
    /// </param>
    /// <returns>The exit code, the stderr text, and the exception that stopped the input from being read.</returns>
    /// <remarks>
    /// When reading the input fails, or the cmdlet is stopped, stdin is still closed so the remote script sees its
    /// input end early and cleans up rather than being killed with its temporary file in place when the shell is
    /// aborted.
    /// </remarks>
    private protected TransferResult RunTransfer(string commandLine, string description,
        IEnumerable<byte[]>? input, Action<Stream> readStdout)
    {
        // Opened for the first file, so nothing connects when every file is skipped.
        OpenShell(Encoding.UTF8);
        using WinRSCommand command = StartCommand(commandLine, description);
        try
        {
            using MemoryStream stderr = new();
            Queue<byte[]> stdout = new();

            void Handle(WinRSOutput output)
            {
                if (output.Stream == "stderr")
                {
                    stderr.Write(output.Data);
                }
                else
                {
                    stdout.Enqueue(output.Data);
                }
            }

            Exception? inputError = null;
            if (input is not null)
            {
                using IEnumerator<byte[]> chunks = input.GetEnumerator();
                byte[]? pending = null;
                while (true)
                {
                    try
                    {
                        if (!chunks.MoveNext())
                        {
                            break;
                        }
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    {
                        inputError = e;
                        break;
                    }

                    // Holding back one chunk lets the last one carry the end of stdin without an extra Send.
                    if (pending is not null)
                    {
                        command.Send(pending, end: false, StopToken);
                        while (command.TryRead(out WinRSOutput? output))
                        {
                            Handle(output);
                        }
                        if (!command.CanSend)
                        {
                            break;
                        }
                    }
                    pending = chunks.Current;
                }

                command.Send(inputError is null ? pending ?? [] : [], end: true, StopToken);
            }

            using IEnumerator<WinRSOutput> remaining = command.ReadToEnd(StopToken).GetEnumerator();
            using (ChunkReadStream stdoutStream = new(() =>
            {
                while (stdout.Count == 0)
                {
                    if (!remaining.MoveNext())
                    {
                        return null;
                    }
                    Handle(remaining.Current);
                }
                return stdout.Dequeue();
            }))
            {
                readStdout(stdoutStream);
            }
            while (remaining.MoveNext())
            {
                Handle(remaining.Current);
            }

            WinRSReceiveCompletion completion = command.EnsureDone();
            WriteCommandFinished(command, completion);
            command.Terminate(StopToken);

            return new(completion.ExitCode ?? 0, Encoding.UTF8.GetString(stderr.ToArray()).Trim(), inputError);
        }
        catch (Exception e) when (input is not null && (e is PipelineStoppedException ||
            (e is OperationCanceledException && StopToken.IsCancellationRequested)))
        {
            // A stop surfaces as the cancelled token in a request, or as PowerShell rejecting the next progress
            // record.
            FinishAfterStop(command);
            throw;
        }
    }

    /// <summary>Ends stdin of a stopped upload and waits a short time for the remote script to exit.</summary>
    /// <remarks>
    /// Aborting the shell kills the process before its finally block can remove the temporary file. The cmdlet's
    /// token is already cancelled so these requests get their own deadline, and failing is only traced as the
    /// abort that follows is the fallback.
    /// </remarks>
    private static void FinishAfterStop(WinRSCommand command)
    {
        using CancellationTokenSource cts = new(StopGracePeriod);
        try
        {
            command.Send([], end: true, cts.Token);
            foreach (WinRSOutput _ in command.ReadToEnd(cts.Token))
            {
            }
        }
        catch (Exception e)
        {
            BaseClientTransportManager.tracer.WriteLine(
                $"PSWSMan file transfer: stopped upload did not finish cleanly: {e.Message}");
        }
    }

    /// <summary>Writes a non-terminating error for one file.</summary>
    private protected void WriteFileError(Exception exception, string errorId, object target)
    {
        ErrorCategory category = exception switch
        {
            FileNotFoundException or DirectoryNotFoundException or ItemNotFoundException
                => ErrorCategory.ObjectNotFound,
            UnauthorizedAccessException => ErrorCategory.PermissionDenied,
            ArgumentException or NotSupportedException => ErrorCategory.InvalidArgument,
            InvalidDataException => ErrorCategory.InvalidResult,
            _ => ErrorCategory.NotSpecified,
        };
        WriteError(new ErrorRecord(exception, errorId, category, target));
    }

    private protected sealed record TransferResult(int ExitCode, string Stderr, Exception? InputError)
    {
        public Exception? GetRemoteError()
        {
            if (ExitCode == 0)
            {
                return null;
            }

            string message = Stderr.Length > 0
                ? Stderr
                : $"The remote PowerShell process exited with code {ExitCode} without an error message.";
            return new RemoteException(message);
        }
    }

    /// <summary>Reports the progress of one file, only writing a record when the percentage changes.</summary>
    private protected sealed class TransferProgress
    {
        private static int s_nextActivityId = 1;

        private readonly Cmdlet _cmdlet;
        private readonly ProgressRecord _record;
        private int _lastPercent = -1;

        public TransferProgress(Cmdlet cmdlet, string activity)
        {
            _cmdlet = cmdlet;
            _record = new(s_nextActivityId++, activity, "Starting");
        }

        public void Update(long done, long? total)
        {
            if (total is not long length)
            {
                return;
            }

            int percent = length == 0 ? 100 : (int)(Math.Min(done, length) * 100 / length);
            if (percent == _lastPercent)
            {
                return;
            }

            _lastPercent = percent;
            _record.PercentComplete = percent;
            _record.StatusDescription = string.Format(CultureInfo.CurrentCulture, "{0:N0} of {1:N0} bytes",
                Math.Min(done, length), length);
            _cmdlet.WriteProgress(_record);
        }

        public void Complete()
        {
            if (_lastPercent == -1)
            {
                return;
            }

            _record.RecordType = ProgressRecordType.Completed;
            _cmdlet.WriteProgress(_record);
        }
    }
}
