using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Management.Automation;
using System.Text;
using System.Threading;
using PSWSMan.Connection;
using PSWSMan.Lib;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsLifecycle.Invoke, "WinRSCommand",
    DefaultParameterSetName = "ComputerName"
)]
[Alias("irscm")]
[OutputType(typeof(string), typeof(byte[]))]
public sealed class InvokeWinRSCommand : WinRSCmdletBase
{
    // Windows console programs expect CRLF terminated input lines.
    private const string InputNewLine = "\r\n";

    private readonly MemoryStream _pendingBytes = new();
    private WinRSLineDecoder? _stdout;
    private WinRSLineDecoder? _stderr;
    private WinRSCommand? _command;
    private bool _firstError = true;

    [Parameter(
        Mandatory = true,
        Position = 1
    )]
    [ValidateNotNullOrEmpty]
    public string Command { get; set; } = "";

    [Parameter(
        ValueFromPipeline = true
    )]
    [AllowNull]
    [AllowEmptyString]
    public PSObject? InputObject { get; set; }

    [Parameter]
    [EncodingTransform]
    [EncodingCompletions]
    [ValidateNotNull]
    public Encoding ConsoleEncoding { get; set; } = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    [Parameter]
    public SwitchParameter AsByteStream { get; set; }

    protected override void BeginProcessing()
    {
        base.BeginProcessing();

        // The shell's console already has its code page, the parameter only changes how this side encodes the
        // input and decodes the output.
        if (Shell is not null && !MyInvocation.BoundParameters.ContainsKey(nameof(ConsoleEncoding)))
        {
            ConsoleEncoding = Shell.ConsoleEncoding;
        }

        Guard(StartCommand);
    }

    protected override void ProcessRecord()
    {
        if (InputObject is null)
        {
            return;
        }

        Guard(() =>
        {
            SendInput(InputObject);
            WriteAvailableOutput();
        });
    }

    protected override void EndProcessing()
    {
        Guard(FinishCommand);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _command?.Dispose();
            _pendingBytes.Dispose();
        }
        base.Dispose(disposing);
    }

    /// <summary>Interrupts the running command like Ctrl+C would locally and waits a short time for it to exit.</summary>
    /// <remarks>
    /// The cmdlet's token is already cancelled so these requests get their own deadline. The output is discarded
    /// as the pipeline no longer accepts it, and a failure is only traced as aborting the shell is the fallback.
    /// </remarks>
    private protected override void OnStopping()
    {
        if (_command is null)
        {
            return;
        }

        using CancellationTokenSource cts = new(StopGracePeriod);
        try
        {
            while (_command.TryRead(out _))
            {
            }
            if (_command.Completion is null)
            {
                _command.Signal(SignalCode.CtrlC, cts.Token);
                foreach (WinRSOutput _ in _command.ReadToEnd(cts.Token))
                {
                }
            }
        }
        catch (Exception e)
        {
            Trace(
                $"PSWSMan Invoke-WinRSCommand: stopped command did not exit cleanly: {e.Message}");
        }
    }

    private void StartCommand()
    {
        OpenShell(ConsoleEncoding);

        _stdout = AsByteStream ? null : new WinRSLineDecoder(ConsoleEncoding);
        _stderr = new WinRSLineDecoder(ConsoleEncoding);

        _command = StartCommand(Command);
    }

    private void FinishCommand()
    {
        Debug.Assert(_command is not null);
        Debug.Assert(_stderr is not null);

        WinRSCommand command = _command;
        CancellationToken token = StopToken;

        // Closing stdin gives a process that reads it EOF instead of leaving it blocked.
        FlushPendingBytes();
        command.Send([], end: true, token);

        foreach (WinRSOutput output in command.ReadToEnd(token))
        {
            WriteOutput(output);
        }
        if (_stdout?.Flush() is string lastOut)
        {
            WriteLine(lastOut, isError: false);
        }
        if (_stderr.Flush() is string lastErr)
        {
            WriteLine(lastErr, isError: true);
        }

        WinRSReceiveCompletion completion = command.EnsureDone();
        WriteCommandFinished(command, completion);
        if (completion.ExitCode is int exitCode)
        {
            SessionState.PSVariable.Set("global:LASTEXITCODE", exitCode);
        }

        command.Terminate(token);
        CloseShell();
    }

    /// <summary>Sends one pipeline object to stdin.</summary>
    /// <remarks>
    /// Strings are lines. A byte array is raw data and so are single bytes, which arrive one per record when an
    /// array was enumerated by the pipeline so they are collected and sent together. Anything else that enumerates
    /// is unwrapped, the rest is sent as its string form, one line each.
    /// </remarks>
    private void SendInput(object? input)
    {
        object? value = input is PSObject pso ? pso.BaseObject : input;
        switch (value)
        {
            case null:
                break;
            case string text:
                FlushPendingBytes();
                SendStdin(ConsoleEncoding.GetBytes(text + InputNewLine));
                break;
            case byte[] bytes:
                FlushPendingBytes();
                SendStdin(bytes);
                break;
            case byte b:
                _pendingBytes.WriteByte(b);
                if (_pendingBytes.Length >= WinRSCommand.InputChunkSize)
                {
                    FlushPendingBytes();
                }
                break;
            case IEnumerable enumerable when value is not IDictionary:
                foreach (object? item in enumerable)
                {
                    SendInput(item);
                }
                break;
            default:
                FlushPendingBytes();
                SendStdin(ConsoleEncoding.GetBytes(LanguagePrimitives.ConvertTo<string>(value) + InputNewLine));
                break;
        }
    }

    private void FlushPendingBytes()
    {
        if (_pendingBytes.Length == 0)
        {
            return;
        }

        byte[] data = _pendingBytes.ToArray();
        _pendingBytes.SetLength(0);
        SendStdin(data);
    }

    private void SendStdin(byte[] data)
    {
        Debug.Assert(_command is not null);
        _command.Send(data, end: false, StopToken);
    }

    /// <summary>Writes the output that has already arrived without waiting for more.</summary>
    private void WriteAvailableOutput()
    {
        Debug.Assert(_command is not null);

        while (_command.TryRead(out WinRSOutput? output))
        {
            WriteOutput(output);
        }
    }

    private void WriteOutput(WinRSOutput output)
    {
        Debug.Assert(_stderr is not null);

        bool isError = output.Stream == "stderr";
        if (!isError && _stdout is null)
        {
            // Each chunk as the server returned it, enumerating byte by byte would cost a pipeline object per byte.
            if (output.Data.Length > 0)
            {
                WriteObject(output.Data, enumerateCollection: false);
            }
            return;
        }

        WinRSLineDecoder decoder = isError ? _stderr : _stdout!;
        foreach (string line in decoder.Decode(output.Data))
        {
            WriteLine(line, isError);
        }
    }

    private void WriteLine(string line, bool isError)
    {
        if (!isError)
        {
            WriteObject(line);
            return;
        }

        // The same shape PowerShell gives stderr lines of a local native command so they format as plain text. The
        // formatter matches the error id exactly, and WriteError would append the cmdlet type to it when it stamps
        // the record with the invocation info, so the internal flag the runtime uses to skip that step is set.
        //
        // Internal S.M.A API: ErrorRecord.PreserveInvocationInfoOnce is internal and only reachable through the
        // assembly wide IgnoresAccessChecksTo. It is a known risk, a PowerShell release that renames or removes it
        // makes this method fail with a MissingMemberException until PSWSMan is updated.
        ErrorRecord record = _firstError
            ? new(new RemoteException(line), "NativeCommandError", ErrorCategory.NotSpecified, line)
            : new(new RemoteException(line), "NativeCommandErrorMessage", ErrorCategory.NotSpecified, null);
        record.PreserveInvocationInfoOnce = true;
        _firstError = false;
        WriteError(record);
    }
}
