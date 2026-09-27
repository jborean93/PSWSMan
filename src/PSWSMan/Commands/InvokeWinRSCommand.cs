using PSWSMan.Connection;
using PSWSMan.Lib;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Management.Automation.Runspaces;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsLifecycle.Invoke, "WinRSCommand",
    DefaultParameterSetName = "ComputerName"
)]
[Alias("iwcm")]
[OutputType(typeof(string), typeof(byte[]))]
public sealed class InvokeWinRSCommand : PSCmdlet, IDisposable
{
    private const string CmdShellUri = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

    // Windows console programs expect CRLF terminated input lines.
    private const string InputNewLine = "\r\n";

    // The largest stdin payload sent in one Send request, the base64 of it has to fit well within the envelope size.
    internal const int InputChunkSize = 64 * 1024;

    // ERROR_BROKEN_PIPE and ERROR_NO_DATA, what the cmd plugin answers a Send with once the process has exited or
    // closed its stdin.
    private static readonly HashSet<int> s_stdinClosedFaults = [0x0000006D, 0x000000E8];

    private readonly CancellationTokenSource _cts = new();
    private readonly OutputQueue _queue = new();
    private readonly MemoryStream _pendingBytes = new();
    private WinRSLineDecoder? _stdout;
    private WinRSLineDecoder? _stderr;
    private WSManTransport? _transport;
    private WinRSShell? _shell;
    private Guid _commandId;
    private bool _firstError = true;
    private bool _stdinClosed;
    private WinRSReceiveCompletion? _completion;

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "ComputerName"
    )]
    [ValidateNotNullOrEmpty]
    [Alias("Cn")]
    public string ComputerName { get; set; } = "";

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "ConnectionUri"
    )]
    [ValidateNotNull]
    [Alias("URI", "CU")]
    public Uri? ConnectionUri { get; set; }

    [Parameter(
        Mandatory = true,
        Position = 1
    )]
    [ValidateNotNullOrEmpty]
    public string Command { get; set; } = "";

    [Parameter(
        ValueFromPipeline = true
    )]
    [System.Management.Automation.AllowNull]
    [AllowEmptyString]
    public PSObject? InputObject { get; set; }

    [Parameter]
    [EncodingTransform]
    [EncodingCompletions]
    [ValidateNotNull]
    public Encoding ConsoleEncoding { get; set; } = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    [Parameter]
    public SwitchParameter AsByteStream { get; set; }

    [Parameter]
    [Credential]
    public PSCredential? Credential { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [ValidateRange(1, 65535)]
    public int Port { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public SwitchParameter UseSSL { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [ValidateNotNullOrEmpty]
    public string ApplicationName { get; set; } = "wsman";

    [Parameter]
    public PSSessionOption? SessionOption { get; set; }

    [Parameter]
    public AuthenticationMethod Authentication { get; set; } = AuthenticationMethod.Default;

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string? CertificateThumbprint { get; set; }

    protected override void BeginProcessing()
    {
        if (ConnectionUri is not null && (!ConnectionUri.IsAbsoluteUri ||
            (ConnectionUri.Scheme != Uri.UriSchemeHttp && ConnectionUri.Scheme != Uri.UriSchemeHttps)))
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException($"The ConnectionUri '{ConnectionUri}' must be an absolute http or https URI."),
                "WinRSCommandInvalidParameter",
                ErrorCategory.InvalidArgument,
                ConnectionUri));
        }

        if (CertificateThumbprint is not null)
        {
            // The same combinations Invoke-Command rejects, plus the transport requirement it leaves to WinRM.
            string? problem = null;
            if (Credential is not null)
            {
                problem = "The Credential parameter and the CertificateThumbprint parameter cannot be used together.";
            }
            else if (Authentication != AuthenticationMethod.Default)
            {
                problem = "The Authentication parameter and the CertificateThumbprint parameter cannot be used together.";
            }
            else if (ConnectionUri is null ? !UseSSL : ConnectionUri.Scheme != Uri.UriSchemeHttps)
            {
                problem = "The CertificateThumbprint parameter requires UseSSL or a https ConnectionUri, certificate authentication is only available over HTTPS.";
            }

            if (problem is not null)
            {
                ThrowTerminatingError(new ErrorRecord(new ArgumentException(problem), "WinRSCommandInvalidParameter",
                    ErrorCategory.InvalidArgument, null));
            }
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

    protected override void StopProcessing()
    {
        _cts.Cancel();
    }

    /// <summary>Aborts anything still running, a no-op after a normal finish.</summary>
    public void Dispose()
    {
        _shell?.Dispose();
        _transport?.Dispose();
        _queue.Dispose();
        _pendingBytes.Dispose();
        _cts.Dispose();
    }

    /// <summary>Runs one phase of the cmdlet, turning transport failures into terminating errors.</summary>
    private void Guard(Action phase)
    {
        try
        {
            phase();
        }
        catch (OperationCanceledException) when (_cts.IsCancellationRequested)
        {
            // Stopped with Ctrl+C or by the pipeline, Dispose tears the shell down.
        }
        catch (Exception e) when (e is WSManException or AuthenticationException or HttpRequestException
            or SocketException or IOException or TimeoutException or ArgumentException)
        {
            ErrorCategory category = e switch
            {
                AuthenticationException => ErrorCategory.AuthenticationError,
                WSManFault => ErrorCategory.InvalidOperation,
                ArgumentException => ErrorCategory.InvalidArgument,
                _ => ErrorCategory.ConnectionError,
            };
            ThrowTerminatingError(new ErrorRecord(e, "WinRSCommandFailed", category,
                ConnectionUri is null ? ComputerName : ConnectionUri));
        }
    }

    private void StartCommand()
    {
        PSTraceSource tracer = BaseClientTransportManager.tracer;
        CancellationToken token = _cts.Token;

        // Built the same way Invoke-Command builds it, so -SessionOption means the same thing for both.
        // A ConnectionUri is used as is, without a port that means 80 or 443 as it does for Invoke-Command.
        WSManConnectionInfo connInfo = ConnectionUri is null
            ? new(UseSSL, ComputerName, Port, ApplicationName, CmdShellUri, Credential)
            : new(ConnectionUri, CmdShellUri, Credential);
        if (CertificateThumbprint is not null)
        {
            // The setter rejects null rather than treating it as unset.
            connInfo.CertificateThumbprint = CertificateThumbprint;
        }
        PSWSManSessionOption? extraOptions = null;
        if (SessionOption is not null)
        {
            connInfo.SetSessionOptions(SessionOption);
            extraOptions = WSManTransportFactory.GetExtraOptions(SessionOption);
        }
        Uri connectionUri = WSManTransportFactory.GetConnectionUri(connInfo);

        _transport = WSManTransportFactory.Create(connectionUri, connInfo, extraOptions,
            WSManPSRPSession.DefaultMaxEnvelopeSize, tracer.WriteLine, Authentication);
        // Disposing the shell aborts it, which kills a still running command on every exit path but the normal one.
        _shell = new WinRSShell(_transport.Pool, _transport.Client, CmdShellUri, tracer.WriteLine)
        {
            ReceiveRetries = Math.Max(connInfo.MaxConnectionRetryCount, 0),
        };

        _stdout = AsByteStream ? null : new WinRSLineDecoder(ConsoleEncoding);
        _stderr = new WinRSLineDecoder(ConsoleEncoding);

        OptionSet shellOptions = new();
        shellOptions.Add("WINRS_CODEPAGE", ConsoleEncoding.CodePage.ToString(CultureInfo.InvariantCulture));
        if (connInfo.NoMachineProfile)
        {
            shellOptions.Add("WINRS_NOPROFILE", "TRUE");
        }
        _shell.Open(options: shellOptions, cancellationToken: token);

        _commandId = _shell.RunCommand(Command, cancellationToken: token);
        _shell.StartReceive(_queue, "stdout stderr", _commandId);
    }

    private void FinishCommand()
    {
        Debug.Assert(_shell is not null);

        WinRSShell shell = _shell;
        CancellationToken token = _cts.Token;

        // Closing stdin gives a process that reads it EOF instead of leaving it blocked.
        FlushPendingBytes();
        SendStdin([], end: true);

        WinRSReceiveCompletion completion = WriteRemainingOutput(token);
        if (completion.Reason != WinRSReceiveReason.Done)
        {
            throw completion.Error
                ?? new WSManTransportException($"The receive pump stopped unexpectedly ({completion.Reason}).");
        }

        if (completion.ExitCode is int exitCode)
        {
            SessionState.PSVariable.Set("global:LASTEXITCODE", exitCode);
        }

        // The command has finished but the server keeps it, and its output buffers, until it is terminated.
        shell.Signal(SignalCode.Terminate, _commandId, token);
        shell.Close(token);
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
                if (_pendingBytes.Length >= InputChunkSize)
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

    /// <summary>Sends data to the command's stdin in chunks the envelope can carry.</summary>
    /// <remarks>
    /// Once the process has exited or closed its stdin there is nobody to read the input so the rest is dropped,
    /// the same way PowerShell ignores the broken pipe when a local native command stops reading before its input
    /// is written. The pump reporting completion is one signal, a pipe fault from the server on the Send is the
    /// other as the process can exit between the two.
    /// </remarks>
    private void SendStdin(byte[] data, bool end = false)
    {
        Debug.Assert(_shell is not null);

        if (_stdinClosed || _completion is not null)
        {
            return;
        }

        WinRSShell shell = _shell;
        int offset = 0;
        do
        {
            int length = Math.Min(InputChunkSize, data.Length - offset);
            byte[] chunk = length == data.Length ? data : data.AsSpan(offset, length).ToArray();
            offset += length;
            try
            {
                shell.Send("stdin", chunk, _commandId, end && offset >= data.Length, _cts.Token);
            }
            catch (WSManFault e) when (e.WSManFaultCode is int code && s_stdinClosedFaults.Contains(code))
            {
                _stdinClosed = true;
                return;
            }
        }
        while (offset < data.Length);
    }

    /// <summary>Writes the output that has already arrived without waiting for more.</summary>
    private void WriteAvailableOutput()
    {
        while (_completion is null && _queue.TryTake(out OutputItem? item))
        {
            WriteItem(item);
        }
    }

    /// <summary>Drains the pump's queue onto the pipeline until the pump reports why it stopped.</summary>
    private WinRSReceiveCompletion WriteRemainingOutput(CancellationToken token)
    {
        Debug.Assert(_stderr is not null);

        if (_completion is null)
        {
            foreach (OutputItem item in _queue.GetConsumingEnumerable(token))
            {
                WriteItem(item);
                if (_completion is not null)
                {
                    break;
                }
            }
        }

        if (_stdout?.Flush() is string lastOut)
        {
            WriteLine(lastOut, isError: false);
        }
        if (_stderr.Flush() is string lastErr)
        {
            WriteLine(lastErr, isError: true);
        }

        return _completion ?? throw new WSManTransportException("The receive pump ended without reporting a result.");
    }

    private void WriteItem(OutputItem item)
    {
        Debug.Assert(_stderr is not null);

        if (item.Completion is not null)
        {
            _completion = item.Completion;
            return;
        }

        bool isError = item.Stream == "stderr";
        if (!isError && _stdout is null)
        {
            // Each chunk as the server returned it, enumerating byte by byte would cost a pipeline object per byte.
            if (item.Data.Length > 0)
            {
                WriteObject(item.Data, enumerateCollection: false);
            }
            return;
        }

        WinRSLineDecoder decoder = isError ? _stderr : _stdout!;
        foreach (string line in decoder.Decode(item.Data))
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
        ErrorRecord record = _firstError
            ? new(new RemoteException(line), "NativeCommandError", ErrorCategory.NotSpecified, line)
            : new(new RemoteException(line), "NativeCommandErrorMessage", ErrorCategory.NotSpecified, null);
        record.PreserveInvocationInfoOnce = true;
        _firstError = false;
        WriteError(record);
    }

    private sealed record OutputItem(string Stream, byte[] Data, WinRSReceiveCompletion? Completion);

    /// <summary>Hands the pump's output from its thread to the pipeline thread.</summary>
    private sealed class OutputQueue : IWinRSOutputSink, IDisposable
    {
        private readonly BlockingCollection<OutputItem> _items = new();

        public IEnumerable<OutputItem> GetConsumingEnumerable(CancellationToken token)
            => _items.GetConsumingEnumerable(token);

        public bool TryTake([NotNullWhen(true)] out OutputItem? item) => _items.TryTake(out item);

        public void OnData(string stream, byte[] data)
        {
            TryAdd(new(stream, data, null));
        }

        public void OnCompleted(WinRSReceiveCompletion completion)
        {
            TryAdd(new("", Array.Empty<byte>(), completion));
        }

        private void TryAdd(OutputItem item)
        {
            try
            {
                _items.Add(item);
            }
            catch (Exception e) when (e is ObjectDisposedException or InvalidOperationException)
            {
                // The cmdlet has stopped consuming and is tearing the shell down, the output has nowhere to go.
            }
        }

        public void Dispose()
        {
            _items.Dispose();
        }
    }
}
