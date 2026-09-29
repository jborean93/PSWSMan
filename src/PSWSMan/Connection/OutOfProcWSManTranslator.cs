using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;
using System.Threading;
using System.Xml.Linq;
using PSWSMan.Lib;

namespace PSWSMan.Connection;

/// <summary>Translates the OutOfProc PSRP packets PowerShell writes into WSMan shell operations and back.</summary>
/// <remarks>
/// <para>
/// PowerShell's custom transport API speaks the OutOfProc protocol, one XML packet per line over a single duplex
/// channel, and expects each packet to be acknowledged. WSMan instead has an operation for each step. The client
/// packets map to WSMan as follows:
/// </para>
/// <list type="bullet">
///   <item>The session <c>Data</c> up to the end of the INIT_RUNSPACEPOOL message is the Create with the fragments
///   as the creationXml.</item>
///   <item>Further session <c>Data</c> is a Send to the shell on stdin or pr.</item>
///   <item><c>Command</c> is acknowledged straight away, the <c>Data</c> for it up to the end of its first message
///   is the Command request with the fragments as the argument, later ones are a Send to the command. The first
///   message is usually CREATE_PIPELINE but Enter-PSSession and implicit remoting open a command with
///   GET_COMMAND_METADATA.</item>
///   <item><c>Signal</c> is the PowerShell Ctrl+C signal and <c>Close</c> the terminate signal for a command, or
///   the Delete of the shell for the session.</item>
/// </list>
/// <para>
/// PowerShell splits its fragment stream into OutOfProc packets of at most 32KiB and waits for the ack of each
/// before writing the next. The packets that make up the opening message are acked straight away and gathered so
/// the whole message goes in the one Create or Command, as the WSMan client does. Only what does not fit in the
/// envelope is sent separately.
/// </para>
/// <para>
/// Receive pumps on the shell and each command turn the stdout of every Receive response into <c>Data</c> packets.
/// The client packets are handled one at a time in the order written on a dedicated thread so the writer never
/// blocks PowerShell on the network.
/// </para>
/// <para>
/// The WSMan operations themselves go through <see cref="IWSManShellOperations"/>. Nothing here references
/// System.Management.Automation, PowerShell's side is only the text writer and the two callbacks.
/// </para>
/// </remarks>
internal sealed class OutOfProcWSManTranslator : IDisposable
{
    // Room left in the envelope for the headers, options and body around the base64 payload.
    private const int EnvelopeOverhead = 4096;

    // Servers newer than protocol 2.1 (Windows 8/Server 2012) default to 500KiB envelopes, the same adjustment
    // PowerShell's WSMan client makes once it has the server's SESSION_CAPABILITY.
    private const int ExtendedMaxEnvelopeSize = 500 << 10;
    private static readonly Version s_extendedEnvelopeProtocol = new(2, 1);

    // How much shell output to look through for the server's SESSION_CAPABILITY before giving up on it.
    private const int MaxServerOpeningSize = 1 << 20;

    private readonly IWSManShellOperations _shell;
    private readonly Guid _runspacePoolId;
    private readonly bool _noMachineProfile;
    private readonly Action<string> _onPacket;
    private readonly Action<Exception> _onError;
    private readonly Action<string>? _trace;
    private readonly BlockingCollection<string> _requests = new();
    private readonly Dictionary<Guid, PipelineState> _pipelines = new();
    private readonly Thread _thread;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly ManualResetEventSlim _firstReceive = new();
    private readonly OpeningMessage _sessionOpening = new(PSRPMessageType.InitRunspacePool);
    private MemoryStream? _serverOpening = new();
    private bool _shellCreated;
    private readonly CancellationTokenRegistration _abortRegistration;
    private volatile bool _closing;
    private int _disposed;

    public OutOfProcWSManTranslator(
        IWSManShellOperations shell,
        Guid runspacePoolId,
        bool noMachineProfile,
        Action<string> onPacket,
        Action<Exception> onError,
        Action<string>? trace,
        CancellationToken abortToken = default)
    {
        _shell = shell;
        _runspacePoolId = runspacePoolId;
        _noMachineProfile = noMachineProfile;
        _onPacket = onPacket;
        _onError = onError;
        _trace = trace;

        Writer = new PacketWriter(_requests);
        _thread = new Thread(Run)
        {
            IsBackground = true,
            Name = $"PSWSMan OutOfProc Translator {runspacePoolId}",
        };
        _thread.Start();

        _abortRegistration = abortToken.Register(Abort);
    }

    /// <summary>The writer PowerShell sends the client packets to, one per line.</summary>
    public TextWriter Writer { get; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        _closing = true;
        _abortRegistration.Unregister();
        _lifetime.Cancel();
        _requests.CompleteAdding();

        _shell.Dispose();
    }

    /// <summary>Fails the connection and stops everything in flight, like a Create still connecting.</summary>
    private void Abort()
    {
        if (_closing)
        {
            return;
        }

        Trace("aborting");
        _onError(new OperationCanceledException("The connection was stopped before it was opened."));
        Dispose();
    }

    private void Run()
    {
        try
        {
            foreach (string line in _requests.GetConsumingEnumerable())
            {
                try
                {
                    Process(line);
                }
                catch (Exception e)
                {
                    Trace("failed to process the last sent packet", e);
                    if (!_closing)
                    {
                        _onError(e);
                    }
                }
            }
        }
        catch (Exception e)
        {
            // Nothing may escape this thread, like the error callback itself failing, or it takes the process down.
            Trace("translator thread failed", e);
        }
    }

    private void Process(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return;
        }

        TracePacket("Sent", line);
        XElement packet = XElement.Parse(line);
        string rawGuid = packet.Attribute("PSGuid")?.Value
            ?? throw new InvalidDataException($"OutOfProc packet {packet.Name.LocalName} has no PSGuid");
        Guid psGuid = Guid.Parse(rawGuid);

        switch (packet.Name.LocalName)
        {
            case "Data":
                string stream = packet.Attribute("Stream")?.Value == "PromptResponse" ? "pr" : "stdin";
                byte[] data = Convert.FromBase64String(packet.Value);
                if (psGuid == Guid.Empty)
                {
                    OnSessionData(stream, data);
                }
                else
                {
                    OnPipelineData(psGuid, stream, data);
                }
                break;

            case "Command":
                _pipelines[psGuid] = new PipelineState(psGuid);
                Emit(CreatePacket("CommandAck", psGuid));
                break;

            case "Signal":
                if (_pipelines.TryGetValue(psGuid, out PipelineState? toSignal) && toSignal.Created)
                {
                    _shell.Signal(SignalCode.PSCtrlC, psGuid);
                }
                Emit(CreatePacket("SignalAck", psGuid));
                break;

            case "Close":
                if (psGuid == Guid.Empty)
                {
                    OnSessionClose();
                }
                else
                {
                    OnPipelineClose(psGuid);
                }
                break;

            default:
                throw new InvalidDataException($"Unknown OutOfProc packet {packet.Name.LocalName}");
        }
    }

    private void OnSessionData(string stream, byte[] data)
    {
        if (_sessionOpening.IsComplete)
        {
            WaitForFirstReceive();
            SendChunked(stream, data, null);
            Emit(CreatePacket("DataAck", Guid.Empty));
            return;
        }

        _sessionOpening.Append(data, Trace);
        while (true)
        {
            // Once the shell exists the rest waits for the first Receive, by which point the server's
            // SESSION_CAPABILITY may have raised the envelope size for the remaining chunks.
            if (_shellCreated)
            {
                WaitForFirstReceive();
            }
            if (!_sessionOpening.TryTakeChunk(MaxPayloadSize, out byte[]? chunk))
            {
                break;
            }

            if (_shellCreated)
            {
                _shell.Send("stdin", chunk, null);
            }
            else
            {
                CreateShell(chunk);
            }
        }
        Emit(CreatePacket("DataAck", Guid.Empty));
    }

    private void CreateShell(byte[] creationData)
    {
        XElement creationXml = new(WSManNamespace.pwsh + "creationXml", Convert.ToBase64String(creationData));
        OptionSet shellOptions = new();
        shellOptions.Add("protocolversion", "2.3", new() { { "MustComply", "true" } });
        if (_noMachineProfile)
        {
            shellOptions.Add("WINRS_NOPROFILE", "1", new() { { "MustComply", "true" } });
        }

        Trace($"creating shell with {creationData.Length} bytes of opening fragments");
        _shell.Open("stdin pr", "stdout", _runspacePoolId, creationXml, shellOptions);
        _shellCreated = true;
        _shell.StartReceive(new ReceiveSink(this, null), null, CancellationToken.None);
    }

    private void OnPipelineData(Guid commandId, string stream, byte[] data)
    {
        if (!_pipelines.TryGetValue(commandId, out PipelineState? pipeline))
        {
            throw new InvalidDataException($"OutOfProc Data for unknown command {commandId}");
        }

        if (pipeline.Opening.IsComplete)
        {
            SendChunked(stream, data, commandId);
            Emit(CreatePacket("DataAck", commandId));
            return;
        }

        pipeline.Opening.Append(data, Trace);
        while (pipeline.Opening.TryTakeChunk(MaxPayloadSize, out byte[]? chunk))
        {
            if (pipeline.Created)
            {
                _shell.Send("stdin", chunk, commandId);
            }
            else
            {
                Trace($"creating command {commandId} with {chunk.Length} bytes of opening fragments");
                _shell.RunCommand(commandId, Convert.ToBase64String(chunk));
                pipeline.Created = true;
                _shell.StartReceive(new ReceiveSink(this, pipeline), commandId, pipeline.Receive.Token);
            }
        }
        Emit(CreatePacket("DataAck", commandId));
    }

    /// <summary>The most raw bytes whose base64 fits in one envelope.</summary>
    private int MaxPayloadSize => (_shell.MaxEnvelopeSize - EnvelopeOverhead) / 4 * 3;

    private void SendChunked(string stream, ReadOnlySpan<byte> data, Guid? commandId)
    {
        int chunkSize = MaxPayloadSize;
        do
        {
            ReadOnlySpan<byte> chunk = data[..Math.Min(chunkSize, data.Length)];
            _shell.Send(stream, chunk.ToArray(), commandId);
            data = data[chunk.Length..];
        }
        while (data.Length > 0);
    }

    /// <summary>
    /// Waits until the server has answered the shell's first Receive, it must not get any input for the shell
    /// before then.
    /// </summary>
    private void WaitForFirstReceive()
    {
        if (!_firstReceive.IsSet)
        {
            Trace("waiting for the first shell Receive response");
            _firstReceive.Wait(_lifetime.Token);
        }
    }

    private void OnPipelineClose(Guid commandId)
    {
        if (_pipelines.Remove(commandId, out PipelineState? pipeline))
        {
            pipeline.Closed = true;
            try
            {
                if (pipeline.Created)
                {
                    _shell.Signal(SignalCode.Terminate, commandId);
                }
            }
            catch (Exception e)
            {
                // The command is finished with either way, PowerShell only waits for the ack.
                Trace($"terminate for {commandId} failed", e);
            }
            finally
            {
                pipeline.Receive.Cancel();
            }
        }

        Emit(CreatePacket("CloseAck", commandId));
    }

    private void OnSessionClose()
    {
        _closing = true;
        try
        {
            _shell.Close();
        }
        catch (Exception e)
        {
            // The shell is aborted by Close on failure, PowerShell only waits for the ack.
            Trace("shell delete failed", e);
        }

        Emit(CreatePacket("CloseAck", Guid.Empty));
    }

    private void OnReceiveData(PipelineState? pipeline, byte[] data)
    {
        if (pipeline?.Closed == true)
        {
            return;
        }

        Guid psGuid = pipeline?.CommandId ?? Guid.Empty;
        Emit($"<Data Stream='Default' PSGuid='{psGuid}'>{Convert.ToBase64String(data)}</Data>");
        if (pipeline is null)
        {
            CheckServerCapability(data);
            _firstReceive.Set();
        }
    }

    /// <summary>Raises the envelope size once the server's SESSION_CAPABILITY shows it supports it.</summary>
    /// <remarks>Only called from the shell's receive pump thread.</remarks>
    private void CheckServerCapability(byte[] data)
    {
        if (_serverOpening is null)
        {
            return;
        }

        try
        {
            _serverOpening.Write(data);
            if (!PSRPFragment.TryGetMessage(_serverOpening.GetBuffer().AsSpan(0, (int)_serverOpening.Length),
                PSRPMessageType.SessionCapability, out byte[]? capability))
            {
                if (_serverOpening.Length > MaxServerOpeningSize)
                {
                    Trace("no SESSION_CAPABILITY in the shell output, keeping the envelope size");
                    _serverOpening = null;
                }
                return;
            }
            _serverOpening = null;

            Version protocolVersion = PSRPMessage.GetProtocolVersion(capability);
            int current = _shell.MaxEnvelopeSize;
            Trace($"server protocol version {protocolVersion}, max envelope size {current}");
            if (protocolVersion > s_extendedEnvelopeProtocol && current < ExtendedMaxEnvelopeSize)
            {
                Trace($"raising max envelope size to {ExtendedMaxEnvelopeSize}");
                _shell.UpdateMaxEnvelopeSize(ExtendedMaxEnvelopeSize);
            }
        }
        catch (FormatException e)
        {
            Trace("failed to read the server SESSION_CAPABILITY, keeping the envelope size", e);
            _serverOpening = null;
        }
    }

    private void OnReceiveCompleted(PipelineState? pipeline, WinRSReceiveCompletion completion)
    {
        if (pipeline is null)
        {
            // Nothing more will come so nothing should wait for it.
            _firstReceive.Set();
        }

        if (completion.Reason is WinRSReceiveReason.Done or WinRSReceiveReason.Cancelled || _closing ||
            pipeline?.Closed == true)
        {
            return;
        }

        _onError(completion.Error
            ?? new WSManTransportException($"The receive pump stopped unexpectedly ({completion.Reason})."));
    }

    private void Emit(string packet)
    {
        TracePacket("Received", packet);
        _onPacket(packet);
    }

    // The session and command packets are told apart by PowerShell by this exact PSGuid attribute text.
    private static string CreatePacket(string name, Guid psGuid) => $"<{name} PSGuid='{psGuid}' />";

    /// <summary>Traces a whole OutOfProc packet, Sent by PowerShell or Received by it from the translator.</summary>
    /// <remarks>
    /// Every packet line starts with the same prefix so they can be filtered in or out of a trace, the packet is
    /// written as is on the one line.
    /// </remarks>
    private void TracePacket(string direction, string packet)
    {
        if (_trace is null)
        {
            return;
        }

        try
        {
            _trace($"PSWSMan OutOfProc Packet [{_runspacePoolId}] {direction}: {packet}");
        }
        catch (Exception)
        {
            // Tracing is best effort.
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
            _trace($"PSWSMan OutOfProc [{_runspacePoolId}]: {message}{suffix}");
        }
        catch (Exception)
        {
            // Tracing is best effort.
        }
    }

    private sealed class PipelineState
    {
        public PipelineState(Guid commandId)
        {
            CommandId = commandId;
        }

        public Guid CommandId { get; }

        // Whatever the first message is opens the command, CREATE_PIPELINE or GET_COMMAND_METADATA.
        public OpeningMessage Opening { get; } = new(null);

        public bool Created { get; set; }

        public volatile bool Closed;

        public CancellationTokenSource Receive { get; } = new();
    }

    /// <summary>
    /// Gathers the fragments of the message that opens a shell or command so they go out in as few envelopes as
    /// possible, a full envelope at a time until the end of the message is seen.
    /// </summary>
    private sealed class OpeningMessage
    {
        private readonly int? _messageType;
        // The whole stream is kept from its start as the end of the message can only be found by walking the
        // fragments from the first one.
        private MemoryStream? _data = new();
        private int _taken;
        private bool _hasEnd;

        /// <param name="messageType">The message that ends the opening, null for the first message of any type.</param>
        public OpeningMessage(int? messageType)
        {
            _messageType = messageType;
        }

        /// <summary>Whether the whole message has been gathered and handed out.</summary>
        public bool IsComplete => _data is null;

        public void Append(byte[] data, Action<string, Exception?> trace)
        {
            _data!.Write(data);
            try
            {
                ReadOnlySpan<byte> gathered = _data.GetBuffer().AsSpan(0, (int)_data.Length);
                _hasEnd = _messageType is int messageType
                    ? PSRPFragment.ContainsCompleteMessage(gathered, messageType)
                    : PSRPFragment.ContainsCompleteFirstMessage(gathered);
            }
            catch (FormatException e)
            {
                // Better to send what there is and let the server reject it than wait for an end that never comes.
                trace("opening fragments could not be read", e);
                _hasEnd = true;
            }
        }

        /// <summary>Takes the next envelope's worth, or the rest once the end of the message is in.</summary>
        public bool TryTakeChunk(int maxSize, [NotNullWhen(true)] out byte[]? chunk)
        {
            chunk = null;
            if (_data is null)
            {
                return false;
            }

            // Once the end is in the loop below takes everything and clears the data, so nothing pending here
            // means the end has not arrived yet.
            int pending = (int)_data.Length - _taken;
            if (pending == 0 || (!_hasEnd && pending < maxSize))
            {
                return false;
            }

            int length = Math.Min(pending, maxSize);
            chunk = _data.GetBuffer().AsSpan(_taken, length).ToArray();
            _taken += length;
            if (_hasEnd && _taken == _data.Length)
            {
                _data = null;
            }
            return true;
        }
    }

    private sealed class ReceiveSink : IWinRSOutputSink
    {
        private readonly OutOfProcWSManTranslator _owner;
        private readonly PipelineState? _pipeline;

        public ReceiveSink(OutOfProcWSManTranslator owner, PipelineState? pipeline)
        {
            _owner = owner;
            _pipeline = pipeline;
        }

        public void OnData(string stream, byte[] data) => _owner.OnReceiveData(_pipeline, data);

        public void OnCompleted(WinRSReceiveCompletion completion) => _owner.OnReceiveCompleted(_pipeline, completion);
    }

    /// <summary>Queues each line PowerShell writes as one client packet.</summary>
    private sealed class PacketWriter : TextWriter
    {
        private readonly BlockingCollection<string> _requests;
        private readonly StringBuilder _partial = new();

        public PacketWriter(BlockingCollection<string> requests)
        {
            _requests = requests;
        }

        public override Encoding Encoding => Encoding.UTF8;

        public override void WriteLine(string? value)
        {
            lock (_partial)
            {
                _partial.Append(value);
                Queue();
            }
        }

        public override void Write(char value)
        {
            lock (_partial)
            {
                if (value == '\n')
                {
                    Queue();
                }
                else if (value != '\r')
                {
                    _partial.Append(value);
                }
            }
        }

        private void Queue()
        {
            string line = _partial.ToString();
            _partial.Clear();
            try
            {
                _requests.Add(line);
            }
            catch (InvalidOperationException e)
            {
                // PowerShell treats an IOException from the writer as the connection being gone.
                throw new IOException("The PSWSMan transport has been closed.", e);
            }
        }
    }
}
