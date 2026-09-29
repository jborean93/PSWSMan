using PSWSMan.Lib;
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace PSWSMan.Connection.Tests;

/// <summary>Records the WSMan operations the translator asks for instead of sending them.</summary>
internal sealed class FakeShellOperations : IWSManShellOperations
{
    private readonly ConcurrentDictionary<Guid, IWinRSOutputSink> _sinks = new();

    /// <summary>Every operation in the order it was asked for, like "Open 120" or "Send stdin 30 &lt;id&gt;".</summary>
    public BlockingCollection<string> Calls { get; } = new();

    public ConcurrentDictionary<Guid, CancellationToken> ReceiveTokens { get; } = new();

    /// <summary>Returns an exception for an operation name that should fail.</summary>
    public Func<string, Exception?>? Fail { get; set; }

    public XElement? OpenOptions { get; private set; }

    public string? OpenCreationXml { get; private set; }

    public List<string> RunCommandArguments { get; } = new();

    public int MaxEnvelopeSize { get; set; } = 153600;

    public bool IsDisposed { get; private set; }

    public void UpdateMaxEnvelopeSize(int size) => MaxEnvelopeSize = size;

    public void Open(string inputStreams, string outputStreams, Guid shellId, XElement extra, OptionSet options)
    {
        OpenOptions = options.ToXml();
        OpenCreationXml = extra.Value;
        Record("Open", $"Open {Convert.FromBase64String(extra.Value).Length}");
    }

    public void RunCommand(Guid commandId, string argument)
    {
        RunCommandArguments.Add(argument);
        Record("RunCommand", $"RunCommand {commandId} {Convert.FromBase64String(argument).Length}");
    }

    public void Send(string stream, byte[] data, Guid? commandId)
        => Record("Send", $"Send {stream} {data.Length} {commandId?.ToString() ?? "shell"}");

    public void Signal(string code, Guid commandId)
        => Record("Signal", $"Signal {code[(code.LastIndexOf('/') + 1)..]} {commandId}");

    public void StartReceive(IWinRSOutputSink sink, Guid? commandId, CancellationToken cancellationToken)
    {
        _sinks[commandId ?? Guid.Empty] = sink;
        ReceiveTokens[commandId ?? Guid.Empty] = cancellationToken;
        Record("StartReceive", $"StartReceive {commandId?.ToString() ?? "shell"}");
    }

    public void Close() => Record("Close", "Close");

    public void Dispose() => IsDisposed = true;

    /// <summary>The receive sink of the shell or a command, as the receive pump would call it.</summary>
    public IWinRSOutputSink Sink(Guid? commandId = null) => _sinks[commandId ?? Guid.Empty];

    private void Record(string operation, string call)
    {
        Calls.Add(call);
        if (Fail?.Invoke(operation) is Exception e)
        {
            throw e;
        }
    }
}

/// <summary>A translator on a fake shell with everything it emits collected.</summary>
internal sealed class TranslatorHarness : IDisposable
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    public TranslatorHarness(bool noMachineProfile = false, CancellationToken abortToken = default,
        Action<string>? trace = null, Action<Exception>? onError = null)
    {
        Translator = new(Shell, RunspacePoolId, noMachineProfile, Packets.Add, onError ?? Errors.Add, trace,
            abortToken);
    }

    public Guid RunspacePoolId { get; } = Guid.NewGuid();

    public FakeShellOperations Shell { get; } = new();

    public BlockingCollection<string> Packets { get; } = new();

    public BlockingCollection<Exception> Errors { get; } = new();

    public OutOfProcWSManTranslator Translator { get; }

    public void Write(string packet) => Translator.Writer.WriteLine(packet);

    public string NextPacket() => Take(Packets);

    public string NextCall() => Take(Shell.Calls);

    public Exception NextError() => Take(Errors);

    /// <summary>Waits a short time to show nothing more arrives.</summary>
    public static bool IsIdle<T>(BlockingCollection<T> items)
        => !items.TryTake(out _, TimeSpan.FromMilliseconds(300));

    /// <summary>Opens the shell with a small opening message and delivers the first Receive.</summary>
    public void OpenShell()
    {
        Write(OutOfProcPackets.Data(Guid.Empty, Psrp.Opening(100)));
        NextCall();
        NextCall();
        Shell.Sink().OnData("stdout", [0]);
        NextPacket();
        NextPacket();
    }

    /// <summary>Creates a command with a small CREATE_PIPELINE message.</summary>
    public Guid CreateCommand()
    {
        Guid commandId = Guid.NewGuid();
        Write(OutOfProcPackets.Create("Command", commandId));
        NextPacket();
        Write(OutOfProcPackets.Data(commandId, Psrp.Fragments(7, Psrp.Message(PSRPMessageType.CreatePipeline, "pipe"))));
        NextCall();
        NextCall();
        NextPacket();
        return commandId;
    }

    public void Dispose() => Translator.Dispose();

    private static T Take<T>(BlockingCollection<T> items)
        => items.TryTake(out T? item, Timeout) ? item : throw new TimeoutException("Nothing arrived in time");
}

/// <summary>Builds the OutOfProc packets PowerShell writes and the translator emits.</summary>
internal static class OutOfProcPackets
{
    public static string Data(Guid psGuid, byte[] data, string stream = "Default")
        => $"<Data Stream='{stream}' PSGuid='{psGuid}'>{Convert.ToBase64String(data)}</Data>";

    public static string Create(string name, Guid psGuid) => $"<{name} PSGuid='{psGuid}' />";
}

/// <summary>Builds PSRP fragment streams.</summary>
internal static class Psrp
{
    public static byte[] Message(int messageType, string data)
    {
        byte[] header = new byte[40];
        BinaryPrimitives.WriteInt32LittleEndian(header, 0x00000002);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(4), messageType);
        return [.. header, .. Encoding.UTF8.GetBytes(data)];
    }

    /// <summary>Splits a message into fragments with blobs of at most the given size.</summary>
    public static byte[] Fragments(long objectId, byte[] message, int size = int.MaxValue)
    {
        List<byte> result = new();
        int offset = 0;
        long fragmentId = 0;
        do
        {
            int length = Math.Min(size, message.Length - offset);
            byte[] header = new byte[21];
            BinaryPrimitives.WriteInt64BigEndian(header, objectId);
            BinaryPrimitives.WriteInt64BigEndian(header.AsSpan(8), fragmentId++);
            header[16] = (byte)((offset == 0 ? 1 : 0) | (offset + length == message.Length ? 2 : 0));
            BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(17), length);
            result.AddRange(header);
            result.AddRange(message.AsSpan(offset, length).ToArray());
            offset += length;
        }
        while (offset < message.Length);

        return result.ToArray();
    }

    /// <summary>The SESSION_CAPABILITY and INIT_RUNSPACEPOOL messages that open a runspace pool.</summary>
    public static byte[] Opening(int size)
        => [
            .. Fragments(1, Message(PSRPMessageType.SessionCapability, "<Obj />")),
            .. Fragments(2, Message(PSRPMessageType.InitRunspacePool, new string('i', size))),
        ];

    public static byte[] Capability(string protocolVersion)
        => Fragments(1, Message(PSRPMessageType.SessionCapability,
            $"<Obj RefId=\"0\"><MS><Version N=\"protocolversion\">{protocolVersion}</Version></MS></Obj>"));
}

public class OutOfProcWSManTranslatorTests
{
    // The envelope size that leaves room for 300 bytes of payload after the overhead the translator reserves.
    private const int SmallEnvelope = 4096 + 400;

    private static string Ack(string name, Guid psGuid) => OutOfProcPackets.Create(name, psGuid);

    [Test]
    public async Task Opening_CreatesShellAndAcksAfterFirstReceive()
    {
        using TranslatorHarness h = new();
        byte[] opening = Psrp.Opening(100);

        h.Write(OutOfProcPackets.Data(Guid.Empty, opening));

        await Assert.That(h.NextCall()).IsEqualTo($"Open {opening.Length}");
        await Assert.That(h.NextCall()).IsEqualTo("StartReceive shell");
        await Assert.That(Convert.FromBase64String(h.Shell.OpenCreationXml!)).IsEquivalentTo(opening);
        await Assert.That(h.Shell.OpenOptions!.ToString()).Contains("protocolversion");
        await Assert.That(h.Shell.OpenOptions!.ToString()).DoesNotContain("WINRS_NOPROFILE");
        // WSMan must have answered the first Receive before the shell gets more input, so no ack yet.
        await Assert.That(TranslatorHarness.IsIdle(h.Packets)).IsTrue();

        h.Shell.Sink().OnData("stdout", [1, 2, 3]);

        await Assert.That(h.NextPacket()).IsEqualTo(OutOfProcPackets.Data(Guid.Empty, [1, 2, 3]));
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("DataAck", Guid.Empty));
    }

    [Test]
    public async Task Opening_SetsNoMachineProfile()
    {
        using TranslatorHarness h = new(noMachineProfile: true);

        h.Write(OutOfProcPackets.Data(Guid.Empty, Psrp.Opening(10)));
        h.NextCall();

        await Assert.That(h.Shell.OpenOptions!.ToString()).Contains("WINRS_NOPROFILE");
    }

    [Test]
    public async Task Opening_GathersPacketsUntilTheMessageEnds()
    {
        using TranslatorHarness h = new();
        byte[] opening = Psrp.Opening(100);
        int half = opening.Length / 2;

        h.Write(OutOfProcPackets.Data(Guid.Empty, opening[..half]));

        await Assert.That(h.NextPacket()).IsEqualTo(Ack("DataAck", Guid.Empty));
        await Assert.That(TranslatorHarness.IsIdle(h.Shell.Calls)).IsTrue();

        h.Write(OutOfProcPackets.Data(Guid.Empty, opening[half..]));

        await Assert.That(h.NextCall()).IsEqualTo($"Open {opening.Length}");
    }

    [Test]
    public async Task Opening_SendsWhatDoesNotFitAfterTheFirstReceive()
    {
        using TranslatorHarness h = new();
        h.Shell.MaxEnvelopeSize = SmallEnvelope;
        byte[] opening = Psrp.Opening(700);

        h.Write(OutOfProcPackets.Data(Guid.Empty, opening));

        await Assert.That(h.NextCall()).IsEqualTo("Open 300");
        await Assert.That(h.NextCall()).IsEqualTo("StartReceive shell");
        await Assert.That(TranslatorHarness.IsIdle(h.Shell.Calls)).IsTrue();

        h.Shell.Sink().OnData("stdout", [0]);

        int sent = 300;
        while (sent < opening.Length)
        {
            string call = h.NextCall();
            await Assert.That(call).StartsWith("Send stdin ");
            sent += int.Parse(call.Split(' ')[2]);
        }
        await Assert.That(sent).IsEqualTo(opening.Length);
        h.NextPacket();
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("DataAck", Guid.Empty));
    }

    [Test]
    public async Task Opening_SendsFragmentsItCannotReadStraightAway()
    {
        using TranslatorHarness h = new();
        byte[] invalid = Psrp.Opening(10);
        BinaryPrimitives.WriteInt32BigEndian(invalid.AsSpan(17), -1);

        h.Write(OutOfProcPackets.Data(Guid.Empty, invalid));

        await Assert.That(h.NextCall()).IsEqualTo($"Open {invalid.Length}");
    }

    [Test]
    [Arguments("2.3", 512000)]
    [Arguments("2.2", 512000)]
    [Arguments("2.1", 153600)]
    [Arguments("2.0", 153600)]
    public async Task ServerCapability_RaisesEnvelopeForNewerProtocols(string version, int expected)
    {
        using TranslatorHarness h = new();
        h.Write(OutOfProcPackets.Data(Guid.Empty, Psrp.Opening(10)));
        h.NextCall();
        h.NextCall();

        h.Shell.Sink().OnData("stdout", Psrp.Capability(version));

        h.NextPacket();
        await Assert.That(h.Shell.MaxEnvelopeSize).IsEqualTo(expected);
    }

    [Test]
    public async Task ServerCapability_ReadsItAcrossReceives()
    {
        using TranslatorHarness h = new();
        h.Write(OutOfProcPackets.Data(Guid.Empty, Psrp.Opening(10)));
        h.NextCall();
        h.NextCall();
        byte[] capability = Psrp.Capability("2.3");

        h.Shell.Sink().OnData("stdout", capability[..30]);
        h.NextPacket();
        await Assert.That(h.Shell.MaxEnvelopeSize).IsEqualTo(153600);

        h.Shell.Sink().OnData("stdout", capability[30..]);
        h.NextPacket();
        await Assert.That(h.Shell.MaxEnvelopeSize).IsEqualTo(512000);
    }

    [Test]
    public async Task ServerCapability_KeepsEnvelopeWhenItCannotBeRead()
    {
        using TranslatorHarness h = new();
        h.Write(OutOfProcPackets.Data(Guid.Empty, Psrp.Opening(10)));
        h.NextCall();
        h.NextCall();

        h.Shell.Sink().OnData("stdout", Psrp.Fragments(1, Psrp.Message(PSRPMessageType.SessionCapability, "<Obj>")));
        h.NextPacket();
        // Once given up a valid one is no longer looked for.
        h.Shell.Sink().OnData("stdout", Psrp.Capability("2.3"));
        h.NextPacket();

        await Assert.That(h.Shell.MaxEnvelopeSize).IsEqualTo(153600);
    }

    [Test]
    public async Task ServerCapability_GivesUpAfterTooMuchOutput()
    {
        using TranslatorHarness h = new();
        h.Write(OutOfProcPackets.Data(Guid.Empty, Psrp.Opening(10)));
        h.NextCall();
        h.NextCall();

        h.Shell.Sink().OnData("stdout", Psrp.Fragments(1, Psrp.Message(0x00041002, new string('o', 1100000))));
        h.NextPacket();
        h.Shell.Sink().OnData("stdout", Psrp.Capability("2.3"));
        h.NextPacket();

        await Assert.That(h.Shell.MaxEnvelopeSize).IsEqualTo(153600);
    }

    [Test]
    [Arguments("Default", "stdin")]
    [Arguments("PromptResponse", "pr")]
    public async Task SessionData_IsSentOnTheStream(string stream, string expected)
    {
        using TranslatorHarness h = new();
        h.OpenShell();

        h.Write(OutOfProcPackets.Data(Guid.Empty, [1, 2, 3], stream));

        await Assert.That(h.NextCall()).IsEqualTo($"Send {expected} 3 shell");
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("DataAck", Guid.Empty));
    }

    [Test]
    public async Task SessionData_IsSentInEnvelopeSizedChunks()
    {
        using TranslatorHarness h = new();
        h.OpenShell();
        h.Shell.MaxEnvelopeSize = SmallEnvelope;

        h.Write(OutOfProcPackets.Data(Guid.Empty, new byte[700]));

        await Assert.That(h.NextCall()).IsEqualTo("Send stdin 300 shell");
        await Assert.That(h.NextCall()).IsEqualTo("Send stdin 300 shell");
        await Assert.That(h.NextCall()).IsEqualTo("Send stdin 100 shell");
    }

    [Test]
    public async Task Command_RunsWithTheCreatePipelineMessage()
    {
        using TranslatorHarness h = new();
        h.OpenShell();
        Guid commandId = Guid.NewGuid();
        byte[] createPipeline = Psrp.Fragments(7, Psrp.Message(PSRPMessageType.CreatePipeline, "pipeline"), 20);

        h.Write(OutOfProcPackets.Create("Command", commandId));
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("CommandAck", commandId));

        h.Write(OutOfProcPackets.Data(commandId, createPipeline[..30]));
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("DataAck", commandId));
        await Assert.That(TranslatorHarness.IsIdle(h.Shell.Calls)).IsTrue();

        h.Write(OutOfProcPackets.Data(commandId, createPipeline[30..]));
        await Assert.That(h.NextCall()).IsEqualTo($"RunCommand {commandId} {createPipeline.Length}");
        await Assert.That(h.NextCall()).IsEqualTo($"StartReceive {commandId}");
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("DataAck", commandId));
        await Assert.That(Convert.FromBase64String(h.Shell.RunCommandArguments[0])).IsEquivalentTo(createPipeline);

        h.Write(OutOfProcPackets.Data(commandId, [9, 9]));
        await Assert.That(h.NextCall()).IsEqualTo($"Send stdin 2 {commandId}");
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("DataAck", commandId));

        h.Shell.Sink(commandId).OnData("stdout", [4, 5]);
        await Assert.That(h.NextPacket()).IsEqualTo(OutOfProcPackets.Data(commandId, [4, 5]));
    }

    [Test]
    public async Task Command_OpensWithWhateverTheFirstMessageIs()
    {
        // Enter-PSSession and implicit remoting open a command with GET_COMMAND_METADATA instead of CREATE_PIPELINE.
        using TranslatorHarness h = new();
        h.OpenShell();
        Guid commandId = Guid.NewGuid();
        byte[] metadata = Psrp.Fragments(8, Psrp.Message(PSRPMessageType.GetCommandMetadata, "metadata"));

        h.Write(OutOfProcPackets.Create("Command", commandId));
        h.NextPacket();
        h.Write(OutOfProcPackets.Data(commandId, metadata));

        await Assert.That(h.NextCall()).IsEqualTo($"RunCommand {commandId} {metadata.Length}");
        await Assert.That(h.NextCall()).IsEqualTo($"StartReceive {commandId}");
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("DataAck", commandId));
    }

    [Test]
    public async Task Command_SendsWhatDoesNotFitInTheCommand()
    {
        using TranslatorHarness h = new();
        h.OpenShell();
        h.Shell.MaxEnvelopeSize = SmallEnvelope;
        Guid commandId = Guid.NewGuid();
        byte[] createPipeline = Psrp.Fragments(7, Psrp.Message(PSRPMessageType.CreatePipeline, new string('p', 600)));

        h.Write(OutOfProcPackets.Create("Command", commandId));
        h.NextPacket();
        h.Write(OutOfProcPackets.Data(commandId, createPipeline));

        await Assert.That(h.NextCall()).IsEqualTo($"RunCommand {commandId} 300");
        await Assert.That(h.NextCall()).IsEqualTo($"StartReceive {commandId}");
        await Assert.That(h.NextCall()).IsEqualTo($"Send stdin 300 {commandId}");
        await Assert.That(h.NextCall()).IsEqualTo($"Send stdin {createPipeline.Length - 600} {commandId}");
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("DataAck", commandId));
    }

    [Test]
    public async Task Command_DataForAnUnknownCommandIsAnError()
    {
        using TranslatorHarness h = new();

        h.Write(OutOfProcPackets.Data(Guid.NewGuid(), [1]));

        await Assert.That(h.NextError()).IsTypeOf<InvalidDataException>();
    }

    [Test]
    public async Task Signal_IsOnlySentOnceTheCommandExists()
    {
        using TranslatorHarness h = new();
        h.OpenShell();
        Guid pending = Guid.NewGuid();
        h.Write(OutOfProcPackets.Create("Command", pending));
        h.NextPacket();

        h.Write(OutOfProcPackets.Create("Signal", pending));
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("SignalAck", pending));
        await Assert.That(TranslatorHarness.IsIdle(h.Shell.Calls)).IsTrue();

        Guid commandId = h.CreateCommand();
        h.Write(OutOfProcPackets.Create("Signal", commandId));
        await Assert.That(h.NextCall()).IsEqualTo($"Signal crtl_c {commandId}");
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("SignalAck", commandId));
    }

    [Test]
    public async Task Close_TerminatesTheCommandAndStopsItsOutput()
    {
        using TranslatorHarness h = new();
        h.OpenShell();
        Guid commandId = h.CreateCommand();

        h.Write(OutOfProcPackets.Create("Close", commandId));

        await Assert.That(h.NextCall()).IsEqualTo($"Signal Terminate {commandId}");
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("CloseAck", commandId));
        await Assert.That(h.Shell.ReceiveTokens[commandId].IsCancellationRequested).IsTrue();

        // Output and a failed pump for a closed command are dropped.
        h.Shell.Sink(commandId).OnData("stdout", [1]);
        h.Shell.Sink(commandId).OnCompleted(new(WinRSReceiveReason.Failed, null, new IOException("gone")));
        await Assert.That(TranslatorHarness.IsIdle(h.Packets)).IsTrue();
        await Assert.That(TranslatorHarness.IsIdle(h.Errors)).IsTrue();
    }

    [Test]
    public async Task Close_AcksEvenWhenTerminateFails()
    {
        using TranslatorHarness h = new();
        h.OpenShell();
        Guid commandId = h.CreateCommand();
        h.Shell.Fail = operation => operation == "Signal" ? new IOException("broken") : null;

        h.Write(OutOfProcPackets.Create("Close", commandId));

        h.NextCall();
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("CloseAck", commandId));
        await Assert.That(TranslatorHarness.IsIdle(h.Errors)).IsTrue();
    }

    [Test]
    public async Task Close_AcksACommandThatWasNeverCreated()
    {
        using TranslatorHarness h = new();
        Guid commandId = Guid.NewGuid();

        h.Write(OutOfProcPackets.Create("Close", commandId));

        await Assert.That(h.NextPacket()).IsEqualTo(Ack("CloseAck", commandId));
        await Assert.That(TranslatorHarness.IsIdle(h.Shell.Calls)).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Close_DeletesTheShellAndAcks(bool deleteFails)
    {
        using TranslatorHarness h = new();
        h.OpenShell();
        if (deleteFails)
        {
            h.Shell.Fail = operation => operation == "Close" ? new IOException("broken") : null;
        }

        h.Write(OutOfProcPackets.Create("Close", Guid.Empty));

        await Assert.That(h.NextCall()).IsEqualTo("Close");
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("CloseAck", Guid.Empty));

        // The shell pump ending as the shell goes away is not an error.
        h.Shell.Sink().OnCompleted(new(WinRSReceiveReason.ShellClosed, null, new IOException("deleted")));
        await Assert.That(TranslatorHarness.IsIdle(h.Errors)).IsTrue();
    }

    [Test]
    public async Task Receive_FailureIsReported()
    {
        using TranslatorHarness h = new();
        h.OpenShell();
        IOException error = new("connection lost");

        h.Shell.Sink().OnCompleted(new(WinRSReceiveReason.Failed, null, error));

        await Assert.That(h.NextError()).IsSameReferenceAs(error);
    }

    [Test]
    public async Task Receive_FailureWithoutAnErrorIsReported()
    {
        using TranslatorHarness h = new();
        h.OpenShell();
        Guid commandId = h.CreateCommand();

        h.Shell.Sink(commandId).OnCompleted(new(WinRSReceiveReason.ShellClosed, null, null));

        await Assert.That(h.NextError()).IsTypeOf<WSManTransportException>();
    }

    [Test]
    [Arguments(nameof(WinRSReceiveReason.Done))]
    [Arguments(nameof(WinRSReceiveReason.Cancelled))]
    public async Task Receive_NormalEndIsNotAnError(string reasonName)
    {
        WinRSReceiveReason reason = Enum.Parse<WinRSReceiveReason>(reasonName);
        using TranslatorHarness h = new();
        h.OpenShell();
        Guid commandId = h.CreateCommand();

        h.Shell.Sink(commandId).OnCompleted(new(reason, 0, null));

        await Assert.That(TranslatorHarness.IsIdle(h.Errors)).IsTrue();
    }

    [Test]
    public async Task Receive_EndingBeforeAnyOutputReleasesTheOpening()
    {
        using TranslatorHarness h = new();
        h.Shell.MaxEnvelopeSize = SmallEnvelope;
        h.Write(OutOfProcPackets.Data(Guid.Empty, Psrp.Opening(700)));
        h.NextCall();
        h.NextCall();

        // A pump that ends without output must not leave the rest of the opening waiting forever.
        h.Shell.Sink().OnCompleted(new(WinRSReceiveReason.Failed, null, new IOException("refused")));

        await Assert.That(h.NextError()).IsTypeOf<IOException>();
        await Assert.That(h.NextCall()).StartsWith("Send stdin ");
    }

    [Test]
    public async Task Packets_BlankLinesAreIgnored()
    {
        using TranslatorHarness h = new();
        Guid commandId = Guid.NewGuid();

        h.Write("");
        h.Write(OutOfProcPackets.Create("Command", commandId));

        await Assert.That(h.NextPacket()).IsEqualTo(Ack("CommandAck", commandId));
        await Assert.That(TranslatorHarness.IsIdle(h.Errors)).IsTrue();
    }

    [Test]
    public async Task Packets_InvalidOnesAreErrors()
    {
        using TranslatorHarness h = new();

        h.Write($"<Unknown PSGuid='{Guid.Empty}' />");
        h.Write("<Command />");
        h.Write("<Command");

        await Assert.That(h.NextError()).IsTypeOf<InvalidDataException>();
        await Assert.That(h.NextError()).IsTypeOf<InvalidDataException>();
        await Assert.That(h.NextError()).IsTypeOf<XmlException>();
    }

    [Test]
    public async Task Writer_SplitsCharactersIntoPackets()
    {
        using TranslatorHarness h = new();
        Guid commandId = Guid.NewGuid();

        h.Translator.Writer.Write($"{OutOfProcPackets.Create("Command", commandId)}\r\n");

        await Assert.That(h.NextPacket()).IsEqualTo(Ack("CommandAck", commandId));
        await Assert.That(h.Translator.Writer.Encoding).IsEqualTo(Encoding.UTF8);
    }

    [Test]
    public async Task Writer_FailsOnceDisposed()
    {
        TranslatorHarness h = new();

        h.Dispose();
        h.Dispose();

        await Assert.That(h.Shell.IsDisposed).IsTrue();
        await Assert.That(() => h.Write(OutOfProcPackets.Create("Command", Guid.NewGuid()))).Throws<IOException>();
    }

    [Test]
    public async Task Dispose_StopsWaitingForTheFirstReceive()
    {
        TranslatorHarness h = new();
        h.Shell.MaxEnvelopeSize = SmallEnvelope;
        h.Write(OutOfProcPackets.Data(Guid.Empty, Psrp.Opening(700)));
        h.NextCall();
        h.NextCall();

        h.Dispose();

        await Assert.That(TranslatorHarness.IsIdle(h.Errors)).IsTrue();
        await Assert.That(TranslatorHarness.IsIdle(h.Shell.Calls)).IsTrue();
    }

    [Test]
    public async Task Abort_FailsTheConnectionAndDisposes()
    {
        using CancellationTokenSource abort = new();
        using TranslatorHarness h = new(abortToken: abort.Token);

        abort.Cancel();

        await Assert.That(h.NextError()).IsTypeOf<OperationCanceledException>();
        await Assert.That(h.Shell.IsDisposed).IsTrue();
    }

    [Test]
    public async Task Abort_DoesNothingOnceClosing()
    {
        using CancellationTokenSource abort = new();
        using TranslatorHarness h = new(abortToken: abort.Token);
        h.OpenShell();
        h.Write(OutOfProcPackets.Create("Close", Guid.Empty));
        h.NextCall();
        h.NextPacket();

        abort.Cancel();

        await Assert.That(TranslatorHarness.IsIdle(h.Errors)).IsTrue();
    }

    [Test]
    public async Task Trace_HasEveryPacketWithThePrefix()
    {
        ConcurrentQueue<string> lines = new();
        using TranslatorHarness h = new(trace: lines.Enqueue);
        Guid commandId = Guid.NewGuid();

        h.Write(OutOfProcPackets.Create("Command", commandId));
        h.NextPacket();

        string prefix = $"PSWSMan OutOfProc Packet [{h.RunspacePoolId}] ";
        await Assert.That(lines).Contains($"{prefix}Sent: {OutOfProcPackets.Create("Command", commandId)}");
        await Assert.That(lines).Contains($"{prefix}Received: {Ack("CommandAck", commandId)}");
    }

    [Test]
    public async Task Run_StopsWithoutEscapingWhenTheErrorCallbackFails()
    {
        BlockingCollection<string> lines = new();
        using TranslatorHarness h = new(trace: lines.Add, onError: _ => throw new InvalidOperationException("failed"));

        h.Write("<Command");

        string? failed = null;
        while (failed is null && lines.TryTake(out string? line, TranslatorHarness.Timeout))
        {
            failed = line.Contains("translator thread failed") ? line : null;
        }
        await Assert.That(failed).IsNotNull();
    }

    [Test]
    public async Task Trace_FailureDoesNotAffectTheTranslator()
    {
        using TranslatorHarness h = new(trace: _ => throw new InvalidOperationException("trace broken"));
        Guid commandId = Guid.NewGuid();

        h.Write("<Command");
        h.Write(OutOfProcPackets.Create("Command", commandId));

        await Assert.That(h.NextError()).IsTypeOf<XmlException>();
        await Assert.That(h.NextPacket()).IsEqualTo(Ack("CommandAck", commandId));
    }
}
