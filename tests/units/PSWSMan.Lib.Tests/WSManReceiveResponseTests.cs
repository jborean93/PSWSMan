using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PSWSMan.Lib.Tests;

public class WSManReceiveResponseTests
{
    private static byte[] ReceiveResponse(Guid? relatesTo = null, params object?[] content)
    {
        return TestHelpers.Response(WSManAction.ReceiveResponse, relatesTo,
            new XElement(WSManNamespace.rsp + "ReceiveResponse", content));
    }

    [Test]
    public async Task Parse_RunningCommandWithOutput()
    {
        Guid messageId = Guid.NewGuid();
        Guid commandId = Guid.NewGuid();
        byte[] chunk = Encoding.UTF8.GetBytes("hello");
        byte[] data = ReceiveResponse(messageId,
            TestHelpers.Stream("stdout", chunk, commandId),
            TestHelpers.CommandState(CommandState.Running, commandId));

        WSManReceiveResponse response = WSManReceiveResponse.Parse(data, messageId);

        await Assert.That(response.State).IsEqualTo(CommandState.Running);
        await Assert.That(response.ExitCode).IsNull();
        await Assert.That(response.Streams.Keys).IsEquivalentTo(new[] { "stdout" });
        await Assert.That(response.Streams["stdout"].Length).IsEqualTo(1);
        await Assert.That(response.Streams["stdout"][0]).IsEquivalentTo(chunk);
    }

    [Test]
    public async Task Parse_DoneCommandWithExitCode()
    {
        Guid commandId = Guid.NewGuid();
        byte[] data = ReceiveResponse(null,
            TestHelpers.Stream("stdout", Array.Empty<byte>(), commandId, end: true),
            TestHelpers.Stream("stderr", Array.Empty<byte>(), commandId, end: true),
            TestHelpers.CommandState(CommandState.Done, commandId, exitCode: "0"));

        WSManReceiveResponse response = WSManReceiveResponse.Parse(data);

        await Assert.That(response.State).IsEqualTo(CommandState.Done);
        await Assert.That(response.ExitCode).IsEqualTo((int?)0);
        await Assert.That(response.Streams.Count).IsEqualTo(2);
        await Assert.That(response.Streams["stdout"][0].Length).IsEqualTo(0);
        await Assert.That(response.Streams["stderr"][0].Length).IsEqualTo(0);
    }

    [Test]
    [Arguments("1", 1)]
    [Arguments("-1", -1)]
    [Arguments("-1073741510", -1073741510)]
    [Arguments(" 42 ", 42)]
    public async Task Parse_ExitCodeValues(string raw, int expected)
    {
        byte[] data = ReceiveResponse(null, TestHelpers.CommandState(CommandState.Done, exitCode: raw));

        WSManReceiveResponse response = WSManReceiveResponse.Parse(data);

        await Assert.That(response.ExitCode).IsEqualTo((int?)expected);
    }

    [Test]
    [Arguments("")]
    [Arguments("   ")]
    public async Task Parse_EmptyExitCodeIsNull(string raw)
    {
        byte[] data = ReceiveResponse(null, TestHelpers.CommandState(CommandState.Done, exitCode: raw));

        WSManReceiveResponse response = WSManReceiveResponse.Parse(data);

        await Assert.That(response.State).IsEqualTo(CommandState.Done);
        await Assert.That(response.ExitCode).IsNull();
    }

    [Test]
    [Arguments("abc")]
    [Arguments("0x10")]
    [Arguments("4294967295")]
    public async Task Parse_InvalidExitCode(string raw)
    {
        byte[] data = ReceiveResponse(null, TestHelpers.CommandState(CommandState.Done, exitCode: raw));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManReceiveResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo($"ReceiveResponse rsp:ExitCode '{raw}' is not an integer");
    }

    [Test]
    public async Task Parse_CommandStateWithoutStateAttribute()
    {
        byte[] data = ReceiveResponse(null,
            new XElement(WSManNamespace.rsp + "CommandState", new XElement(WSManNamespace.rsp + "ExitCode", "3")));

        WSManReceiveResponse response = WSManReceiveResponse.Parse(data);

        await Assert.That(response.State).IsNull();
        await Assert.That(response.ExitCode).IsEqualTo((int?)3);
    }

    [Test]
    public async Task Parse_MultipleChunksPreserveOrderPerStream()
    {
        byte[] data = ReceiveResponse(null,
            TestHelpers.Stream("stdout", new byte[] { 1 }),
            TestHelpers.Stream("stderr", new byte[] { 2 }),
            TestHelpers.Stream("stdout", new byte[] { 3 }),
            TestHelpers.Stream("stdout", new byte[] { 4 }),
            TestHelpers.Stream("stderr", new byte[] { 5 }));

        WSManReceiveResponse response = WSManReceiveResponse.Parse(data);

        await Assert.That(response.Streams["stdout"].Select(c => c[0])).IsEquivalentTo(new byte[] { 1, 3, 4 });
        await Assert.That(response.Streams["stderr"].Select(c => c[0])).IsEquivalentTo(new byte[] { 2, 5 });
    }

    [Test]
    public async Task Parse_LargeChunk()
    {
        byte[] chunk = new byte[64 * 1024];
        new Random(42).NextBytes(chunk);
        byte[] data = ReceiveResponse(null, TestHelpers.Stream("stdout", chunk));

        WSManReceiveResponse response = WSManReceiveResponse.Parse(data);

        await Assert.That(response.Streams["stdout"][0]).IsEquivalentTo(chunk);
    }

    [Test]
    public async Task Parse_Base64WithWhitespace()
    {
        // Base64 split over lines is still valid.
        byte[] data = ReceiveResponse(null,
            new XElement(WSManNamespace.rsp + "Stream", new XAttribute("Name", "stdout"), "aGVs\n  bG8="));

        WSManReceiveResponse response = WSManReceiveResponse.Parse(data);

        await Assert.That(Encoding.UTF8.GetString(response.Streams["stdout"][0])).IsEqualTo("hello");
    }

    [Test]
    public async Task Parse_NoStreamsOrState()
    {
        byte[] data = ReceiveResponse();

        WSManReceiveResponse response = WSManReceiveResponse.Parse(data);

        await Assert.That(response.State).IsNull();
        await Assert.That(response.ExitCode).IsNull();
        await Assert.That(response.Streams.Count).IsEqualTo(0);
    }

    [Test]
    public async Task Parse_StreamNameIsCaseSensitive()
    {
        byte[] data = ReceiveResponse(null,
            TestHelpers.Stream("stdout", new byte[] { 1 }),
            TestHelpers.Stream("StdOut", new byte[] { 2 }));

        WSManReceiveResponse response = WSManReceiveResponse.Parse(data);

        await Assert.That(response.Streams.Count).IsEqualTo(2);
    }

    [Test]
    public async Task Parse_MissingReceiveResponseElement()
    {
        byte[] data = TestHelpers.Response(WSManAction.ReceiveResponse);

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManReceiveResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("ReceiveResponse is missing the rsp:ReceiveResponse element");
    }

    [Test]
    public async Task Parse_StreamMissingName()
    {
        byte[] data = ReceiveResponse(null, new XElement(WSManNamespace.rsp + "Stream", "AQ=="));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManReceiveResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("ReceiveResponse rsp:Stream is missing the Name attribute");
    }

    [Test]
    public async Task Parse_StreamInvalidBase64()
    {
        byte[] data = ReceiveResponse(null,
            new XElement(WSManNamespace.rsp + "Stream", new XAttribute("Name", "stdout"), "not base64!"));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManReceiveResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("ReceiveResponse rsp:Stream 'stdout' is not valid base64");
        await Assert.That(ex.InnerException).IsTypeOf<FormatException>();
    }

    [Test]
    public async Task Parse_WrongAction()
    {
        byte[] data = TestHelpers.Response(WSManAction.SendResponse, null,
            new XElement(WSManNamespace.rsp + "ReceiveResponse"));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManReceiveResponse.Parse(data));

        await Assert.That(ex.Message).StartsWith($"Expecting action '{WSManAction.ReceiveResponse}'");
    }

    [Test]
    public async Task Parse_OperationTimeoutFault()
    {
        // WinRM returns this when no output arrived within OperationTimeout, the caller is expected to retry.
        byte[] data = TestHelpers.Response(WSManAction.Fault, null, TestHelpers.Fault(
            code: "s:Receiver",
            subCode: "w:TimedOut",
            reason: "The WS-Management service cannot complete the operation within the time specified.",
            faultDetail: "http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/OperationTimeout",
            wsmanFaultCode: "2150858793"));

        WSManFault ex = Assert.Throws<WSManFault>(() => WSManReceiveResponse.Parse(data));

        await Assert.That(ex.WSManFaultCode).IsEqualTo((int?)unchecked((int)0x80338029));
        await Assert.That(ex.FaultDetail).EndsWith("/OperationTimeout");
    }
}
