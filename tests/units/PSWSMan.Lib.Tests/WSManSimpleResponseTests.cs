using System;
using System.Threading.Tasks;

namespace PSWSMan.Lib.Tests;

/// <summary>Covers the response types that carry no payload beyond the envelope validation.</summary>
public class WSManSimpleResponseTests
{
    [Test]
    public async Task Delete_Parse()
    {
        Guid messageId = Guid.NewGuid();
        byte[] data = TestHelpers.Response(WSManAction.DeleteResponse, messageId);

        WSManDeleteResponse response = WSManDeleteResponse.Parse(data, messageId);

        await Assert.That(response).IsNotNull();
    }

    [Test]
    public async Task Delete_WrongAction()
    {
        byte[] data = TestHelpers.Response(WSManAction.SignalResponse);

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManDeleteResponse.Parse(data));

        await Assert.That(ex.Message).StartsWith($"Expecting action '{WSManAction.DeleteResponse}'");
    }

    [Test]
    public async Task Send_Parse()
    {
        Guid messageId = Guid.NewGuid();
        byte[] data = TestHelpers.Response(WSManAction.SendResponse, messageId);

        WSManSendResponse response = WSManSendResponse.Parse(data, messageId);

        await Assert.That(response).IsNotNull();
    }

    [Test]
    public async Task Send_WrongAction()
    {
        byte[] data = TestHelpers.Response(WSManAction.DeleteResponse);

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManSendResponse.Parse(data));

        await Assert.That(ex.Message).StartsWith($"Expecting action '{WSManAction.SendResponse}'");
    }

    [Test]
    public async Task Send_RelatesToMismatch()
    {
        byte[] data = TestHelpers.Response(WSManAction.SendResponse, Guid.NewGuid());

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(
            () => WSManSendResponse.Parse(data, Guid.NewGuid()));

        await Assert.That(ex.Message).StartsWith("Received related id does not match");
    }

    [Test]
    public async Task Signal_Parse()
    {
        Guid messageId = Guid.NewGuid();
        byte[] data = TestHelpers.Response(WSManAction.SignalResponse, messageId);

        WSManSignalResponse response = WSManSignalResponse.Parse(data, messageId);

        await Assert.That(response).IsNotNull();
    }

    [Test]
    public async Task Signal_WrongAction()
    {
        byte[] data = TestHelpers.Response(WSManAction.SendResponse);

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManSignalResponse.Parse(data));

        await Assert.That(ex.Message).StartsWith($"Expecting action '{WSManAction.SignalResponse}'");
    }

    [Test]
    public async Task Signal_ShellDisconnectedFault()
    {
        byte[] data = TestHelpers.Response(WSManAction.Fault, null, TestHelpers.Fault(
            reason: "The shell is disconnected.",
            wsmanFaultCode: "2150859204"));

        WSManFault ex = Assert.Throws<WSManFault>(() => WSManSignalResponse.Parse(data));

        await Assert.That(ex.WSManFaultCode).IsEqualTo((int?)unchecked((int)0x803381C4));
    }
}
