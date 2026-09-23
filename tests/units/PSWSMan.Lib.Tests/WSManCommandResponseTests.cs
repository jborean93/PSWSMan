using System;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PSWSMan.Lib.Tests;

public class WSManCommandResponseTests
{
    private static XElement CommandResponseBody(string commandId)
    {
        return new XElement(WSManNamespace.rsp + "CommandResponse",
            new XElement(WSManNamespace.rsp + "CommandId", commandId));
    }

    [Test]
    public async Task Parse_Response()
    {
        Guid messageId = Guid.NewGuid();
        Guid commandId = Guid.NewGuid();
        byte[] data = TestHelpers.Response(WSManAction.CommandResponse, messageId,
            CommandResponseBody(commandId.ToString().ToUpperInvariant()));

        WSManCommandResponse response = WSManCommandResponse.Parse(data, messageId);

        await Assert.That(response.CommandId).IsEqualTo(commandId);
    }

    [Test]
    [Arguments("uuid:{0}")]
    [Arguments("{0}")]
    [Arguments("{{{0}}}")]
    public async Task Parse_CommandIdFormats(string format)
    {
        Guid commandId = Guid.NewGuid();
        byte[] data = TestHelpers.Response(WSManAction.CommandResponse, null,
            CommandResponseBody(string.Format(format, commandId)));

        WSManCommandResponse response = WSManCommandResponse.Parse(data);

        await Assert.That(response.CommandId).IsEqualTo(commandId);
    }

    [Test]
    public async Task Parse_MissingCommandResponse()
    {
        byte[] data = TestHelpers.Response(WSManAction.CommandResponse);

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManCommandResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("CommandResponse is missing the rsp:CommandId element");
    }

    [Test]
    public async Task Parse_MissingCommandId()
    {
        byte[] data = TestHelpers.Response(WSManAction.CommandResponse, null,
            new XElement(WSManNamespace.rsp + "CommandResponse"));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManCommandResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("CommandResponse is missing the rsp:CommandId element");
    }

    [Test]
    public async Task Parse_InvalidCommandId()
    {
        byte[] data = TestHelpers.Response(WSManAction.CommandResponse, null, CommandResponseBody("uuid:1234"));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManCommandResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("Failed to parse uuid value 'uuid:1234'");
    }

    [Test]
    public async Task Parse_RelatesToMismatch()
    {
        byte[] data = TestHelpers.Response(WSManAction.CommandResponse, Guid.NewGuid(),
            CommandResponseBody(Guid.NewGuid().ToString()));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(
            () => WSManCommandResponse.Parse(data, Guid.NewGuid()));

        await Assert.That(ex.Message).StartsWith("Received related id does not match");
    }

    [Test]
    public async Task Parse_ShellNotFoundFault()
    {
        byte[] data = TestHelpers.Response(WSManAction.Fault, null, TestHelpers.Fault(
            code: "s:Receiver",
            subCode: "w:InternalError",
            reason: "The request for the Windows Remote Shell failed because the shell was not found on the server.",
            wsmanFaultCode: "2150858843",
            machine: "server"));

        WSManFault ex = Assert.Throws<WSManFault>(() => WSManCommandResponse.Parse(data));

        await Assert.That(ex.WSManFaultCode).IsEqualTo((int?)unchecked((int)0x8033805B));
    }
}
