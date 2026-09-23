using System;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PSWSMan.Lib.Tests;

public class WSManFaultTests
{
    private const string TimeoutMessage =
        "The WS-Management service cannot complete the operation within the time specified in OperationTimeout.  ";

    private static WSManFault ParseFault(XElement fault, string action = WSManAction.Fault)
    {
        byte[] data = TestHelpers.Response(action, null, fault);
        return Assert.Throws<WSManFault>(() => WSManReceiveResponse.Parse(data));
    }

    [Test]
    public async Task OperationTimeoutFault()
    {
        // The fault WinRM returns when a Receive times out, the PSRP shim keys off the code to retry.
        WSManFault fault = ParseFault(TestHelpers.Fault(
            code: "s:Receiver",
            subCode: "w:TimedOut",
            reason: TimeoutMessage,
            faultDetail: "http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/OperationTimeout",
            wsmanFaultCode: "2150858793",
            machine: "server2022.domain.test",
            message: TimeoutMessage));

        await Assert.That(fault.Code).IsEqualTo("s:Receiver");
        await Assert.That(fault.SubCode).IsEqualTo("w:TimedOut");
        await Assert.That(fault.Reason).IsEqualTo(TimeoutMessage);
        await Assert.That(fault.FaultDetail)
            .IsEqualTo("http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/OperationTimeout");
        await Assert.That(fault.WSManFaultCode).IsEqualTo((int?)unchecked((int)0x80338029));
        await Assert.That(fault.Machine).IsEqualTo("server2022.domain.test");
        await Assert.That(fault.FaultMessage).IsEqualTo(TimeoutMessage);
        await Assert.That(fault.Message).IsEqualTo(
            "Received a WSManFault: Code: s:Receiver SubCode: w:TimedOut " +
            $"Reason: {TimeoutMessage.Trim()} " +
            "FaultDetail: http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/OperationTimeout " +
            $"WSManFaultCode: 0x80338029 - {TimeoutMessage.Trim()}");
    }

    [Test]
    public async Task MinimalFault()
    {
        WSManFault fault = ParseFault(TestHelpers.Fault(code: "s:Sender", reason: "Access is denied."));

        await Assert.That(fault.Code).IsEqualTo("s:Sender");
        await Assert.That(fault.SubCode).IsNull();
        await Assert.That(fault.Reason).IsEqualTo("Access is denied.");
        await Assert.That(fault.FaultDetail).IsNull();
        await Assert.That(fault.WSManFaultCode).IsNull();
        await Assert.That(fault.Machine).IsNull();
        await Assert.That(fault.FaultMessage).IsNull();
        await Assert.That(fault.Message).IsEqualTo("Received a WSManFault: Code: s:Sender Reason: Access is denied.");
    }

    [Test]
    public async Task EmptyFault()
    {
        WSManFault fault = ParseFault(TestHelpers.Fault(code: null));

        await Assert.That(fault.Code).IsNull();
        await Assert.That(fault.Reason).IsNull();
        await Assert.That(fault.Message).StartsWith("Received a WSManFault:");
    }

    [Test]
    public async Task FaultCodeWithoutMessage()
    {
        WSManFault fault = ParseFault(TestHelpers.Fault(
            reason: "Cancelled",
            wsmanFaultCode: "1223",
            machine: "server"));

        await Assert.That(fault.WSManFaultCode).IsEqualTo((int?)0x000004C7);
        await Assert.That(fault.Machine).IsEqualTo("server");
        await Assert.That(fault.FaultMessage).IsNull();
        await Assert.That(fault.Message)
            .IsEqualTo("Received a WSManFault: Code: s:Receiver Reason: Cancelled WSManFaultCode: 0x000004C7");
    }

    [Test]
    [Arguments("2150859012", unchecked((int)0x80338104))]
    [Arguments("995", 0x000003E3)]
    [Arguments("0", 0)]
    [Arguments("4294967295", -1)]
    public async Task FaultCodeIsParsedAsUnsignedThenCastToInt(string raw, int expected)
    {
        WSManFault fault = ParseFault(TestHelpers.Fault(wsmanFaultCode: raw));

        await Assert.That(fault.WSManFaultCode).IsEqualTo((int?)expected);
    }

    [Test]
    [Arguments("0x80338029")]
    [Arguments("-1")]
    [Arguments("")]
    [Arguments("abc")]
    public async Task InvalidFaultCodeIsIgnored(string raw)
    {
        WSManFault fault = ParseFault(TestHelpers.Fault(wsmanFaultCode: raw, message: "msg"));

        await Assert.That(fault.WSManFaultCode).IsNull();
        await Assert.That(fault.FaultMessage).IsEqualTo("msg");
    }

    [Test]
    public async Task ComplexFaultMessageIsSerializedAsXml()
    {
        // The PowerShell plugin nests a ProviderFault inside the Message element.
        const string innerText = "The request for the Windows Remote Shell with ShellId " +
            "F7C4B4AB-3F2B-4F0D-9B8E-1A2B3C4D5E6F failed because the shell was not found on the server.";
        XElement providerFault = new(WSManNamespace.wsmanfault + "ProviderFault",
            new XAttribute("provider", "microsoft.powershell"),
            new XAttribute("path", "%systemroot%\\system32\\pwrshplugin.dll"),
            new XElement(WSManNamespace.wsmanfault + "WSManFault",
                new XAttribute("Code", "2150858843"),
                new XAttribute("Machine", "server"),
                new XElement(WSManNamespace.wsmanfault + "Message", innerText)));

        WSManFault fault = ParseFault(TestHelpers.Fault(
            code: "s:Receiver",
            subCode: "w:InternalError",
            reason: "The request for the Windows Remote Shell failed.",
            wsmanFaultCode: "2150858843",
            machine: "server",
            message: providerFault));

        await Assert.That(fault.WSManFaultCode).IsEqualTo((int?)unchecked((int)0x8033805B));
        await Assert.That(fault.FaultMessage).IsNotNull();
        await Assert.That(fault.FaultMessage!).StartsWith("<f:Message ");
        await Assert.That(fault.FaultMessage!).Contains("provider=\"microsoft.powershell\"");
        await Assert.That(fault.FaultMessage!).Contains(innerText);
        await Assert.That(fault.Message).Contains($"- {fault.FaultMessage}");
    }

    [Test]
    public async Task WhitespaceOnlyValuesAreOmittedFromMessage()
    {
        WSManFault fault = ParseFault(TestHelpers.Fault(code: "  ", reason: "\n", wsmanFaultCode: "5", message: " "));

        await Assert.That(fault.Message).IsEqualTo("Received a WSManFault: WSManFaultCode: 0x00000005");
    }

    [Test]
    public async Task FaultFromAddressingAction()
    {
        WSManFault fault = ParseFault(
            TestHelpers.Fault(code: "s:Sender", subCode: "wsa:DestinationUnreachable", reason: "No route"),
            action: WSManAction.FaultAddressing);

        await Assert.That(fault.SubCode).IsEqualTo("wsa:DestinationUnreachable");
    }

    [Test]
    public async Task FaultWithMultipleReasonTextsUsesFirst()
    {
        XElement fault = TestHelpers.Fault(code: "s:Sender");
        fault.Add(new XElement(WSManNamespace.s + "Reason",
            new XElement(WSManNamespace.s + "Text", new XAttribute(WSManNamespace.xml + "lang", "en-US"), "English"),
            new XElement(WSManNamespace.s + "Text", new XAttribute(WSManNamespace.xml + "lang", "fr-FR"), "French")));

        WSManFault parsed = ParseFault(fault);

        await Assert.That(parsed.Reason).IsEqualTo("English");
    }

    [Test]
    public async Task FaultCanBeCaughtAsBaseException()
    {
        byte[] data = TestHelpers.Response(WSManAction.Fault, null, TestHelpers.Fault(reason: "x"));

        WSManException ex = Assert.Throws<WSManException>(() => WSManSignalResponse.Parse(data));

        await Assert.That(ex).IsTypeOf<WSManFault>();
    }
}
