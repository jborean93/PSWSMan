using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace PSWSMan.Lib.Tests;

/// <summary>
/// Covers the shared envelope validation that every response type goes through. WSManDeleteResponse is used as
/// the vehicle as it has no body requirements of its own.
/// </summary>
public class WSManEnvelopeTests
{
    [Test]
    public async Task Parse_EmptyResponse()
    {
        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(
            () => WSManDeleteResponse.Parse(Array.Empty<byte>()));

        await Assert.That(ex.Message).IsEqualTo("Received empty WSMan response");
    }

    [Test]
    public async Task Parse_NonXmlResponseIncludesRawText()
    {
        // Exchange Online is known to return a plain text error body.
        byte[] data = TestHelpers.ToBytes("The remote server returned an error: (401) Unauthorized.");

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManDeleteResponse.Parse(data));

        await Assert.That(ex.Message)
            .IsEqualTo("Received non-xml response: The remote server returned an error: (401) Unauthorized.");
        await Assert.That(ex.InnerException).IsTypeOf<XmlException>();
    }

    [Test]
    public async Task Parse_TruncatedXml()
    {
        byte[] full = TestHelpers.Response(WSManAction.DeleteResponse);
        byte[] data = full[..(full.Length / 2)];

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManDeleteResponse.Parse(data));

        await Assert.That(ex.Message).StartsWith("Received non-xml response: ");
        await Assert.That(ex.InnerException).IsTypeOf<XmlException>();
    }

    [Test]
    public async Task Parse_MissingHeader()
    {
        byte[] data = TestHelpers.Envelope(null, new XElement(WSManNamespace.s + "Body"));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManDeleteResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("WSMan envelope is missing the s:Header element");
    }

    [Test]
    public async Task Parse_MissingBody()
    {
        byte[] data = TestHelpers.Envelope(
            new XElement(WSManNamespace.s + "Header",
                new XElement(WSManNamespace.wsa + "Action", WSManAction.DeleteResponse)),
            null);

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManDeleteResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("WSMan envelope is missing the s:Body element");
    }

    [Test]
    public async Task Parse_MissingAction()
    {
        byte[] data = TestHelpers.Envelope(
            new XElement(WSManNamespace.s + "Header"),
            new XElement(WSManNamespace.s + "Body"));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManDeleteResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("WSMan envelope is missing the wsa:Action header");
    }

    [Test]
    public async Task Parse_WrongNamespaceIsTreatedAsMissing()
    {
        XNamespace soap11 = "http://schemas.xmlsoap.org/soap/envelope/";
        byte[] data = TestHelpers.ToBytes(new XElement(soap11 + "Envelope",
            new XElement(soap11 + "Header"),
            new XElement(soap11 + "Body")));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManDeleteResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("WSMan envelope is missing the s:Header element");
    }

    [Test]
    public async Task Parse_UnexpectedAction()
    {
        byte[] data = TestHelpers.Response(WSManAction.SendResponse);

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManDeleteResponse.Parse(data));

        await Assert.That(ex.Message)
            .IsEqualTo($"Expecting action '{WSManAction.DeleteResponse}' but got '{WSManAction.SendResponse}'");
    }

    [Test]
    public async Task Parse_RelatesToMatches()
    {
        Guid messageId = Guid.NewGuid();
        byte[] data = TestHelpers.Response(WSManAction.DeleteResponse, messageId);

        WSManDeleteResponse response = WSManDeleteResponse.Parse(data, messageId);

        await Assert.That(response).IsNotNull();
    }

    [Test]
    [Arguments("uuid:{0}")]
    [Arguments("UUID:{0}")]
    [Arguments("{0}")]
    [Arguments("  uuid:{0}  ")]
    public async Task Parse_RelatesToAcceptsDifferentFormats(string format)
    {
        Guid messageId = Guid.NewGuid();
        string relatesTo = string.Format(format, messageId.ToString().ToLowerInvariant());
        byte[] data = TestHelpers.Envelope(
            new XElement(WSManNamespace.s + "Header",
                new XElement(WSManNamespace.wsa + "Action", WSManAction.DeleteResponse),
                new XElement(WSManNamespace.wsa + "RelatesTo", relatesTo)),
            new XElement(WSManNamespace.s + "Body"));

        WSManDeleteResponse response = WSManDeleteResponse.Parse(data, messageId);

        await Assert.That(response).IsNotNull();
    }

    [Test]
    public async Task Parse_RelatesToMismatch()
    {
        Guid sent = Guid.NewGuid();
        Guid received = Guid.NewGuid();
        byte[] data = TestHelpers.Response(WSManAction.DeleteResponse, received);

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManDeleteResponse.Parse(data, sent));

        await Assert.That(ex.Message).IsEqualTo(
            "Received related id does not match related expected message id: " +
            $"Sent: {sent}, Received: {TestHelpers.UuidString(received)}");
    }

    [Test]
    public async Task Parse_RelatesToMissingWhenExpected()
    {
        Guid sent = Guid.NewGuid();
        byte[] data = TestHelpers.Response(WSManAction.DeleteResponse);

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManDeleteResponse.Parse(data, sent));

        await Assert.That(ex.Message).StartsWith("Received related id does not match related expected message id");
        await Assert.That(ex.Message).EndsWith("Received: ");
    }

    [Test]
    public async Task Parse_RelatesToInvalidUuid()
    {
        byte[] data = TestHelpers.Envelope(
            new XElement(WSManNamespace.s + "Header",
                new XElement(WSManNamespace.wsa + "Action", WSManAction.DeleteResponse),
                new XElement(WSManNamespace.wsa + "RelatesTo", "uuid:not-a-guid")),
            new XElement(WSManNamespace.s + "Body"));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(
            () => WSManDeleteResponse.Parse(data, Guid.NewGuid()));

        await Assert.That(ex.Message).IsEqualTo("Failed to parse uuid value 'uuid:not-a-guid'");
    }

    [Test]
    public async Task Parse_RelatesToNotCheckedWhenNotRequested()
    {
        byte[] data = TestHelpers.Response(WSManAction.DeleteResponse, Guid.NewGuid());

        WSManDeleteResponse response = WSManDeleteResponse.Parse(data);

        await Assert.That(response).IsNotNull();
    }

    [Test]
    [Arguments(WSManAction.Fault)]
    [Arguments(WSManAction.FaultAddressing)]
    public async Task Parse_FaultTakesPrecedenceOverExpectedAction(string faultAction)
    {
        byte[] data = TestHelpers.Response(faultAction, null,
            TestHelpers.Fault(code: "s:Sender", subCode: "wsa:ActionNotSupported", reason: "Not supported"));

        WSManFault ex = Assert.Throws<WSManFault>(() => WSManDeleteResponse.Parse(data));

        await Assert.That(ex.Code).IsEqualTo("s:Sender");
        await Assert.That(ex.SubCode).IsEqualTo("wsa:ActionNotSupported");
        await Assert.That(ex.Reason).IsEqualTo("Not supported");
    }

    [Test]
    public async Task Parse_FaultCheckedBeforeRelatesTo()
    {
        // A fault for a different message is still surfaced as the fault rather than a RelatesTo mismatch.
        byte[] data = TestHelpers.Response(WSManAction.Fault, Guid.NewGuid(), TestHelpers.Fault(reason: "Boom"));

        WSManFault ex = Assert.Throws<WSManFault>(() => WSManDeleteResponse.Parse(data, Guid.NewGuid()));

        await Assert.That(ex.Reason).IsEqualTo("Boom");
    }

    [Test]
    public async Task Parse_FaultActionWithoutFaultElement()
    {
        byte[] data = TestHelpers.Response(WSManAction.Fault);

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManDeleteResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("WSMan fault response is missing the s:Fault element");
    }

    [Test]
    public async Task Parse_RejectsDtd()
    {
        string raw = "<!DOCTYPE s:Envelope [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" +
            Encoding.UTF8.GetString(TestHelpers.Response(WSManAction.DeleteResponse));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(
            () => WSManDeleteResponse.Parse(TestHelpers.ToBytes(raw)));

        await Assert.That(ex.Message).StartsWith("Received non-xml response: ");
        await Assert.That(ex.InnerException).IsTypeOf<XmlException>();
    }

    [Test]
    public async Task Parse_AcceptsXmlDeclarationAndBom()
    {
        byte[] envelope = TestHelpers.Response(WSManAction.DeleteResponse);
        byte[] data = new byte[] { 0xEF, 0xBB, 0xBF }
            .Concat(TestHelpers.ToBytes("<?xml version=\"1.0\" encoding=\"utf-8\"?>"))
            .Concat(envelope)
            .ToArray();

        WSManDeleteResponse response = WSManDeleteResponse.Parse(data);

        await Assert.That(response).IsNotNull();
    }

    [Test]
    public async Task Parse_AcceptsIndentedXml()
    {
        XElement envelope = new(WSManNamespace.s + "Envelope",
            new XElement(WSManNamespace.s + "Header",
                new XElement(WSManNamespace.wsa + "Action", WSManAction.DeleteResponse)),
            new XElement(WSManNamespace.s + "Body"));
        byte[] data = TestHelpers.ToBytes(envelope.ToString(SaveOptions.None));

        WSManDeleteResponse response = WSManDeleteResponse.Parse(data);

        await Assert.That(response).IsNotNull();
    }

    [Test]
    public async Task ExceptionHierarchy()
    {
        WSManProtocolException protocol = new("protocol");
        WSManFault fault = new("fault");

        await Assert.That(protocol).IsAssignableTo<WSManException>();
        await Assert.That(fault).IsAssignableTo<WSManException>();
        await Assert.That(protocol.Message).IsEqualTo("protocol");
        await Assert.That(fault.Message).IsEqualTo("fault");
        await Assert.That(fault.WSManFaultCode).IsNull();
    }
}
