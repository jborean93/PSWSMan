using System;
using System.Linq;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PSWSMan.Lib.Tests;

public class WSManCreateResponseTests
{
    [Test]
    public async Task Parse_FullResponse()
    {
        Guid messageId = Guid.NewGuid();
        Guid shellId = Guid.NewGuid();
        byte[] data = TestHelpers.Response(WSManAction.CreateResponse, messageId,
            TestHelpers.CreateResponseBody(shellId));

        WSManCreateResponse response = WSManCreateResponse.Parse(data, messageId);

        await Assert.That(response.ShellId).IsEqualTo(shellId);
        await Assert.That(response.ResourceUri).IsEqualTo(TestHelpers.ShellUri);

        XElement selector = response.Selectors.ToXml().Element(WSManNamespace.wsman + "Selector")!;
        await Assert.That(selector.Attribute("Name")?.Value).IsEqualTo("ShellId");
        await Assert.That(selector.Value).IsEqualTo(shellId.ToString().ToUpperInvariant());
    }

    [Test]
    public async Task Parse_ShellIdWithUuidPrefix()
    {
        Guid shellId = Guid.NewGuid();
        byte[] data = TestHelpers.Response(WSManAction.CreateResponse, null,
            new XElement(WSManNamespace.wst + "ResourceCreated",
                new XElement(WSManNamespace.wsa + "ReferenceParameters",
                    new XElement(WSManNamespace.wsman + "SelectorSet"))),
            new XElement(WSManNamespace.rsp + "Shell",
                new XElement(WSManNamespace.rsp + "ShellId", $"uuid:{shellId.ToString().ToLowerInvariant()}"),
                new XElement(WSManNamespace.rsp + "ResourceUri", TestHelpers.ShellUri)));

        WSManCreateResponse response = WSManCreateResponse.Parse(data);

        await Assert.That(response.ShellId).IsEqualTo(shellId);
        await Assert.That(response.Selectors.ToXml().HasElements).IsFalse();
    }

    [Test]
    public async Task Parse_MissingSelectorSet()
    {
        byte[] data = TestHelpers.Response(WSManAction.CreateResponse, null,
            TestHelpers.CreateResponseBody(Guid.NewGuid(), includeSelectorSet: false));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManCreateResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("CreateResponse is missing the wsman:SelectorSet element");
    }

    [Test]
    public async Task Parse_MissingResourceCreated()
    {
        byte[] data = TestHelpers.Response(WSManAction.CreateResponse, null,
            TestHelpers.CreateResponseBody(Guid.NewGuid()).Skip(1).ToArray());

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManCreateResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("CreateResponse is missing the wsman:SelectorSet element");
    }

    [Test]
    public async Task Parse_MissingShell()
    {
        byte[] data = TestHelpers.Response(WSManAction.CreateResponse, null,
            TestHelpers.CreateResponseBody(Guid.NewGuid(), includeShell: false));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManCreateResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("CreateResponse is missing the rsp:Shell element");
    }

    [Test]
    public async Task Parse_MissingShellId()
    {
        byte[] data = TestHelpers.Response(WSManAction.CreateResponse, null,
            TestHelpers.CreateResponseBody(Guid.NewGuid(), includeShellId: false));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManCreateResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("CreateResponse is missing the rsp:ShellId element");
    }

    [Test]
    public async Task Parse_MissingResourceUri()
    {
        byte[] data = TestHelpers.Response(WSManAction.CreateResponse, null,
            TestHelpers.CreateResponseBody(Guid.NewGuid(), includeResourceUri: false));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManCreateResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("CreateResponse is missing the rsp:ResourceUri element");
    }

    [Test]
    public async Task Parse_InvalidShellId()
    {
        byte[] data = TestHelpers.Response(WSManAction.CreateResponse, null,
            new XElement(WSManNamespace.wst + "ResourceCreated",
                new XElement(WSManNamespace.wsa + "ReferenceParameters",
                    new XElement(WSManNamespace.wsman + "SelectorSet"))),
            new XElement(WSManNamespace.rsp + "Shell",
                new XElement(WSManNamespace.rsp + "ShellId", "Runspace1"),
                new XElement(WSManNamespace.rsp + "ResourceUri", TestHelpers.ShellUri)));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManCreateResponse.Parse(data));

        await Assert.That(ex.Message).IsEqualTo("Failed to parse uuid value 'Runspace1'");
    }

    [Test]
    public async Task Parse_WrongAction()
    {
        byte[] data = TestHelpers.Response(WSManAction.CommandResponse, null,
            TestHelpers.CreateResponseBody(Guid.NewGuid()));

        WSManProtocolException ex = Assert.Throws<WSManProtocolException>(() => WSManCreateResponse.Parse(data));

        await Assert.That(ex.Message).StartsWith($"Expecting action '{WSManAction.CreateResponse}'");
    }

    [Test]
    public async Task Parse_AccessDeniedFault()
    {
        byte[] data = TestHelpers.Response(WSManAction.Fault, null, TestHelpers.Fault(
            code: "s:Sender",
            subCode: "w:AccessDenied",
            reason: "The WinRM client cannot process the request.",
            wsmanFaultCode: "5"));

        WSManFault ex = Assert.Throws<WSManFault>(() => WSManCreateResponse.Parse(data));

        await Assert.That(ex.WSManFaultCode).IsEqualTo((int?)5);
        await Assert.That(ex.SubCode).IsEqualTo("w:AccessDenied");
    }
}
