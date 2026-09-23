using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PSWSMan.Lib.Tests;

public class WSManClientTests
{
    private const string ResourceUri = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

    [Test]
    public async Task Constructor_SetsProperties()
    {
        WSManClient client = new(TestHelpers.ConnectionUri, 512000, TimeSpan.FromSeconds(20), "en-AU", "fr-FR");

        await Assert.That(client.ConnectionUri).IsEqualTo(TestHelpers.ConnectionUri);
        await Assert.That(client.MaxEnvelopeSize).IsEqualTo(512000);
        await Assert.That(client.OperationTimeout).IsEqualTo(TimeSpan.FromSeconds(20));
        await Assert.That(client.Locale).IsEqualTo("en-AU");
        await Assert.That(client.DataLocale).IsEqualTo("fr-FR");
        await Assert.That(client.SessionId).IsNotEqualTo(Guid.Empty);
    }

    [Test]
    [Arguments("")]
    [Arguments("   ")]
    public async Task Constructor_EmptyLocaleFallsBackToEnUS(string locale)
    {
        WSManClient client = TestHelpers.NewWSManClient(locale: locale);

        await Assert.That(client.Locale).IsEqualTo("en-US");
        await Assert.That(client.DataLocale).IsEqualTo("en-US");
    }

    [Test]
    [Arguments(null)]
    [Arguments("")]
    public async Task Constructor_EmptyDataLocaleFallsBackToLocale(string? dataLocale)
    {
        WSManClient client = TestHelpers.NewWSManClient(locale: "de-DE", dataLocale: dataLocale);

        await Assert.That(client.DataLocale).IsEqualTo("de-DE");
    }

    [Test]
    public async Task SessionId_IsUniquePerClient()
    {
        WSManClient client1 = TestHelpers.NewWSManClient();
        WSManClient client2 = TestHelpers.NewWSManClient();

        await Assert.That(client1.SessionId).IsNotEqualTo(client2.SessionId);
    }

    [Test]
    public async Task CreateRequest_BuildsHeader()
    {
        WSManClient client = TestHelpers.NewWSManClient(maxEnvelopeSize: 153600, locale: "en-US",
            dataLocale: "en-AU");

        WSManRequest request = client.CreateRequest(WSManAction.Get, ResourceUri);
        XElement envelope = TestHelpers.ParseRequest(request);
        XElement header = envelope.Header();

        await Assert.That(envelope.Name).IsEqualTo(WSManNamespace.s + "Envelope");

        XElement action = header.Element(WSManNamespace.wsa + "Action")!;
        await Assert.That(action.Value).IsEqualTo(WSManAction.Get);
        await Assert.That(action.Attribute(WSManNamespace.s + "mustUnderstand")?.Value).IsEqualTo("true");

        await Assert.That(envelope.HeaderValue(WSManNamespace.wsa + "MessageID"))
            .IsEqualTo(TestHelpers.UuidString(request.MessageId));
        await Assert.That(envelope.HeaderValue(WSManNamespace.wsmv + "SessionId"))
            .IsEqualTo(TestHelpers.UuidString(client.SessionId));
        await Assert.That(envelope.HeaderValue(WSManNamespace.wsa + "To"))
            .IsEqualTo(TestHelpers.ConnectionUri.ToString());
        await Assert.That(envelope.HeaderValue(WSManNamespace.wsman + "ResourceURI")).IsEqualTo(ResourceUri);
        await Assert.That(envelope.HeaderValue(WSManNamespace.wsman + "MaxEnvelopeSize")).IsEqualTo("153600");
        await Assert.That(envelope.HeaderValue(WSManNamespace.wsman + "OperationTimeout")).IsEqualTo("PT30S");

        await Assert.That(header.Element(WSManNamespace.wsman + "Locale")
            ?.Attribute(WSManNamespace.xml + "lang")?.Value).IsEqualTo("en-US");
        await Assert.That(header.Element(WSManNamespace.wsmv + "DataLocale")
            ?.Attribute(WSManNamespace.xml + "lang")?.Value).IsEqualTo("en-AU");

        await Assert.That(header.Element(WSManNamespace.wsa + "ReplyTo")
            ?.Element(WSManNamespace.wsa + "Address")?.Value)
            .IsEqualTo("http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous");
    }

    [Test]
    public async Task CreateRequest_OmitsXmlDeclaration()
    {
        WSManRequest request = TestHelpers.NewWSManClient().CreateRequest(WSManAction.Get, ResourceUri);
        string raw = Encoding.UTF8.GetString(request.Content);

        await Assert.That(raw).StartsWith("<s:Envelope ");
    }

    [Test]
    public async Task CreateRequest_EmptyBodyWhenNoneProvided()
    {
        WSManRequest request = TestHelpers.NewWSManClient().CreateRequest(WSManAction.Get, ResourceUri);
        XElement body = TestHelpers.ParseRequest(request).Body();

        await Assert.That(body.HasElements).IsFalse();
        await Assert.That(body.Value).IsEqualTo("");
    }

    [Test]
    public async Task CreateRequest_IncludesBody()
    {
        XElement bodyContent = new(WSManNamespace.rsp + "Receive",
            new XElement(WSManNamespace.rsp + "DesiredStream", "stdout"));

        WSManRequest request = TestHelpers.NewWSManClient().CreateRequest(WSManAction.Receive, ResourceUri,
            body: bodyContent);
        XElement body = TestHelpers.ParseRequest(request).Body();

        XElement? receive = body.Element(WSManNamespace.rsp + "Receive");
        await Assert.That(receive).IsNotNull();
        await Assert.That(receive!.Element(WSManNamespace.rsp + "DesiredStream")?.Value).IsEqualTo("stdout");
    }

    [Test]
    public async Task CreateRequest_NoOptionOrSelectorSetByDefault()
    {
        WSManRequest request = TestHelpers.NewWSManClient().CreateRequest(WSManAction.Get, ResourceUri);
        XElement header = TestHelpers.ParseRequest(request).Header();

        await Assert.That(header.Element(WSManNamespace.wsman + "OptionSet")).IsNull();
        await Assert.That(header.Element(WSManNamespace.wsman + "SelectorSet")).IsNull();
    }

    [Test]
    public async Task CreateRequest_IncludesOptionsAndSelectors()
    {
        OptionSet options = new();
        options.Add("WINRS_NOPROFILE", "1");
        SelectorSet selectors = new();
        selectors.Add("ShellId", "F7C4B4AB-3F2B-4F0D-9B8E-1A2B3C4D5E6F");

        WSManRequest request = TestHelpers.NewWSManClient().CreateRequest(WSManAction.Get, ResourceUri,
            options: options, selectors: selectors);
        XElement header = TestHelpers.ParseRequest(request).Header();

        XElement? optionSet = header.Element(WSManNamespace.wsman + "OptionSet");
        await Assert.That(optionSet).IsNotNull();
        XElement option = optionSet!.Element(WSManNamespace.wsman + "Option")!;
        await Assert.That(option.Attribute("Name")?.Value).IsEqualTo("WINRS_NOPROFILE");
        await Assert.That(option.Value).IsEqualTo("1");

        XElement? selectorSet = header.Element(WSManNamespace.wsman + "SelectorSet");
        await Assert.That(selectorSet).IsNotNull();
        XElement selector = selectorSet!.Element(WSManNamespace.wsman + "Selector")!;
        await Assert.That(selector.Attribute("Name")?.Value).IsEqualTo("ShellId");
        await Assert.That(selector.Value).IsEqualTo("F7C4B4AB-3F2B-4F0D-9B8E-1A2B3C4D5E6F");

        // The sets are appended after the standard headers, options before selectors.
        string[] lastTwo = header.Elements().Select(e => e.Name.LocalName).TakeLast(2).ToArray();
        await Assert.That(lastTwo).IsEquivalentTo(new[] { "OptionSet", "SelectorSet" });
    }

    [Test]
    [Arguments(90, "PT1M30S")]
    [Arguments(1.5, "PT1.5S")]
    [Arguments(3600, "PT1H")]
    public async Task CreateRequest_TimeoutOverride(double seconds, string expected)
    {
        WSManRequest request = TestHelpers.NewWSManClient().CreateRequest(WSManAction.Get, ResourceUri,
            timeout: TimeSpan.FromSeconds(seconds));
        XElement envelope = TestHelpers.ParseRequest(request);

        await Assert.That(envelope.HeaderValue(WSManNamespace.wsman + "OperationTimeout")).IsEqualTo(expected);
    }

    [Test]
    public async Task CreateRequest_UniqueMessageIdPerRequest()
    {
        WSManClient client = TestHelpers.NewWSManClient();

        WSManRequest request1 = client.CreateRequest(WSManAction.Get, ResourceUri);
        WSManRequest request2 = client.CreateRequest(WSManAction.Get, ResourceUri);

        await Assert.That(request1.MessageId).IsNotEqualTo(request2.MessageId);
        await Assert.That(TestHelpers.ParseRequest(request1).HeaderValue(WSManNamespace.wsmv + "SessionId"))
            .IsEqualTo(TestHelpers.ParseRequest(request2).HeaderValue(WSManNamespace.wsmv + "SessionId"));
    }

    [Test]
    public async Task UpdateMaxEnvelopeSize_AffectsSubsequentRequests()
    {
        WSManClient client = TestHelpers.NewWSManClient(maxEnvelopeSize: 153600);

        client.UpdateMaxEnvelopeSize(512000);
        WSManRequest request = client.CreateRequest(WSManAction.Get, ResourceUri);

        await Assert.That(client.MaxEnvelopeSize).IsEqualTo(512000);
        await Assert.That(TestHelpers.ParseRequest(request).HeaderValue(WSManNamespace.wsman + "MaxEnvelopeSize"))
            .IsEqualTo("512000");
    }

    [Test]
    public async Task CreateRequest_EncodesContentAsUtf8WithoutBom()
    {
        XElement bodyContent = new(WSManNamespace.rsp + "Command", "café ☃");

        WSManRequest request = TestHelpers.NewWSManClient().CreateRequest(WSManAction.Command, ResourceUri,
            body: bodyContent);

        await Assert.That(request.Content[0]).IsEqualTo((byte)'<');
        await Assert.That(TestHelpers.ParseRequest(request).Body().Element(WSManNamespace.rsp + "Command")?.Value)
            .IsEqualTo("café ☃");
    }

    [Test]
    public async Task CreateRequest_EscapesSpecialCharactersInValues()
    {
        XElement bodyContent = new(WSManNamespace.rsp + "Command", "echo \"<a & b>\"");

        WSManRequest request = TestHelpers.NewWSManClient().CreateRequest(WSManAction.Command,
            "http://resource/<uri>", body: bodyContent);
        XElement envelope = TestHelpers.ParseRequest(request);

        await Assert.That(envelope.HeaderValue(WSManNamespace.wsman + "ResourceURI"))
            .IsEqualTo("http://resource/<uri>");
        await Assert.That(envelope.Body().Element(WSManNamespace.rsp + "Command")?.Value)
            .IsEqualTo("echo \"<a & b>\"");
    }
}
