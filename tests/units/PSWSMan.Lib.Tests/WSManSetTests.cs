using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PSWSMan.Lib.Tests;

public class WSManSetTests
{
    [Test]
    public async Task OptionSet_ToXml_SetsMustUnderstand()
    {
        OptionSet options = new();
        options.Add("WINRS_CODEPAGE", "65001");

        XElement xml = options.ToXml();

        await Assert.That(xml.Name).IsEqualTo(WSManNamespace.wsman + "OptionSet");
        await Assert.That(xml.Attribute(WSManNamespace.s + "mustUnderstand")?.Value).IsEqualTo("true");

        XElement option = xml.Element(WSManNamespace.wsman + "Option")!;
        await Assert.That(option.Attribute("Name")?.Value).IsEqualTo("WINRS_CODEPAGE");
        await Assert.That(option.Value).IsEqualTo("65001");
    }

    [Test]
    public async Task SelectorSet_ToXml_NoMustUnderstand()
    {
        SelectorSet selectors = new();
        selectors.Add("ShellId", "F7C4B4AB-3F2B-4F0D-9B8E-1A2B3C4D5E6F");

        XElement xml = selectors.ToXml();

        await Assert.That(xml.Name).IsEqualTo(WSManNamespace.wsman + "SelectorSet");
        await Assert.That(xml.Attribute(WSManNamespace.s + "mustUnderstand")).IsNull();

        XElement selector = xml.Element(WSManNamespace.wsman + "Selector")!;
        await Assert.That(selector.Attribute("Name")?.Value).IsEqualTo("ShellId");
        await Assert.That(selector.Value).IsEqualTo("F7C4B4AB-3F2B-4F0D-9B8E-1A2B3C4D5E6F");
    }

    [Test]
    public async Task EmptySet_ToXml_HasNoEntries()
    {
        XElement xml = new OptionSet().ToXml();

        await Assert.That(xml.HasElements).IsFalse();
    }

    [Test]
    public async Task Add_WithAttributes_WritesExtraAttributes()
    {
        OptionSet options = new();
        options.Add("protocolversion", "2.3", new Dictionary<string, string> { { "MustComply", "true" } });

        XElement option = options.ToXml().Element(WSManNamespace.wsman + "Option")!;

        await Assert.That(option.Attribute("Name")?.Value).IsEqualTo("protocolversion");
        await Assert.That(option.Attribute("MustComply")?.Value).IsEqualTo("true");
        await Assert.That(option.Value).IsEqualTo("2.3");
    }

    [Test]
    public async Task Add_PreservesOrderAndAllowsDuplicateNames()
    {
        OptionSet options = new();
        options.Add("b", "1");
        options.Add("a", "2");
        options.Add("b", "3");

        (string Name, string Value)[] entries = options.ToXml()
            .Elements(WSManNamespace.wsman + "Option")
            .Select(e => (e.Attribute("Name")!.Value, e.Value))
            .ToArray();

        await Assert.That(entries).IsEquivalentTo(new[] { ("b", "1"), ("a", "2"), ("b", "3") });
    }

    [Test]
    public async Task ToXml_ReturnsNewElementEachCall()
    {
        SelectorSet selectors = new();
        selectors.Add("ShellId", "abc");

        XElement first = selectors.ToXml();
        first.RemoveAll();
        XElement second = selectors.ToXml();

        await Assert.That(second.Elements().Count()).IsEqualTo(1);
    }

    [Test]
    public async Task SelectorSet_FromCreateResponse_PreservesEntriesAndAttributes()
    {
        Guid shellId = Guid.NewGuid();
        XElement rawSelectors = new(WSManNamespace.wsman + "SelectorSet",
            new XElement(WSManNamespace.wsman + "Selector",
                new XAttribute("Name", "ShellId"),
                new XAttribute("Custom", "value"),
                shellId.ToString().ToUpperInvariant()),
            new XElement(WSManNamespace.wsman + "Selector", "no name attribute so ignored"),
            new XElement(WSManNamespace.wsman + "Selector",
                new XAttribute("Name", "Other"),
                "other-value"));
        byte[] response = TestHelpers.Response(WSManAction.CreateResponse, null,
            new XElement(WSManNamespace.wst + "ResourceCreated",
                new XElement(WSManNamespace.wsa + "ReferenceParameters", rawSelectors)),
            new XElement(WSManNamespace.rsp + "Shell",
                new XElement(WSManNamespace.rsp + "ShellId", shellId.ToString().ToUpperInvariant()),
                new XElement(WSManNamespace.rsp + "ResourceUri", TestHelpers.ShellUri)));

        WSManCreateResponse parsed = WSManCreateResponse.Parse(response);
        XElement[] selectors = parsed.Selectors.ToXml().Elements(WSManNamespace.wsman + "Selector").ToArray();

        await Assert.That(selectors.Length).IsEqualTo(2);
        await Assert.That(selectors[0].Attribute("Name")?.Value).IsEqualTo("ShellId");
        await Assert.That(selectors[0].Value).IsEqualTo(shellId.ToString().ToUpperInvariant());
        await Assert.That(selectors[0].Attribute("Custom")?.Value).IsEqualTo("value");
        await Assert.That(selectors[1].Attribute("Name")?.Value).IsEqualTo("Other");
        await Assert.That(selectors[1].Value).IsEqualTo("other-value");
    }
}
