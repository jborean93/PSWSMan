using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace PSWSMan.Lib;

/// <summary>The base class for a WSMan set of named values in the message header.</summary>
public abstract class WSManSet
{
    private readonly string _label;
    private readonly string _valueLabel;
    private readonly bool _mustUnderstand;
    private readonly List<(string Name, string Value, Dictionary<string, string> Attributes)> _entries = new();

    /// <summary>Creates an empty set.</summary>
    /// <param name="label">The element name of the set.</param>
    /// <param name="valueLabel">The element name of each value in the set.</param>
    /// <param name="mustUnderstand">Whether to set s:mustUnderstand="true" on the set.</param>
    protected WSManSet(string label, string valueLabel, bool mustUnderstand)
    {
        _label = label;
        _valueLabel = valueLabel;
        _mustUnderstand = mustUnderstand;
    }

    /// <summary>Creates a set with the values copied from an existing XML element.</summary>
    /// <param name="raw">The existing set element to copy the values from.</param>
    /// <param name="valueLabel">The element name of each value in the set.</param>
    /// <param name="mustUnderstand">Whether to set s:mustUnderstand="true" on the set.</param>
    protected WSManSet(XElement raw, string valueLabel, bool mustUnderstand)
        : this(raw.Name.LocalName, valueLabel, mustUnderstand)
    {
        foreach (XElement entry in raw.Elements(WSManNamespace.wsman + valueLabel))
        {
            string? name = entry.Attribute("Name")?.Value;
            if (name is null)
            {
                continue;
            }

            Dictionary<string, string> attributes = entry.Attributes()
                .Where(a => !a.IsNamespaceDeclaration && a.Name != "Name")
                .ToDictionary(a => a.Name.LocalName, a => a.Value);
            Add(name, entry.Value, attributes);
        }
    }

    /// <summary>Creates a copy of an existing set.</summary>
    /// <param name="fromCopy">The set to copy.</param>
    protected WSManSet(WSManSet fromCopy) : this(fromCopy._label, fromCopy._valueLabel, fromCopy._mustUnderstand)
    {
        foreach ((string name, string value, Dictionary<string, string> attributes) in fromCopy._entries)
        {
            Add(name, value, new(attributes));
        }
    }

    /// <summary>Adds a named value to the set.</summary>
    /// <param name="name">The name of the value.</param>
    /// <param name="value">The value to add.</param>
    /// <param name="attributes">Optional extra attributes to set on the value element.</param>
    public void Add(string name, string value, Dictionary<string, string>? attributes = null)
    {
        _entries.Add((name, value, attributes ?? new()));
    }

    /// <summary>Builds a new XML element for the set.</summary>
    /// <returns>The set as an XML element.</returns>
    public XElement ToXml()
    {
        XElement raw = new(WSManNamespace.wsman + _label);
        if (_mustUnderstand)
        {
            raw.SetAttributeValue(WSManNamespace.s + "mustUnderstand", "true");
        }

        foreach ((string name, string value, Dictionary<string, string> attributes) in _entries)
        {
            XElement element = new(WSManNamespace.wsman + _valueLabel,
                new XAttribute("Name", name),
                value);
            foreach (KeyValuePair<string, string> attr in attributes)
            {
                element.Add(new XAttribute(attr.Key, attr.Value));
            }
            raw.Add(element);
        }

        return raw;
    }
}

/// <summary>A wsman:SelectorSet used to identify a specific resource instance.</summary>
public sealed class SelectorSet : WSManSet
{
    /// <summary>Creates an empty selector set.</summary>
    public SelectorSet() : base("SelectorSet", "Selector", false)
    { }

    internal SelectorSet(SelectorSet fromCopy) : base(fromCopy)
    { }

    internal SelectorSet(XElement raw) : base(raw, "Selector", false)
    { }
}

/// <summary>A wsman:OptionSet used to pass extra options with a request.</summary>
public sealed class OptionSet : WSManSet
{
    /// <summary>Creates an empty option set.</summary>
    public OptionSet() : base("OptionSet", "Option", true)
    { }

    internal OptionSet(OptionSet fromCopy) : base(fromCopy)
    { }

    internal OptionSet(XElement raw) : base(raw, "Option", true)
    { }
}
