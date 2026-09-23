using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace PSWSMan.Lib;

/// <summary>Builds WSMan request envelopes.</summary>
public class WSManClient
{
    private static readonly XmlWriterSettings s_writerSettings = new()
    {
        OmitXmlDeclaration = true,
        Encoding = new UTF8Encoding(false),
    };

    /// <summary>The unique session identifier sent with each request.</summary>
    public Guid SessionId { get; }

    /// <summary>The URI of the WSMan endpoint.</summary>
    public Uri ConnectionUri { get; }

    /// <summary>The maximum size of a response envelope in bytes.</summary>
    public int MaxEnvelopeSize { get; private set; }

    /// <summary>The default operation timeout.</summary>
    public TimeSpan OperationTimeout { get; }

    /// <summary>The locale used for the response messages.</summary>
    public string Locale { get; }

    /// <summary>The locale used for formatting data in the response.</summary>
    public string DataLocale { get; }

    /// <summary>Creates a new WSMan client.</summary>
    /// <param name="connectionUri">The URI of the WSMan endpoint.</param>
    /// <param name="maxEnvelopeSize">The maximum size of a response envelope in bytes.</param>
    /// <param name="operationTimeout">The default operation timeout.</param>
    /// <param name="locale">The locale for response messages, defaults to en-US if empty.</param>
    /// <param name="dataLocale">The locale for response data, defaults to <paramref name="locale"/>.</param>
    public WSManClient(
        Uri connectionUri,
        int maxEnvelopeSize,
        TimeSpan operationTimeout,
        string locale,
        string? dataLocale = null)
    {
        SessionId = Guid.NewGuid();
        ConnectionUri = connectionUri;
        MaxEnvelopeSize = maxEnvelopeSize;
        OperationTimeout = operationTimeout;

        // This value is from pwsh but derived from CultureInfo.CurrentCulture but it may be set to InvariantCulture.
        // Just fallback to en-US as one must be set here.
        Locale = string.IsNullOrWhiteSpace(locale) ? "en-US" : locale;
        DataLocale = string.IsNullOrWhiteSpace(dataLocale) ? Locale : dataLocale;
    }

    /// <summary>
    /// Updates the MaxEnvelopeSize value based on updated information.
    /// </summary>
    /// <param name="newSize">The new maximum envelope size in bytes.</param>
    public void UpdateMaxEnvelopeSize(int newSize)
    {
        MaxEnvelopeSize = newSize;
    }

    /// <summary>Creates a request for a WSMan action.</summary>
    /// <param name="action">The wsa:Action URI of the request, see <see cref="WSManAction"/> for known values.</param>
    /// <param name="resourceUri">The resource URI to target.</param>
    /// <param name="body">Optional body element of the request.</param>
    /// <param name="options">Optional WSMan options to add to the header.</param>
    /// <param name="selectors">Optional WSMan selectors to add to the header.</param>
    /// <param name="timeout">Optional operation timeout, defaults to <see cref="OperationTimeout"/>.</param>
    /// <returns>The WSMan request to send.</returns>
    public WSManRequest CreateRequest(
        string action,
        string resourceUri,
        XElement? body = null,
        OptionSet? options = null,
        SelectorSet? selectors = null,
        TimeSpan? timeout = null)
    {
        XElement envelope = new(WSManNamespace.s + "Envelope",
            new XAttribute(XNamespace.Xmlns + "rsp", WSManNamespace.rsp),
            new XAttribute(XNamespace.Xmlns + "s", WSManNamespace.s),
            new XAttribute(XNamespace.Xmlns + "wsa", WSManNamespace.wsa),
            new XAttribute(XNamespace.Xmlns + "wsman", WSManNamespace.wsman),
            new XAttribute(XNamespace.Xmlns + "wsmv", WSManNamespace.wsmv),
            new XAttribute(XNamespace.Xmlns + "xml", WSManNamespace.xml),
            CreateHeader(action, resourceUri, out Guid messageId, options: options, selectors: selectors,
                timeout: timeout),
            new XElement(WSManNamespace.s + "Body", body)
        );

        using MemoryStream buffer = new();
        using (XmlWriter writer = XmlWriter.Create(buffer, s_writerSettings))
        {
            envelope.WriteTo(writer);
        }

        return new(messageId, buffer.ToArray());
    }

    private XElement CreateHeader(string action, string resourceUri, out Guid messageId,
        OptionSet? options = null, SelectorSet? selectors = null, TimeSpan? timeout = null)
    {
        messageId = Guid.NewGuid();
        string messageIdStr = messageId.ToString().ToUpperInvariant();
        XAttribute mustUnderstandTrue = new(WSManNamespace.s + "mustUnderstand", true);
        XAttribute mustUnderstandFalse = new(WSManNamespace.s + "mustUnderstand", false);

        XElement header = new(WSManNamespace.s + "Header",
            new XElement(WSManNamespace.wsa + "Action",
                mustUnderstandTrue,
                action),
            new XElement(WSManNamespace.wsmv + "DataLocale",
                mustUnderstandFalse,
                new XAttribute(WSManNamespace.xml + "lang", DataLocale)),
            new XElement(WSManNamespace.wsman + "Locale",
                mustUnderstandFalse,
                new XAttribute(WSManNamespace.xml + "lang", Locale)),
            new XElement(WSManNamespace.wsman + "MaxEnvelopeSize",
                mustUnderstandTrue,
                MaxEnvelopeSize),
            new XElement(WSManNamespace.wsa + "MessageID", $"uuid:{messageIdStr}"),
            new XElement(WSManNamespace.wsman + "OperationTimeout", XmlConvert.ToString(timeout ?? OperationTimeout)),
            new XElement(WSManNamespace.wsa + "ReplyTo",
                new XElement(WSManNamespace.wsa + "Address",
                    mustUnderstandTrue,
                    "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous")),
            new XElement(WSManNamespace.wsman + "ResourceURI",
                mustUnderstandTrue,
                resourceUri),
            new XElement(WSManNamespace.wsmv + "SessionId",
                mustUnderstandFalse,
                $"uuid:{SessionId.ToString().ToUpperInvariant()}"),
            new XElement(WSManNamespace.wsa + "To", ConnectionUri)
        );

        if (options is not null)
        {
            header.Add(options.ToXml());
        }

        if (selectors is not null)
        {
            header.Add(selectors.ToXml());
        }

        return header;
    }
}
