using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace PSWSMan.Lib;

/// <summary>Helpers for parsing and validating the common parts of a WSMan response envelope.</summary>
internal static class WSManEnvelope
{
    private static readonly XmlReaderSettings s_readerSettings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        IgnoreWhitespace = true,
    };

    /// <summary>Parses a raw WSMan response and validates the common header values.</summary>
    /// <param name="data">The raw response from the server.</param>
    /// <param name="relatesTo">The MessageId of the request, if set the response RelatesTo must match it.</param>
    /// <param name="expectedAction">The wsa:Action URI expected, if set the response action must match it.</param>
    /// <returns>The s:Body element of the response.</returns>
    /// <exception cref="WSManFault">The server returned a WSMan fault.</exception>
    /// <exception cref="WSManProtocolException">
    /// The response was not valid XML, was not the expected message, or did not relate to the request.
    /// </exception>
    public static XElement Parse(
        ReadOnlySpan<byte> data,
        Guid? relatesTo = null,
        string? expectedAction = null)
    {
        if (data.IsEmpty)
        {
            throw new WSManProtocolException("Received empty WSMan response");
        }

        XElement envelope;
        try
        {
            // There is no XmlReader that can read from a span so pin the data and read it as a stream, the parsing
            // is synchronous so the pin is released once the envelope has been loaded.
            unsafe
            {
                fixed (byte* ptr = data)
                {
                    using UnmanagedMemoryStream stream = new(ptr, data.Length);
                    using XmlReader reader = XmlReader.Create(stream, s_readerSettings);
                    envelope = XElement.Load(reader);
                }
            }
        }
        catch (XmlException e)
        {
            // ExchangeOnline can return a helpful error that isn't XML so just display the response.
            throw new WSManProtocolException($"Received non-xml response: {Encoding.UTF8.GetString(data)}", e);
        }

        XElement header = envelope.Element(WSManNamespace.s + "Header")
            ?? throw new WSManProtocolException("WSMan envelope is missing the s:Header element");
        XElement body = envelope.Element(WSManNamespace.s + "Body")
            ?? throw new WSManProtocolException("WSMan envelope is missing the s:Body element");

        string action = header.Element(WSManNamespace.wsa + "Action")?.Value
            ?? throw new WSManProtocolException("WSMan envelope is missing the wsa:Action header");
        if (action == WSManAction.Fault || action == WSManAction.FaultAddressing)
        {
            throw WSManFault.FromPayload(body);
        }
        else if (expectedAction is not null && action != expectedAction)
        {
            throw new WSManProtocolException($"Expecting action '{expectedAction}' but got '{action}'");
        }

        if (relatesTo is not null)
        {
            string? rawRelatesTo = header.Element(WSManNamespace.wsa + "RelatesTo")?.Value;
            Guid? actualRelatesTo = rawRelatesTo is null ? null : ParseUuid(rawRelatesTo);
            if (actualRelatesTo != relatesTo)
            {
                throw new WSManProtocolException(
                    "Received related id does not match related expected message id: " +
                    $"Sent: {relatesTo}, Received: {rawRelatesTo}");
            }
        }

        return body;
    }

    /// <summary>Parses a uuid:XXX reference value into a Guid.</summary>
    /// <param name="value">The raw value to parse.</param>
    /// <returns>The parsed Guid.</returns>
    /// <exception cref="WSManProtocolException">The value is not a valid uuid reference.</exception>
    public static Guid ParseUuid(string value)
    {
        ReadOnlySpan<char> raw = value.AsSpan().Trim();
        if (raw.StartsWith("uuid:", StringComparison.OrdinalIgnoreCase))
        {
            raw = raw[5..];
        }

        if (!Guid.TryParse(raw, out Guid result))
        {
            throw new WSManProtocolException($"Failed to parse uuid value '{value}'");
        }

        return result;
    }
}
