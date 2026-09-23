using System;
using System.Text;
using System.Xml.Linq;

namespace PSWSMan.Lib.Tests;

/// <summary>Builders for fake server responses and helpers for inspecting built requests.</summary>
internal static class TestHelpers
{
    public const string ShellUri = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell";

    public static readonly Uri ConnectionUri = new("http://server.domain.test:5985/wsman");

    public static WSManClient NewWSManClient(
        int maxEnvelopeSize = 153600,
        TimeSpan? operationTimeout = null,
        string locale = "en-US",
        string? dataLocale = null)
    {
        return new(ConnectionUri, maxEnvelopeSize, operationTimeout ?? TimeSpan.FromSeconds(30), locale, dataLocale);
    }

    public static WinRSClient NewWinRSClient(SelectorSet? selectors = null)
    {
        return new(NewWSManClient(), ShellUri, selectors);
    }

    public static SelectorSet NewShellSelectors(Guid shellId)
    {
        SelectorSet selectors = new();
        selectors.Add("ShellId", shellId.ToString().ToUpperInvariant());
        return selectors;
    }

    /// <summary>Parses the XML envelope of a request built by the library.</summary>
    public static XElement ParseRequest(WSManRequest request)
    {
        return XElement.Parse(Encoding.UTF8.GetString(request.Content));
    }

    public static XElement Header(this XElement envelope)
    {
        return envelope.Element(WSManNamespace.s + "Header")
            ?? throw new InvalidOperationException("Envelope is missing s:Header");
    }

    public static XElement Body(this XElement envelope)
    {
        return envelope.Element(WSManNamespace.s + "Body")
            ?? throw new InvalidOperationException("Envelope is missing s:Body");
    }

    public static string? HeaderValue(this XElement envelope, XName name)
    {
        return envelope.Header().Element(name)?.Value;
    }

    public static string UuidString(Guid value)
    {
        return $"uuid:{value.ToString().ToUpperInvariant()}";
    }

    /// <summary>Builds a full response envelope from the server with the given action and body content.</summary>
    public static byte[] Response(string action, Guid? relatesTo = null, params object?[] bodyContent)
    {
        XElement header = new(WSManNamespace.s + "Header",
            new XElement(WSManNamespace.wsa + "Action", action),
            new XElement(WSManNamespace.wsa + "MessageID", UuidString(Guid.NewGuid())),
            new XElement(WSManNamespace.wsa + "To", "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"));
        if (relatesTo is not null)
        {
            header.Add(new XElement(WSManNamespace.wsa + "RelatesTo", UuidString(relatesTo.Value)));
        }

        return Envelope(header, new XElement(WSManNamespace.s + "Body", bodyContent));
    }

    public static byte[] Envelope(XElement? header, XElement? body)
    {
        return ToBytes(new XElement(WSManNamespace.s + "Envelope", header, body));
    }

    public static byte[] ToBytes(XElement element)
    {
        return Encoding.UTF8.GetBytes(element.ToString(SaveOptions.DisableFormatting));
    }

    public static byte[] ToBytes(string raw)
    {
        return Encoding.UTF8.GetBytes(raw);
    }

    /// <summary>Builds an s:Fault body element in the shape WinRM returns.</summary>
    public static XElement Fault(
        string? code = "s:Receiver",
        string? subCode = null,
        string? reason = null,
        string? faultDetail = null,
        string? wsmanFaultCode = null,
        string? machine = null,
        object? message = null)
    {
        XElement fault = new(WSManNamespace.s + "Fault");

        if (code is not null)
        {
            XElement codeElement = new(WSManNamespace.s + "Code", new XElement(WSManNamespace.s + "Value", code));
            if (subCode is not null)
            {
                codeElement.Add(new XElement(WSManNamespace.s + "Subcode",
                    new XElement(WSManNamespace.s + "Value", subCode)));
            }
            fault.Add(codeElement);
        }

        if (reason is not null)
        {
            fault.Add(new XElement(WSManNamespace.s + "Reason",
                new XElement(WSManNamespace.s + "Text", new XAttribute(WSManNamespace.xml + "lang", "en-US"), reason)));
        }

        if (faultDetail is not null || wsmanFaultCode is not null || machine is not null || message is not null)
        {
            XElement detail = new(WSManNamespace.s + "Detail");
            if (faultDetail is not null)
            {
                detail.Add(new XElement(WSManNamespace.wsman + "FaultDetail", faultDetail));
            }

            XElement wsmanFault = new(WSManNamespace.wsmanfault + "WSManFault",
                new XAttribute(XNamespace.Xmlns + "f", WSManNamespace.wsmanfault));
            if (wsmanFaultCode is not null)
            {
                wsmanFault.SetAttributeValue("Code", wsmanFaultCode);
            }
            if (machine is not null)
            {
                wsmanFault.SetAttributeValue("Machine", machine);
            }
            if (message is not null)
            {
                wsmanFault.Add(new XElement(WSManNamespace.wsmanfault + "Message", message));
            }
            detail.Add(wsmanFault);

            fault.Add(detail);
        }

        return fault;
    }

    /// <summary>Builds the body content of a CreateResponse for a PowerShell shell.</summary>
    public static object[] CreateResponseBody(
        Guid shellId,
        string resourceUri = ShellUri,
        bool includeSelectorSet = true,
        bool includeShell = true,
        bool includeShellId = true,
        bool includeResourceUri = true)
    {
        string shellIdStr = shellId.ToString().ToUpperInvariant();

        XElement referenceParameters = new(WSManNamespace.wsa + "ReferenceParameters",
            new XElement(WSManNamespace.wsman + "ResourceURI", resourceUri));
        if (includeSelectorSet)
        {
            referenceParameters.Add(new XElement(WSManNamespace.wsman + "SelectorSet",
                new XElement(WSManNamespace.wsman + "Selector", new XAttribute("Name", "ShellId"), shellIdStr)));
        }

        XElement resourceCreated = new(WSManNamespace.wst + "ResourceCreated",
            new XElement(WSManNamespace.wsa + "Address", ConnectionUri),
            referenceParameters);

        if (!includeShell)
        {
            return new object[] { resourceCreated };
        }

        XElement shell = new(WSManNamespace.rsp + "Shell",
            includeShellId ? new XElement(WSManNamespace.rsp + "ShellId", shellIdStr) : null,
            new XElement(WSManNamespace.rsp + "Name", "Runspace1"),
            includeResourceUri ? new XElement(WSManNamespace.rsp + "ResourceUri", resourceUri) : null,
            new XElement(WSManNamespace.rsp + "Owner", "DOMAIN\\user"),
            new XElement(WSManNamespace.rsp + "ClientIP", "192.168.1.10"),
            new XElement(WSManNamespace.rsp + "ProcessId", "1234"),
            new XElement(WSManNamespace.rsp + "IdleTimeOut", "PT7200.000S"),
            new XElement(WSManNamespace.rsp + "InputStreams", "stdin pr"),
            new XElement(WSManNamespace.rsp + "OutputStreams", "stdout"),
            new XElement(WSManNamespace.rsp + "MaxIdleTimeOut", "PT2147483.647S"),
            new XElement(WSManNamespace.rsp + "Locale", "en-US"),
            new XElement(WSManNamespace.rsp + "DataLocale", "en-US"),
            new XElement(WSManNamespace.rsp + "CompressionMode", "XpressCompression"),
            new XElement(WSManNamespace.rsp + "ProfileLoaded", "Yes"),
            new XElement(WSManNamespace.rsp + "Encoding", "UTF8"),
            new XElement(WSManNamespace.rsp + "BufferMode", "Block"),
            new XElement(WSManNamespace.rsp + "State", "Connected"),
            new XElement(WSManNamespace.rsp + "ShellRunTime", "P0DT0H0M0S"),
            new XElement(WSManNamespace.rsp + "ShellInactivity", "P0DT0H0M0S"));

        return new object[] { resourceCreated, shell };
    }

    public static XElement Stream(string name, byte[] data, Guid? commandId = null, bool end = false)
    {
        XElement stream = new(WSManNamespace.rsp + "Stream",
            new XAttribute("Name", name),
            Convert.ToBase64String(data));
        if (commandId is not null)
        {
            stream.SetAttributeValue("CommandId", commandId.Value.ToString().ToUpperInvariant());
        }
        if (end)
        {
            stream.SetAttributeValue("End", "true");
        }

        return stream;
    }

    public static XElement CommandState(string state, Guid? commandId = null, string? exitCode = null)
    {
        XElement commandState = new(WSManNamespace.rsp + "CommandState", new XAttribute("State", state));
        if (commandId is not null)
        {
            commandState.SetAttributeValue("CommandId", commandId.Value.ToString().ToUpperInvariant());
        }
        if (exitCode is not null)
        {
            commandState.Add(new XElement(WSManNamespace.rsp + "ExitCode", exitCode));
        }

        return commandState;
    }
}
