using System;
using System.Xml.Linq;

namespace PSWSMan.Lib;

/// <summary>The response to a WinRS shell Create request.</summary>
public sealed class WSManCreateResponse : IWSManPayload<WSManCreateResponse>
{
    /// <summary>The selectors that identify the created shell.</summary>
    public SelectorSet Selectors { get; }

    /// <summary>The identifier of the created shell.</summary>
    public Guid ShellId { get; }

    /// <summary>The resource URI of the created shell.</summary>
    public string ResourceUri { get; }

    private WSManCreateResponse(SelectorSet selectors, Guid shellId, string resourceUri)
    {
        Selectors = selectors;
        ShellId = shellId;
        ResourceUri = resourceUri;
    }

    /// <inheritdoc />
    public static WSManCreateResponse Parse(ReadOnlySpan<byte> data, Guid? relatesTo = null)
    {
        XElement body = WSManEnvelope.Parse(data, relatesTo, WSManAction.CreateResponse);

        XElement selectors = body.Element(WSManNamespace.wst + "ResourceCreated")
            ?.Element(WSManNamespace.wsa + "ReferenceParameters")
            ?.Element(WSManNamespace.wsman + "SelectorSet")
            ?? throw new WSManProtocolException("CreateResponse is missing the wsman:SelectorSet element");

        XElement shell = body.Element(WSManNamespace.rsp + "Shell")
            ?? throw new WSManProtocolException("CreateResponse is missing the rsp:Shell element");
        Guid shellId = WSManEnvelope.ParseUuid(shell.Element(WSManNamespace.rsp + "ShellId")?.Value
            ?? throw new WSManProtocolException("CreateResponse is missing the rsp:ShellId element"));
        string resourceUri = shell.Element(WSManNamespace.rsp + "ResourceUri")?.Value
            ?? throw new WSManProtocolException("CreateResponse is missing the rsp:ResourceUri element");

        return new(new SelectorSet(selectors), shellId, resourceUri);
    }
}
