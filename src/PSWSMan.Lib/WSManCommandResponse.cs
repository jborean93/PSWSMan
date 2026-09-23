using System;
using System.Xml.Linq;

namespace PSWSMan.Lib;

/// <summary>The response to a WinRS Command request.</summary>
public sealed class WSManCommandResponse : IWSManPayload<WSManCommandResponse>
{
    /// <summary>The identifier of the command that was started.</summary>
    public Guid CommandId { get; }

    private WSManCommandResponse(Guid commandId)
    {
        CommandId = commandId;
    }

    /// <inheritdoc />
    public static WSManCommandResponse Parse(ReadOnlySpan<byte> data, Guid? relatesTo = null)
    {
        XElement body = WSManEnvelope.Parse(data, relatesTo, WSManAction.CommandResponse);

        Guid commandId = WSManEnvelope.ParseUuid(body.Element(WSManNamespace.rsp + "CommandResponse")
            ?.Element(WSManNamespace.rsp + "CommandId")?.Value
            ?? throw new WSManProtocolException("CommandResponse is missing the rsp:CommandId element"));

        return new(commandId);
    }
}
