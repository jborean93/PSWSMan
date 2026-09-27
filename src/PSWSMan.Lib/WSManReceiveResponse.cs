using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace PSWSMan.Lib;

/// <summary>One rsp:Stream element of a Receive response.</summary>
/// <param name="Name">The name of the stream, e.g. stdout.</param>
/// <param name="Data">The decoded bytes of the chunk.</param>
public sealed record WSManStreamChunk(string Name, byte[] Data);

/// <summary>The response to a WinRS Receive request.</summary>
public sealed class WSManReceiveResponse : IWSManPayload<WSManReceiveResponse>
{
    /// <summary>The state URI of the command, if returned, see <see cref="CommandState"/> for known values.</summary>
    public string? State { get; }

    /// <summary>The exit code of the command, if it has finished.</summary>
    public int? ExitCode { get; }

    /// <summary>Every chunk of output in the order the server returned it, across all streams.</summary>
    public IReadOnlyList<WSManStreamChunk> Chunks { get; }

    private WSManReceiveResponse(string? state, int? exitCode, IReadOnlyList<WSManStreamChunk> chunks)
    {
        State = state;
        ExitCode = exitCode;
        Chunks = chunks;
    }

    /// <inheritdoc />
    public static WSManReceiveResponse Parse(ReadOnlySpan<byte> data, Guid? relatesTo = null)
    {
        XElement body = WSManEnvelope.Parse(data, relatesTo, WSManAction.ReceiveResponse);

        XElement resp = body.Element(WSManNamespace.rsp + "ReceiveResponse")
            ?? throw new WSManProtocolException("ReceiveResponse is missing the rsp:ReceiveResponse element");

        List<WSManStreamChunk> chunks = new();
        foreach (XElement stream in resp.Elements(WSManNamespace.rsp + "Stream"))
        {
            string streamName = stream.Attribute("Name")?.Value
                ?? throw new WSManProtocolException("ReceiveResponse rsp:Stream is missing the Name attribute");

            try
            {
                chunks.Add(new(streamName, Convert.FromBase64String(stream.Value)));
            }
            catch (FormatException e)
            {
                throw new WSManProtocolException($"ReceiveResponse rsp:Stream '{streamName}' is not valid base64", e);
            }
        }

        string? state = null;
        int? exitCode = null;
        XElement? commandState = resp.Element(WSManNamespace.rsp + "CommandState");
        if (commandState is not null)
        {
            state = commandState.Attribute("State")?.Value;

            string? rawRC = commandState.Element(WSManNamespace.rsp + "ExitCode")?.Value;
            if (!string.IsNullOrWhiteSpace(rawRC))
            {
                exitCode = int.TryParse(rawRC, out int rc)
                    ? rc
                    : throw new WSManProtocolException($"ReceiveResponse rsp:ExitCode '{rawRC}' is not an integer");
            }
        }

        return new(state, exitCode, chunks);
    }
}
