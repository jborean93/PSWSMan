using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace PSWSMan.Lib;

/// <summary>The response to a WinRS Receive request.</summary>
public sealed class WSManReceiveResponse : IWSManPayload<WSManReceiveResponse>
{
    /// <summary>The state URI of the command, if returned, see <see cref="CommandState"/> for known values.</summary>
    public string? State { get; }

    /// <summary>The exit code of the command, if it has finished.</summary>
    public int? ExitCode { get; }

    /// <summary>The output data received, keyed by the stream name.</summary>
    public IReadOnlyDictionary<string, byte[][]> Streams { get; }

    private WSManReceiveResponse(string? state, int? exitCode, IReadOnlyDictionary<string, byte[][]> streams)
    {
        State = state;
        ExitCode = exitCode;
        Streams = streams;
    }

    /// <inheritdoc />
    public static WSManReceiveResponse Parse(ReadOnlySpan<byte> data, Guid? relatesTo = null)
    {
        XElement body = WSManEnvelope.Parse(data, relatesTo, WSManAction.ReceiveResponse);

        XElement resp = body.Element(WSManNamespace.rsp + "ReceiveResponse")
            ?? throw new WSManProtocolException("ReceiveResponse is missing the rsp:ReceiveResponse element");

        Dictionary<string, List<byte[]>> rawStreams = new();
        foreach (XElement stream in resp.Elements(WSManNamespace.rsp + "Stream"))
        {
            string streamName = stream.Attribute("Name")?.Value
                ?? throw new WSManProtocolException("ReceiveResponse rsp:Stream is missing the Name attribute");
            if (!rawStreams.TryGetValue(streamName, out List<byte[]>? chunks))
            {
                chunks = new();
                rawStreams[streamName] = chunks;
            }

            try
            {
                chunks.Add(Convert.FromBase64String(stream.Value));
            }
            catch (FormatException e)
            {
                throw new WSManProtocolException($"ReceiveResponse rsp:Stream '{streamName}' is not valid base64", e);
            }
        }
        Dictionary<string, byte[][]> streams = rawStreams.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.ToArray());

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

        return new(state, exitCode, streams);
    }
}
