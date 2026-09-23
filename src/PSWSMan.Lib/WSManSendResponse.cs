using System;

namespace PSWSMan.Lib;

/// <summary>The response to a WinRS Send request.</summary>
public sealed class WSManSendResponse : IWSManPayload<WSManSendResponse>
{
    private WSManSendResponse()
    { }

    /// <inheritdoc />
    public static WSManSendResponse Parse(ReadOnlySpan<byte> data, Guid? relatesTo = null)
    {
        WSManEnvelope.Parse(data, relatesTo, WSManAction.SendResponse);
        return new();
    }
}
