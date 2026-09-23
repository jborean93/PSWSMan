using System;

namespace PSWSMan.Lib;

/// <summary>The response to a WS-Transfer Delete request.</summary>
public sealed class WSManDeleteResponse : IWSManPayload<WSManDeleteResponse>
{
    private WSManDeleteResponse()
    { }

    /// <inheritdoc />
    public static WSManDeleteResponse Parse(ReadOnlySpan<byte> data, Guid? relatesTo = null)
    {
        WSManEnvelope.Parse(data, relatesTo, WSManAction.DeleteResponse);
        return new();
    }
}
