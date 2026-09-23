using System;

namespace PSWSMan.Lib;

/// <summary>The response to a WinRS Signal request.</summary>
public sealed class WSManSignalResponse : IWSManPayload<WSManSignalResponse>
{
    private WSManSignalResponse()
    { }

    /// <inheritdoc />
    public static WSManSignalResponse Parse(ReadOnlySpan<byte> data, Guid? relatesTo = null)
    {
        WSManEnvelope.Parse(data, relatesTo, WSManAction.SignalResponse);
        return new();
    }
}
