using System;

namespace PSWSMan.Lib;

/// <summary>Defines a WSMan payload type that can be parsed from a raw response.</summary>
/// <typeparam name="TSelf">The payload type that is parsed.</typeparam>
public interface IWSManPayload<TSelf> where TSelf : IWSManPayload<TSelf>
{
    /// <summary>Parses a raw WSMan response into this payload type.</summary>
    /// <param name="data">The raw response from the server.</param>
    /// <param name="relatesTo">The MessageId of the request, if set the response RelatesTo must match it.</param>
    /// <returns>The parsed payload.</returns>
    /// <exception cref="WSManFault">The server returned a WSMan fault.</exception>
    /// <exception cref="WSManProtocolException">
    /// The response was not valid XML, was not the expected message, or did not relate to the request.
    /// </exception>
    static abstract TSelf Parse(ReadOnlySpan<byte> data, Guid? relatesTo = null);
}
