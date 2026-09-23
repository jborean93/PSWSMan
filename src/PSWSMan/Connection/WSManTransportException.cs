using PSWSMan.Lib;
using System;

namespace PSWSMan.Connection;

/// <summary>An error in the HTTP transport layer, such as an unexpected status or malformed encryption framing.</summary>
internal class WSManTransportException : WSManException
{
    /// <summary>Creates a new transport exception.</summary>
    public WSManTransportException() { }

    /// <summary>Creates a new transport exception with a message.</summary>
    /// <param name="message">The error message.</param>
    public WSManTransportException(string message) : base(message) { }

    /// <summary>Creates a new transport exception with a message and inner exception.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The exception that caused this error.</param>
    public WSManTransportException(string message, Exception innerException) : base(message, innerException) { }
}
