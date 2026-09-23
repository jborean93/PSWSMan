using System;

namespace PSWSMan.Lib;

/// <summary>An exception raised when a WSMan response is malformed or not what was expected.</summary>
public class WSManProtocolException : WSManException
{
    /// <summary>Creates a new WSMan protocol exception.</summary>
    public WSManProtocolException() { }

    /// <summary>Creates a new WSMan protocol exception with a message.</summary>
    /// <param name="message">The error message.</param>
    public WSManProtocolException(string message) : base(message) { }

    /// <summary>Creates a new WSMan protocol exception with a message and inner exception.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The exception that caused this error.</param>
    public WSManProtocolException(string message, Exception innerException) : base(message, innerException) { }
}
