using System;

namespace PSWSMan.Lib;

/// <summary>The base exception for all WSMan errors raised by this library.</summary>
public class WSManException : Exception
{
    /// <summary>Creates a new WSMan exception.</summary>
    public WSManException() { }

    /// <summary>Creates a new WSMan exception with a message.</summary>
    /// <param name="message">The error message.</param>
    public WSManException(string message) : base(message) { }

    /// <summary>Creates a new WSMan exception with a message and inner exception.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The exception that caused this error.</param>
    public WSManException(string message, Exception innerException) : base(message, innerException) { }
}
