using System;

namespace PSWSMan.Authentication;

public abstract class AuthenticationContext : IDisposable
{
    /// <summary>
    /// Whether the authentication context has completed the authentication phase.
    /// No more data should be processed through Step once this is True.
    /// </summary>
    public abstract bool Complete { get; }

    /// <summary>
    /// The label to use in the Authorization header, e.g. Basic, Negotiate, CredSSP.
    /// </summary>
    public abstract string HttpAuthLabel { get; }

    /// <summary>
    /// Optional string that descrbes what stage the authentication context was up to.
    /// This is displayed with an authentication failure exception when the server fails
    /// to respond with a token to process.
    /// </summary>
    public virtual string? AuthenticationStage { get; }

    /// <summary>
    /// Provide the next authentication token
    /// </summary>
    /// <remarks>
    /// Some authentication contexts may require multiple calls to Step to complete.
    /// </remarks>
    /// <param name="inToken">Optional input data from the server to process.</param>
    /// <param name="options">Options specific to negotiate providers.</param>
    /// <param name="bindings">Optional channel bindings used with a HTTPS connection.</param>
    /// <returns>
    /// The authentication token to set in the Authorization header.
    /// If this is null no Authorization header is added to the request.
    /// If this is an empty byte[] then only the HttpAuthLabel is added ot the Authorization header.
    /// </returns>
    protected internal abstract byte[]? Step(Span<byte> inToken, NegotiateOptions options, ChannelBindings? bindings);

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    protected virtual void Dispose(bool disposing)
    { }
    ~AuthenticationContext() => Dispose(false);
}
