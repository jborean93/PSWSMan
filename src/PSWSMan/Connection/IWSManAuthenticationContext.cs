using System;

namespace PSWSMan.Connection;

/// <summary>A security context that authenticates one HTTP connection to a WSMan endpoint.</summary>
/// <remarks>
/// A connection creates a context through <see cref="IWSManCredential.CreateAuthContext"/> each time it opens a
/// socket and drives it with <see cref="Step"/> for every challenge round, or once per request for a scheme that
/// does not exchange tokens. Contexts that also implement <see cref="IWSManEncryptionContext"/> can be used for
/// HTTP message encryption once complete.
/// </remarks>
internal interface IWSManAuthenticationContext : IDisposable
{
    /// <summary>
    /// Whether the context needs no further tokens from the server. A context that <see cref="ExchangesTokens"/>
    /// starts incomplete and becomes complete once the exchange finishes, after which <see cref="Step"/> is not
    /// called again. A context that does not exchange tokens is complete from the start.
    /// </summary>
    bool Complete { get; }

    /// <summary>
    /// Whether the context is established through a token exchange with the server. While incomplete, such a
    /// context can only continue with a challenge or 200 OK from the server. A connection whose exchange stalls cannot
    /// be reused, and once complete the socket itself is authenticated so no Authorization header is sent. Schemes
    /// that return false, like Basic and client certificates, attach their header to every request through
    /// <see cref="Step"/> with no input token.
    /// </summary>
    bool ExchangesTokens { get; }

    /// <summary>The scheme used in the Authorization header, e.g. Basic, Negotiate, CredSSP.</summary>
    string HttpAuthLabel { get; }

    /// <summary>
    /// Optional description of the stage the exchange is at, included in the error when the server stops responding
    /// with a token.
    /// </summary>
    string? AuthenticationStage { get; }

    /// <summary>Produces the next authentication token.</summary>
    /// <param name="inToken">
    /// The token from the server's WWW-Authenticate challenge. Empty on the first call, and on every call for a
    /// context that does not exchange tokens.
    /// </param>
    /// <returns>
    /// The token to send in the Authorization header. Null means no header is sent, an empty array means only the
    /// <see cref="HttpAuthLabel"/> is sent without a token.
    /// </returns>
    byte[]? Step(Span<byte> inToken);
}
