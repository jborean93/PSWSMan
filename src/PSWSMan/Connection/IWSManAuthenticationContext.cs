using System;

namespace PSWSMan.Connection;

/// <summary>A security context that authenticates one HTTP connection to a WSMan endpoint.</summary>
/// <remarks>
/// A connection creates a context through <see cref="IWSManCredential.CreateAuthContext"/> each time it opens a
/// socket and drives it with <see cref="Step"/> for every challenge round. Contexts that also implement <see cref="IWSManEncryptionContext"/> can be used for HTTP
/// message encryption once complete.
/// </remarks>
internal interface IWSManAuthenticationContext : IDisposable
{
    /// <summary>
    /// Whether the authentication exchange has finished. No more calls to <see cref="Step"/> are made once this is
    /// true and no Authorization header is sent on subsequent requests. Schemes that send credentials with every
    /// request, like Basic, never complete.
    /// </summary>
    bool Complete { get; }

    /// <summary>The scheme used in the Authorization header, e.g. Basic, Negotiate, CredSSP.</summary>
    string HttpAuthLabel { get; }

    /// <summary>
    /// Optional description of the stage the exchange is at, included in the error when the server stops responding
    /// with a token.
    /// </summary>
    string? AuthenticationStage { get; }

    /// <summary>Produces the next authentication token.</summary>
    /// <param name="inToken">The token from the server's WWW-Authenticate challenge, empty on the first call.</param>
    /// <returns>
    /// The token to send in the Authorization header. Null means no header is sent, an empty array means only the
    /// <see cref="HttpAuthLabel"/> is sent without a token.
    /// </returns>
    byte[]? Step(Span<byte> inToken);
}
