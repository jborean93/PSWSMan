using System;
using System.Net.Security;
using System.Threading;

namespace PSWSMan.Connection;

/// <summary>Settings shared by every HTTP connection a <see cref="WSManConnectionPool"/> opens to one endpoint.</summary>
internal sealed class WSManConnectionOptions
{
    /// <summary>The WSMan endpoint, e.g. http://host:5985/wsman or https://host:5986/wsman.</summary>
    public Uri ConnectionUri { get; }

    /// <summary>The credential used to create a new authentication context for each connection.</summary>
    public IWSManCredential Credential { get; }

    /// <summary>
    /// TLS options for a https connection. The value is copied for each connection so the instance provided is never
    /// mutated. Must be null for a http connection.
    /// </summary>
    public SslClientAuthenticationOptions? TlsOptions { get; init; }

    /// <summary>Whether to wrap each message in WSMan message level encryption. Requires a capable credential.</summary>
    public bool Encrypt { get; init; }

    /// <summary>The time allowed to establish the TCP connection and TLS handshake.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The upper bound for a single request/response exchange, including the server side operation timeout of a long
    /// running Receive. This is what surfaces a black-holed connection. Defaults to no limit.
    /// </summary>
    public TimeSpan RequestTimeout { get; init; } = Timeout.InfiniteTimeSpan;

    /// <summary>The maximum number of concurrently open connections in the pool.</summary>
    public int MaxConnections { get; init; } = int.MaxValue;

    /// <summary>The User-Agent header sent with every request.</summary>
    public string UserAgent { get; init; } = "PSWSMan Client";

    /// <summary>Creates the options for a WSMan endpoint.</summary>
    /// <param name="connectionUri">The WSMan endpoint.</param>
    /// <param name="credential">The credential used to authenticate each connection.</param>
    public WSManConnectionOptions(Uri connectionUri, IWSManCredential credential)
    {
        ConnectionUri = connectionUri;
        Credential = credential;
    }

    internal void Validate()
    {
        bool isHttps = ConnectionUri.Scheme == Uri.UriSchemeHttps;
        if (isHttps && TlsOptions is null)
        {
            throw new ArgumentException("TlsOptions must be set for a https connection.");
        }
        else if (!isHttps && TlsOptions is not null)
        {
            throw new ArgumentException("TlsOptions can only be set for a https connection.");
        }

        if (MaxConnections < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxConnections), "MaxConnections must be at least 1.");
        }

        if (Encrypt)
        {
            // Contexts are cheap to create until they are stepped so create a throwaway one to validate the
            // credential up front rather than on the first request.
            using IWSManAuthenticationContext context = Credential.CreateAuthContext(null);
            if (context is not IWSManEncryptionContext)
            {
                throw new ArgumentException(
                    $"Cannot encrypt WSMan payload as {context.GetType().Name} does not support message encryption.");
            }
        }
    }
}
