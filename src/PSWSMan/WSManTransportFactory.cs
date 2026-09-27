using PSWSMan.Authentication;
using PSWSMan.Connection;
using PSWSMan.Lib;
using System;
using System.Management.Automation.Runspaces;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PSWSMan;

/// <summary>The connection pool and envelope builder for one WSMan endpoint.</summary>
/// <param name="Pool">The authenticated connections to the endpoint.</param>
/// <param name="Client">The envelope builder holding the session id, envelope size and locales.</param>
internal sealed record WSManTransport(WSManConnectionPool Pool, WSManClient Client) : IDisposable
{
    public void Dispose() => Pool.Dispose();
}

/// <summary>Turns the PowerShell connection settings into a <see cref="WSManTransport"/>.</summary>
/// <remarks>
/// This is the one place the <see cref="WSManConnectionInfo"/> and <see cref="PSWSManSessionOption"/> values are
/// mapped to credentials, TLS options and timeouts, so a PSRP session and a WinRS command built from the same
/// parameters connect the same way.
/// </remarks>
internal static class WSManTransportFactory
{
    // Extra time on top of the server side operation timeout before a request is considered lost.
    private static readonly TimeSpan s_requestTimeoutGrace = TimeSpan.FromSeconds(30);

    /// <summary>The endpoint URI of a connection info, with the default WSMan port when none was given.</summary>
    /// <param name="connInfo">The connection info.</param>
    /// <returns>The URI to connect to.</returns>
    /// <remarks>
    /// PowerShell leaves the port off the URI when the caller did not specify one, which <see cref="Uri"/> reads
    /// as 80 or 443. The flag on the connection info says the WSMan defaults are meant instead.
    /// </remarks>
    public static Uri GetConnectionUri(WSManConnectionInfo connInfo)
    {
        Uri connectionUri = connInfo.ConnectionUri;
        if (connInfo.UseDefaultWSManPort)
        {
            UriBuilder uriBuilder = new(connectionUri)
            {
                Port = connectionUri.Scheme == Uri.UriSchemeHttps ? 5986 : 5985,
            };
            connectionUri = uriBuilder.Uri;
        }

        return connectionUri;
    }

    /// <summary>Reads the PSWSMan specific options that New-PSWSManSessionOption attaches to an object.</summary>
    /// <param name="source">The PSSessionOption or WSManConnectionInfo to read from.</param>
    /// <returns>The extra options, or null when the object has none.</returns>
    public static PSWSManSessionOption? GetExtraOptions(object source)
    {
        return System.Management.Automation.PSObject.AsPSObject(source)
            .Properties[PSWSManSessionOption.PSWSMAN_SESSION_OPTION_PROP]
            ?.Value as PSWSManSessionOption;
    }

    /// <summary>Creates the transport for a connection.</summary>
    /// <param name="connectionUri">The endpoint to connect to.</param>
    /// <param name="connInfo">The PowerShell connection settings.</param>
    /// <param name="extraConnInfo">The PSWSMan specific settings, if any.</param>
    /// <param name="maxEnvelopeSize">The initial maximum envelope size.</param>
    /// <param name="trace">Callback for diagnostic messages.</param>
    /// <param name="authMethod">
    /// An explicit authentication method that overrides the one in <paramref name="extraConnInfo"/> and the
    /// mechanism in <paramref name="connInfo"/>. Default uses those instead.
    /// </param>
    /// <returns>The transport, the caller disposes it.</returns>
    public static WSManTransport Create(
        Uri connectionUri,
        WSManConnectionInfo connInfo,
        PSWSManSessionOption? extraConnInfo,
        int maxEnvelopeSize,
        Action<string> trace,
        AuthenticationMethod authMethod = AuthenticationMethod.Default)
    {
        SslClientAuthenticationOptions? tlsOptions = null;
        if (connectionUri.Scheme == Uri.UriSchemeHttps)
        {
            tlsOptions = extraConnInfo?.TlsOption ?? BuildTlsOptions(connectionUri, connInfo, extraConnInfo);

            // If using client certificates, disable TLS session resumption to ensure the certificate exchange occurs
            // on every new connection.
            if ((tlsOptions.ClientCertificates?.Count ?? 0) > 0)
            {
                tlsOptions.AllowTlsResume = false;
            }
        }

        // An explicit method wins, then the extra options, then the builtin mechanism mapped to our known enum.
        if (authMethod == AuthenticationMethod.Default)
        {
            authMethod = extraConnInfo?.AuthMethod ?? AuthenticationMethod.Default;
        }
        if (authMethod == AuthenticationMethod.Default)
        {
            authMethod = connInfo.AuthenticationMechanism switch
            {
                AuthenticationMechanism.Basic => AuthenticationMethod.Basic,
                AuthenticationMechanism.Credssp => AuthenticationMethod.CredSSP,
                AuthenticationMechanism.Kerberos => AuthenticationMethod.Kerberos,
                AuthenticationMechanism.Negotiate => AuthenticationMethod.Negotiate,
                AuthenticationMechanism.NegotiateWithImplicitCredential => AuthenticationMethod.Negotiate,
                _ => AuthenticationMethod.Default,
            };
        }

        NegotiateOptions negoOptions = new()
        {
            Flags = NegotiateRequestFlags.Default,
            SPNHostName = extraConnInfo?.SPNHostName ?? connectionUri.DnsSafeHost,
            SPNService = extraConnInfo?.SPNService,
        };
        if (extraConnInfo?.RequestKerberosDelegate == true)
        {
            negoOptions.Flags |= NegotiateRequestFlags.Delegate;
        }

        WSManCredential credential = WSManCredentialFactory.Create(
            authMethod,
            extraConnInfo?.AuthProvider ?? AuthenticationProvider.Default,
            connInfo.Credential?.UserName,
            connInfo.Credential?.GetNetworkCredential()?.Password,
            tlsOptions,
            extraConnInfo?.CredSSPTlsOption,
            extraConnInfo?.CredSSPAuthMethod ?? AuthenticationMethod.Default,
            negoOptions
        );

        // The PowerShell timeouts are in milliseconds, 0 means the default.
        TimeSpan connectTimeout = connInfo.OpenTimeout > 0
            ? TimeSpan.FromMilliseconds(connInfo.OpenTimeout)
            : TimeSpan.FromSeconds(10);
        TimeSpan operationTimeout = connInfo.OperationTimeout > 0
            ? TimeSpan.FromMilliseconds(connInfo.OperationTimeout)
            : TimeSpan.FromSeconds(180);

        bool encrypt = !(connectionUri.Scheme == Uri.UriSchemeHttps || connInfo.NoEncryption);
        WSManConnectionOptions options = new(connectionUri, credential)
        {
            TlsOptions = tlsOptions,
            Encrypt = encrypt,
            ConnectTimeout = connectTimeout,
            RequestTimeout = operationTimeout + s_requestTimeoutGrace,
            Trace = trace,
        };

        WSManConnectionPool pool = new(options);
        // wsman:Locale is the language for messages and maps to the UI culture, wsmv:DataLocale is the format for
        // data and maps to the culture. The server applies them to Get-UICulture and Get-Culture respectively.
        WSManClient client = new(
            connectionUri,
            maxEnvelopeSize,
            operationTimeout,
            connInfo.UICulture?.Name ?? connInfo.Culture.Name,
            dataLocale: connInfo.Culture.Name);

        return new WSManTransport(pool, client);
    }

    private static SslClientAuthenticationOptions BuildTlsOptions(Uri connectionUri, WSManConnectionInfo connInfo,
        PSWSManSessionOption? extraConnInfo)
    {
        SslClientAuthenticationOptions tlsOptions = new()
        {
            TargetHost = connectionUri.DnsSafeHost,
        };

        if (connInfo.SkipCACheck || connInfo.SkipCNCheck)
        {
            tlsOptions.RemoteCertificateValidationCallback = ((_1, _2, _3, sslPolicyErrors) =>
            {
                if (connInfo.SkipCACheck)
                {
                    sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateChainErrors;
                }
                if (connInfo.SkipCNCheck)
                {
                    sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateNameMismatch;
                }

                return sslPolicyErrors == SslPolicyErrors.None;
            });
        }

        if (!string.IsNullOrWhiteSpace(connInfo.CertificateThumbprint))
        {
            X509Certificate2? cert = FindCertificate(connInfo.CertificateThumbprint);
            if (cert is null)
            {
                string errMsg = $"WinRM failed to find certificate with the thumbprint requested '{connInfo.CertificateThumbprint}'";
                throw new AuthenticationException(errMsg);
            }

            tlsOptions.ClientCertificates = new(new[] { cert });
        }
        else if (extraConnInfo?.ClientCertificate != null)
        {
            tlsOptions.ClientCertificates = new(new[] { extraConnInfo.ClientCertificate });
        }

        return tlsOptions;
    }

    /// <summary>Finds a certificate by thumbprint in the personal store of the current user then the machine.</summary>
    private static X509Certificate2? FindCertificate(string thumbprint)
    {
        foreach (StoreLocation location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            using X509Store store = new(StoreName.My, location);
            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            }
            catch (CryptographicException)
            {
                // The store does not exist or, on Linux, the machine personal store is not supported at all.
                continue;
            }

            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (string.Equals(cert.Thumbprint, thumbprint, StringComparison.InvariantCultureIgnoreCase))
                {
                    return cert;
                }
            }
        }

        return null;
    }
}
