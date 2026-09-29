using PSWSMan.Authentication;
using PSWSMan.Connection;
using PSWSMan.Lib;
using System;
using System.Globalization;
using System.Management.Automation;
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

/// <summary>Turns the connection settings into a <see cref="WSManTransport"/>.</summary>
/// <remarks>
/// This is the one place the <see cref="WinRMSessionOption"/> values are mapped to credentials, TLS options and
/// timeouts, so a PSRP session over the patched transport, a WinRM session and a WinRS command built from the same
/// options connect the same way.
/// </remarks>
internal static class WSManTransportFactory
{
    // Extra time on top of the server side operation timeout before a request is considered lost.
    private static readonly TimeSpan s_requestTimeoutGrace = TimeSpan.FromSeconds(30);

    /// <summary>Creates the transport for a connection.</summary>
    /// <param name="connectionUri">The endpoint to connect to.</param>
    /// <param name="credential">The explicit credential, null for the current user.</param>
    /// <param name="certificateThumbprint">The thumbprint of a client certificate to authenticate with.</param>
    /// <param name="options">The connection options.</param>
    /// <param name="maxEnvelopeSize">The initial maximum envelope size.</param>
    /// <param name="trace">Callback for diagnostic messages.</param>
    /// <param name="authMethod">
    /// An explicit authentication method that overrides the one in <paramref name="options"/>. Default uses that
    /// instead.
    /// </param>
    /// <returns>The transport, the caller disposes it.</returns>
    public static WSManTransport Create(
        Uri connectionUri,
        PSCredential? credential,
        string? certificateThumbprint,
        WinRMSessionOption options,
        int maxEnvelopeSize,
        Action<string> trace,
        AuthenticationMethod authMethod = AuthenticationMethod.Default)
    {
        SslClientAuthenticationOptions? tlsOptions = null;
        if (connectionUri.Scheme == Uri.UriSchemeHttps)
        {
            tlsOptions = options.TlsOption ?? BuildTlsOptions(connectionUri, certificateThumbprint, options);

            // If using client certificates, disable TLS session resumption to ensure the certificate exchange occurs
            // on every new connection.
            if ((tlsOptions.ClientCertificates?.Count ?? 0) > 0)
            {
                tlsOptions.AllowTlsResume = false;
            }
        }

        if (authMethod == AuthenticationMethod.Default)
        {
            authMethod = options.AuthMethod;
        }

        NegotiateOptions negoOptions = new()
        {
            Flags = NegotiateRequestFlags.Default,
            SPNHostName = options.SPNHostName ?? connectionUri.DnsSafeHost,
            SPNService = options.SPNService,
        };
        if (options.RequestKerberosDelegate)
        {
            negoOptions.Flags |= NegotiateRequestFlags.Delegate;
        }

        WSManCredential wsmanCredential = WSManCredentialFactory.Create(
            authMethod,
            options.AuthProvider,
            credential?.UserName,
            credential?.GetNetworkCredential()?.Password,
            tlsOptions,
            options.CredSSPTlsOption,
            options.CredSSPAuthMethod,
            negoOptions
        );

        // A zero or negative timeout means the default.
        TimeSpan connectTimeout = options.OpenTimeout > TimeSpan.Zero
            ? options.OpenTimeout
            : TimeSpan.FromSeconds(10);
        TimeSpan operationTimeout = options.OperationTimeout > TimeSpan.Zero
            ? options.OperationTimeout
            : TimeSpan.FromSeconds(180);

        bool encrypt = !(connectionUri.Scheme == Uri.UriSchemeHttps || options.NoEncryption);
        WSManConnectionOptions connOptions = new(connectionUri, wsmanCredential)
        {
            TlsOptions = tlsOptions,
            Encrypt = encrypt,
            ConnectTimeout = connectTimeout,
            RequestTimeout = operationTimeout + s_requestTimeoutGrace,
            Trace = trace,
        };

        WSManConnectionPool pool = new(connOptions);
        // wsman:Locale is the language for messages and maps to the UI culture, wsmv:DataLocale is the format for
        // data and maps to the culture. The server applies them to Get-UICulture and Get-Culture respectively.
        CultureInfo culture = options.Culture ?? CultureInfo.CurrentCulture;
        CultureInfo uiCulture = options.UICulture ?? CultureInfo.CurrentUICulture;
        WSManClient client = new(
            connectionUri,
            maxEnvelopeSize,
            operationTimeout,
            uiCulture.Name,
            dataLocale: culture.Name);

        return new WSManTransport(pool, client);
    }

    private static SslClientAuthenticationOptions BuildTlsOptions(Uri connectionUri, string? certificateThumbprint,
        WinRMSessionOption options)
    {
        SslClientAuthenticationOptions tlsOptions = new()
        {
            TargetHost = connectionUri.DnsSafeHost,
        };

        if (options.SkipCACheck || options.SkipCNCheck)
        {
            bool skipCA = options.SkipCACheck;
            bool skipCN = options.SkipCNCheck;
            tlsOptions.RemoteCertificateValidationCallback = ((_1, _2, _3, sslPolicyErrors) =>
            {
                if (skipCA)
                {
                    sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateChainErrors;
                }
                if (skipCN)
                {
                    sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateNameMismatch;
                }

                return sslPolicyErrors == SslPolicyErrors.None;
            });
        }

        if (!string.IsNullOrWhiteSpace(certificateThumbprint))
        {
            X509Certificate2? cert = FindCertificate(certificateThumbprint);
            if (cert is null)
            {
                string errMsg = $"WinRM failed to find certificate with the thumbprint requested '{certificateThumbprint}'";
                throw new AuthenticationException(errMsg);
            }

            tlsOptions.ClientCertificates = new(new[] { cert });
        }
        else if (options.ClientCertificate != null)
        {
            tlsOptions.ClientCertificates = new(new[] { options.ClientCertificate });
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
