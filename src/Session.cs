using System;
using System.Management.Automation;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan;

internal static class GlobalState
{
    /// <summary>The GSSAPI/SSPI provider that is used.</summary>
    public static GssapiProvider GssapiProvider;

    /// <summary>The loaded GSSAPI library on Linux.</summary>
    internal static LibraryInfo? GssapiLib;
}

public sealed class WSManSession : IDisposable
{
    private readonly CreateNewConnection _connectionFactory;

    public Uri Uri { get; }

    public Guid Id => WinRS.ShellId;

    internal WSManConnection Connection { get; }

    internal WinRSClient WinRS { get; }

    internal delegate WSManConnection CreateNewConnection();

    internal WSManSession(Uri uri, WinRSClient winrs, CreateNewConnection connectionFactory)
    {
        _connectionFactory = connectionFactory;
        Uri = uri;
        Connection = connectionFactory();
        WinRS = winrs;
    }

    internal WSManSession Copy()
    {
        return new(Uri, WinRS, _connectionFactory);
    }

    internal async Task<T> PostRequest<T>(string payload, CancellationToken cancelToken = default)
        where T : WSManPayload
    {
        string resp = await Connection.SendMessage(payload, cancelToken);
        return WinRS.ReceiveData<T>(resp);
    }

    public void Dispose()
    {
        Connection.Dispose();
        GC.SuppressFinalize(this);
    }
    ~WSManSession() { Dispose(); }
}

internal static class WSManSessionFactory
{
    internal static WSManSession Create(
        Uri uri,
        bool isTls,
        string resourceUri,
        AuthenticationMethod authMethod,
        PSCredential? credential,
        WinRSSessionOption sessionOption)
    {
        WSManClient wsman = new(
            uri,
            153600,
            sessionOption.OperationTimeout == 0 ? 30 : sessionOption.OperationTimeout,
            sessionOption.Culture ?? "en-US",
            sessionOption.UICulutre);
        WinRSClient winrs = new(wsman, resourceUri);

        SslClientAuthenticationOptions? sslOptions = sessionOption.SslOptions;
        SslClientAuthenticationOptions? credSSPSslOptions = null;
        if (sslOptions is null && isTls)
        {
            sslOptions = new()
            {
                TargetHost = uri.DnsSafeHost,
            };

            if (sessionOption.SkipCertificateCheck)
            {
                sslOptions.RemoteCertificateValidationCallback = (_1, _2, _3, _4) => true;
            }
        }
        else
        {
            credSSPSslOptions = sslOptions;
        }

        if (authMethod == AuthenticationMethod.Default)
        {
            authMethod = GlobalState.GssapiProvider == GssapiProvider.None
                ? AuthenticationMethod.Basic
                : AuthenticationMethod.Negotiate;
        }

        WSManSession.CreateNewConnection connectionFactory = (() =>
        {
            bool encrypt = !(isTls || sessionOption.NoEncryption);
            string spnService = sessionOption.SPNService ?? "host";
            string spnHostname = sessionOption.SPNHostname ?? uri.DnsSafeHost;
            AuthenticationProvider authProvider = GenerateAuthProvider(
                authMethod,
                encrypt,
                credential,
                sslOptions,
                spnService,
                spnHostname,
                sessionOption.RequestDelegate,
                credSSPSslOptions);

            return new(uri, authProvider, sslOptions, encrypt);
        });

        return new WSManSession(uri, winrs, connectionFactory);
    }

    internal static AuthenticationProvider GenerateAuthProvider(
        AuthenticationMethod authMethod,
        bool encrypt,
        PSCredential? credential,
        SslClientAuthenticationOptions? sslOptions,
        string spnService,
        string spnHostname,
        bool requestDelegate,
        SslClientAuthenticationOptions? credSSPSslOption)
    {
        if (authMethod == AuthenticationMethod.Default)
        {
            // FIXME: Select based on whether GSSAPI/Negotiate is present
            authMethod = AuthenticationMethod.Negotiate;
        }

        AuthenticationProvider authProvider;
        if (authMethod == AuthenticationMethod.Basic)
        {
            authProvider = new BasicAuthProvider(
                credential?.UserName,
                credential?.GetNetworkCredential()?.Password
            );
        }
        else if (authMethod == AuthenticationMethod.Certificate)
        {
            if (sslOptions is null)
            {
                throw new ArgumentException("Cannot use Certificate auth without a HTTPS connection");
            }
            // Need to set the relevant sslOptions for this somehow.
            // request.Headers.Add("Authorization", "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual");
            throw new NotImplementedException(authMethod.ToString());
        }
        else if (authMethod == AuthenticationMethod.CredSSP)
        {
            if (credential == null)
            {
                throw new ArgumentException("Credential must be set for CredSSP authentication");
            }

            string domainName = "";
            string username = credential.UserName;
            string password = credential.GetNetworkCredential().Password;
            if (username.Contains('\\'))
            {
                string[] stringSplit = username.Split('\\', 2);
                domainName = stringSplit[0];
                username = stringSplit[1];
            }

            SecurityContext subAuth = SecurityContext.GetPlatformSecurityContext(
                credential.UserName,
                password,
                AuthenticationMethod.Negotiate,
                spnService,
                spnHostname,
                false);
            TSPasswordCreds credSSPCreds = new(domainName, username, password);
            authProvider = new CredSSPAuthProvider(
                credSSPCreds,
                subAuth,
                credSSPSslOption);
        }
        else
        {
            authProvider = new NegotiateAuthProvider(
                credential?.UserName,
                credential?.GetNetworkCredential()?.Password,
                spnService,
                spnHostname,
                authMethod,
                authMethod == AuthenticationMethod.Kerberos ? "Kerberos" : "Negotiate",
                requestDelegate);
        }

        if (encrypt && authProvider is not IWinRMEncryptor)
        {
            throw new ArgumentException($"Cannot perform encryption for {authMethod}");
        }

        return authProvider;
    }
}
