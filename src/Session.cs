using System;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
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
    public Uri ConnectionUri { get; }

    internal WSManSessionOption Options { get; }

    internal WSManConnection Connection { get; }

    internal WinRSClient WinRS { get; }


    internal WSManSession(Uri connectionUri, WinRSClient winrs, WSManSessionOption options)
    {
        ConnectionUri = connectionUri;
        WinRS = winrs;
        Options = options;
        Connection = options.CreateConnection();
    }

    internal WSManSession Copy()
    {
        return new(ConnectionUri, WinRS, Options);
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

public class WSManSessionOption
{
    public string? _dataLocale;

    public Uri ConnectionUri { get; set; }

    public int OperationTimeout { get; set; }

    public int MaxEnvelopeSize { get; set; } = 153600;

    public string Locale { get; set; }

    public string DataLocale
    {
        get => _dataLocale ?? Locale;
        set => _dataLocale = value;
    }

    public SslClientAuthenticationOptions? TlsOptions { get; set; }

    public AuthenticationMethod AuthMethod { get; set; } = AuthenticationMethod.Default;

    public string? UserName { get; set; }

    public string? Password { get; set; }

    public bool NoEncryption { get; set; }

    public string? SPNService { get; set; }

    public string? SPNHostName { get; set; }

    public bool RequestKerberosDelegate { get; set; }

    public SslClientAuthenticationOptions? CredSSPTlsOptions { get; set; }

    public AuthenticationMethod CredSSPAuthMethod { get; set; } = AuthenticationMethod.Negotiate;

    public X509Certificate? ClientCertificate { get; set; }

    public WSManSessionOption(Uri connectionUri, int operationTimeout, string locale)
    {
        ConnectionUri = connectionUri;
        OperationTimeout = operationTimeout;
        Locale = locale;
    }

    internal WSManSession CreateSession()
    {
        WSManClient wsman = new(
            ConnectionUri,
            MaxEnvelopeSize,
            OperationTimeout,
            Locale,
            DataLocale);
        WinRSClient winrs = new(wsman);

        return new(ConnectionUri, winrs, this);
    }

    internal WSManConnection CreateConnection()
    {
        bool isTls = ConnectionUri.Scheme == Uri.UriSchemeHttps;
        bool encrypt = !(isTls || NoEncryption);
        AuthenticationProvider authProvider = GenerateAuthProvider();

        if (encrypt && authProvider is not IWinRMEncryptor)
        {
            throw new ArgumentException($"Cannot perform encryption for {authProvider.GetType().Name}");
        }

        SslClientAuthenticationOptions? sslOptions = null;
        if (isTls)
        {
            sslOptions = TlsOptions ?? new()
            {
                TargetHost = ConnectionUri.DnsSafeHost,
            };
        }

        // FIXME: Set default header and client cert for cert auth
        // request.Headers.Add("Authorization", "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual");

        // Until net7 is the minimum we need to rewrite the URI so that the scheme is always http. This allows the
        // connection handler to wrap it's own TLS stream used to get the channel binding token information for
        // authentication. When setting net7 as the minimum this can be removed as it adds an instance check for
        // SslStream and doesn't try and wrap it again.
        // https://github.com/dotnet/runtime/pull/63851
        UriBuilder uriBuilder = new(ConnectionUri);
        uriBuilder.Scheme = "http";

        return new(uriBuilder.Uri, authProvider, sslOptions, encrypt);
    }

    internal AuthenticationProvider GenerateAuthProvider()
    {
        string spnService = SPNService ?? "host";
        string spnHostName = SPNHostName ?? ConnectionUri.DnsSafeHost;

        AuthenticationMethod authMethod = AuthMethod;
        if (authMethod == AuthenticationMethod.Default)
        {
            authMethod = GlobalState.GssapiProvider == GssapiProvider.None
                ? AuthenticationMethod.Basic
                : AuthenticationMethod.Negotiate;
        }

        if (authMethod == AuthenticationMethod.Basic)
        {
            return new BasicAuthProvider(UserName, Password);
        }
        else if (authMethod == AuthenticationMethod.CredSSP)
        {
            if (UserName is null || Password is null)
            {
                throw new ArgumentException("Username and password must be set for CredSSP authentication");
            }

            string domainName = "";
            string username = UserName;
            if (username.Contains('\\'))
            {
                string[] stringSplit = username.Split('\\', 2);
                domainName = stringSplit[0];
                username = stringSplit[1];
            }

            SecurityContext subAuth = SecurityContext.GetPlatformSecurityContext(
                username,
                Password,
                CredSSPAuthMethod,
                spnService,
                spnHostName,
                false);
            TSPasswordCreds credSSPCreds = new(domainName, username, Password);
            return new CredSSPAuthProvider(
                credSSPCreds,
                subAuth,
                CredSSPTlsOptions);
        }
        else
        {
            return new NegotiateAuthProvider(
                UserName,
                Password,
                spnService,
                spnHostName,
                authMethod,
                authMethod == AuthenticationMethod.Kerberos ? "Kerberos" : "Negotiate",
                RequestKerberosDelegate);
        }
    }
}
