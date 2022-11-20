using System;
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

    /// <summary>The loaded SSPI library on Windows.</summary>
    internal static LibraryInfo? SspiLib;

    /// <summary>The loaded DevolutionsSspi library.</summary>
    internal static LibraryInfo? DevolutionsLib;

    /// <summary>The default authentication provider set for the process.</summary>
    internal static AuthenticationProvider DefaultProvider = AuthenticationProvider.Native;
}

internal sealed class WSManSession : IDisposable
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
        Connection?.Dispose();
        GC.SuppressFinalize(this);
    }
    ~WSManSession() { Dispose(); }
}

internal class WSManSessionOption
{
    internal const int DefaultMaxEnvelopeSize = 153600;

    public string? _dataLocale;

    public Uri ConnectionUri { get; set; }

    public int OpenTimeout { get; set; }

    public int OperationTimeout { get; set; }

    public int MaxEnvelopeSize { get; set; } = DefaultMaxEnvelopeSize;

    public string Locale { get; set; }

    public string DataLocale
    {
        get => _dataLocale ?? Locale;
        set => _dataLocale = value;
    }

    public SslClientAuthenticationOptions? TlsOptions { get; set; }

    public AuthenticationMethod AuthMethod { get; set; } = AuthenticationMethod.Default;

    public AuthenticationProvider AuthProvider { get; set; } = AuthenticationProvider.Default;

    public string? UserName { get; set; }

    public string? Password { get; set; }

    public bool NoEncryption { get; set; }

    public string? SPNService { get; set; }

    public string? SPNHostName { get; set; }

    public bool RequestKerberosDelegate { get; set; }

    public SslClientAuthenticationOptions? CredSSPTlsOptions { get; set; }

    public AuthenticationMethod CredSSPAuthMethod { get; set; } = AuthenticationMethod.Negotiate;

    public WSManSessionOption(Uri connectionUri, int openTimeout, int operationTimeout, string locale)
    {
        OpenTimeout = openTimeout;
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
        HttpAuthProvider authProvider = GenerateAuthProvider();

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

        // Until net7 is the minimum we need to rewrite the URI so that the scheme is always http. This allows the
        // connection handler to wrap it's own TLS stream used to get the channel binding token information for
        // authentication. When setting net7 as the minimum this can be removed as it adds an instance check for
        // SslStream and doesn't try and wrap it again.
        // https://github.com/dotnet/runtime/pull/63851
        UriBuilder uriBuilder = new(ConnectionUri);
        uriBuilder.Scheme = "http";

        TimeSpan? connectTimeout = null;
        if (OpenTimeout != 0)
        {
            connectTimeout = new(((long)OpenTimeout) * TimeSpan.TicksPerMillisecond);
        }

        return new(uriBuilder.Uri, authProvider, sslOptions, encrypt, connectTimeout);
    }

    internal HttpAuthProvider GenerateAuthProvider()
    {
        string spnService = SPNService ?? "host";
        string spnHostName = SPNHostName ?? ConnectionUri.DnsSafeHost;

        AuthenticationMethod authMethod = AuthMethod;
        if (authMethod == AuthenticationMethod.Default)
        {
            if ((TlsOptions?.ClientCertificates?.Count ?? 0) > 0)
            {
                return new CertificateAuthProvider();
            }

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
                AuthProvider,
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
                AuthProvider,
                authMethod == AuthenticationMethod.Kerberos ? "Kerberos" : "Negotiate",
                RequestKerberosDelegate);
        }
    }
}
