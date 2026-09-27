using PSWSMan.Authentication.Native;
using System;
using System.Net.Security;

namespace PSWSMan.Authentication;

/// <summary>Builds the <see cref="WSManCredential"/> for a connection from the requested authentication settings.</summary>
internal static class WSManCredentialFactory
{
    /// <summary>Creates the credential for the requested authentication method.</summary>
    /// <param name="authMethod">The authentication method, Default picks certificate or Negotiate.</param>
    /// <param name="authProvider">The security library to use for Negotiate based methods.</param>
    /// <param name="userName">The username, null for the implicit credential of the process.</param>
    /// <param name="password">The password, null for the implicit credential of the process.</param>
    /// <param name="tlsOptions">The TLS options of the connection, used to detect client certificate auth.</param>
    /// <param name="credSSPTlsOptions">The TLS options for the CredSSP channel.</param>
    /// <param name="credSSPAuthMethod">The Negotiate method used inside CredSSP.</param>
    /// <param name="negoOptions">The Negotiate options such as the SPN.</param>
    /// <returns>The credential to authenticate each connection with.</returns>
    public static WSManCredential Create(
        AuthenticationMethod authMethod,
        AuthenticationProvider authProvider,
        string? userName,
        string? password,
        SslClientAuthenticationOptions? tlsOptions,
        SslClientAuthenticationOptions? credSSPTlsOptions,
        AuthenticationMethod credSSPAuthMethod,
        NegotiateOptions negoOptions)
    {
        if (authMethod == AuthenticationMethod.Default)
        {
            if ((tlsOptions?.ClientCertificates?.Count ?? 0) > 0)
            {
                return new CertificateCredential();
            }

            authMethod = AuthenticationMethod.Negotiate;
        }

        if (authMethod == AuthenticationMethod.Basic)
        {
            return new BasicCredential(userName, password);
        }

        if (authMethod == AuthenticationMethod.CredSSP)
        {
            if (userName is null || password is null)
            {
                throw new ArgumentException("Username and password must be set for CredSSP authentication");
            }

            WSManCredential negoCredential = GetNegotiateCredential(credSSPAuthMethod, authProvider, userName,
                password, negoOptions);

            string domainName = "";
            string username = userName;
            if (username.Contains('\\'))
            {
                string[] stringSplit = username.Split('\\', 2);
                domainName = stringSplit[0];
                username = stringSplit[1];
            }
            TSPasswordCreds credSSPCreds = new(domainName, username, password);
            return new CredSSPCredential(credSSPCreds, negoCredential, credSSPTlsOptions);
        }
        else
        {
            return GetNegotiateCredential(authMethod, authProvider, userName, password, negoOptions);
        }
    }

    /// <summary>Creates a Negotiate, Kerberos or NTLM credential with the configured provider.</summary>
    /// <param name="method">The Negotiate method, anything else falls back to Negotiate.</param>
    /// <param name="provider">The security library, Default uses the one from Set-PSWSManAuth.</param>
    /// <param name="userName">The username, null for the implicit credential of the process.</param>
    /// <param name="password">The password, null for the implicit credential of the process.</param>
    /// <param name="negoOptions">The Negotiate options such as the SPN.</param>
    /// <returns>The credential to authenticate each connection with.</returns>
    public static WSManCredential GetNegotiateCredential(AuthenticationMethod method, AuthenticationProvider provider,
        string? userName, string? password, NegotiateOptions negoOptions)
    {
        NegotiateMethod negoMethod = method switch
        {
            AuthenticationMethod.NTLM => NegotiateMethod.NTLM,
            AuthenticationMethod.Kerberos => NegotiateMethod.Kerberos,
            _ => NegotiateMethod.Negotiate,
        };

        if (provider == AuthenticationProvider.Default)
        {
            provider = ModuleSettings.GetFromTLS().DefaultAuthProvider;
        }

        if (provider == AuthenticationProvider.Devolutions)
        {
            if (!ProviderLibs.TryGetDevolutionsSspi(out SspiProvider? devolutionsProvider, out Exception? devolutionsError))
            {
                throw new ArgumentException(devolutionsError.Message, devolutionsError);
            }

            return new SspiCredential(devolutionsProvider, userName, password, negoMethod, negoOptions);
        }

        // This is set when running on Windows
        SspiProvider? systemProvider = ProviderLibs.GetSystemSspi();
        if (systemProvider is not null)
        {
            return new SspiCredential(systemProvider, userName, password, negoMethod, negoOptions);
        }

        GssapiProvider gssapiProvider = LoadGssapiProvider(ModuleSettings.GetFromTLS());
        return new GssapiCredential(gssapiProvider, userName, password, negoMethod, negoOptions);
    }

    /// <summary>Loads the GSSAPI library configured by Set-PSWSManAuth, or the system one when none is set.</summary>
    private static GssapiProvider LoadGssapiProvider(ModuleSettings moduleSettings)
    {
        if (moduleSettings.GssapiLib != ModuleSettings.DefaultGssapiLib)
        {
            if (!ProviderLibs.TryGetGssapi(moduleSettings.GssapiLib, out GssapiProvider? customProvider,
                out Exception? customError))
            {
                throw new ArgumentException(customError.Message, customError);
            }

            return customProvider;
        }

        if (!ProviderLibs.TryGetSystemGssapi(out GssapiProvider? systemProvider, out Exception? systemError))
        {
            throw new ArgumentException(systemError.Message, systemError);
        }

        return systemProvider;
    }
}
