using System;
using System.Collections.Generic;
using System.Management.Automation.Runspaces;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PSWSMan;

internal class WSManPSRPShim
{
    private readonly Guid _runspacePoolId;
    private readonly WSManSession _session;
    private readonly WSManConnectionInfo _connInfo;

    private WSManPSRPShim(Guid runspacePoolId, WSManSession session, WSManConnectionInfo connInfo)
    {
        _runspacePoolId = runspacePoolId;
        _session = session;
        _connInfo = connInfo;
    }

    public static WSManPSRPShim Create(
        Guid runspacePoolId,
        Uri connectionUri,
        WSManConnectionInfo connInfo,
        PSWSManSessionOption? extraConnInfo,
        int maxEnvelopeSize)
    {
        SslClientAuthenticationOptions? tlsOptions = null;
        if (connectionUri.Scheme == Uri.UriSchemeHttps)
        {
            tlsOptions = extraConnInfo?.TlsOption ?? new()
            {
                TargetHost = connectionUri.DnsSafeHost,
                CertificateRevocationCheckMode = connInfo.SkipRevocationCheck
                    ? X509RevocationMode.NoCheck : X509RevocationMode.Offline,
            };

            if (extraConnInfo?.TlsOption is null && (connInfo.SkipCACheck || connInfo.SkipCNCheck))
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
        }

        // Use the extra options auth method if set, otherwise map the builtin methods to our known enum.
        AuthenticationMethod authMethod = extraConnInfo?.AuthMethod ?? AuthenticationMethod.Default;
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

        WSManSessionOption options = new(connectionUri, connInfo.OperationTimeout,
            connInfo.Culture.Name)
        {
            MaxEnvelopeSize = maxEnvelopeSize,
            TlsOptions = tlsOptions,
            AuthMethod = authMethod,
            UserName = connInfo.Credential?.UserName,
            Password = connInfo.Credential?.GetNetworkCredential()?.Password,
            NoEncryption = connInfo.NoEncryption,
            SPNService = extraConnInfo?.SPNService,
            SPNHostName = extraConnInfo?.SPNHostName,
            RequestKerberosDelegate = extraConnInfo?.RequestKerberosDelegate ?? false,
            CredSSPTlsOptions = extraConnInfo?.CredSSPTlsOption,
            CredSSPAuthMethod = extraConnInfo?.CredSSPAuthMethod ?? AuthenticationMethod.Negotiate,
            // FIXME: ClientCertificate
        };
        if (connInfo.UICulture is not null)
        {
            options.DataLocale = connInfo.UICulture.Name;
        }

        return new(runspacePoolId, options.CreateSession(), connInfo);
    }

    public async Task CreateShellAsync(byte[] psrpFragment)
    {
        string psrpPayload = Convert.ToBase64String(psrpFragment);
        XElement extraContent = new(WSManNamespace.pwsh + "creationXml", psrpPayload);
        OptionSet shellOptions = new();
        shellOptions.Add("protocolversion", "2.3");

        if (_connInfo.NoMachineProfile)
        {
            shellOptions.Add("WINRS_NOPROFILE", "1", new() { {"mustComply", true}});
        }

        string payload = _session.WinRS.Create(
            _connInfo.ShellUri,
            inputStreams: "stdin pr",
            outputStreams: "stdout",
            shellId: _runspacePoolId,
            extra: extraContent,
            options: shellOptions);

        WSManCreateResponse resp = await _session.PostRequest<WSManCreateResponse>(payload);
        string a = "";
    }
}

internal static class WSManCompatState
{
    internal static Int64 _nextSessionId;

    public static Dictionary<IntPtr, WSManPSRPShim> SessionInfo = new();

    public static IntPtr StoreSession(WSManPSRPShim session)
    {
        IntPtr sessionId = new(_nextSessionId++);
        SessionInfo.Add(sessionId, session);
        return sessionId;
    }
}

/// <summary>Used as a way to extend New-PSSessionOption by adding in extra options available in this lib.</summary>
public class PSWSManSessionOption
{
    public const string PSWSMAN_SESSION_OPTION_PROP = "_PSWSManSessionOption";

    public AuthenticationMethod AuthMethod { get; set; } = AuthenticationMethod.Default;
    public string? SPNService { get; set; }
    public string? SPNHostName { get; set; }
    public bool RequestKerberosDelegate { get; set; }
    public SslClientAuthenticationOptions? TlsOption { get; set; }
    public AuthenticationMethod CredSSPAuthMethod { get; set; } = AuthenticationMethod.Default;
    public SslClientAuthenticationOptions? CredSSPTlsOption { get; set; }

    // FIXME: Add X509Certificate property for cert auth
}
