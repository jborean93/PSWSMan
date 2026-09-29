using System;
using System.Globalization;
using System.Management.Automation;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.New, "WinRMSessionOption",
    DefaultParameterSetName = "SimpleTls"
)]
[OutputType(typeof(WinRMSessionOption))]
public sealed class NewWinRMSessionOption : PSCmdlet
{
    [Parameter]
    public SwitchParameter NoMachineProfile { get; set; }

    [Parameter]
    [ValidateNotNull]
    public CultureInfo? Culture { get; set; }

    [Parameter]
    [ValidateNotNull]
    public CultureInfo? UICulture { get; set; }

    [Parameter]
    [ValidateRange(0, int.MaxValue)]
    public int MaxConnectionRetryCount { get; set; } = 5;

    [Parameter]
    [ValidateNotNull]
    public PSPrimitiveDictionary? ApplicationArguments { get; set; }

    [Parameter]
    [Alias("OpenTimeoutMSec")]
    [ValidateRange(0, int.MaxValue)]
    public int OpenTimeout { get; set; } = 3 * 60 * 1000;

    [Parameter]
    [Alias("CancelTimeoutMSec")]
    [ValidateRange(0, int.MaxValue)]
    public int CancelTimeout { get; set; } = 60 * 1000;

    [Parameter]
    [Alias("OperationTimeoutMSec")]
    [ValidateRange(0, int.MaxValue)]
    public int OperationTimeout { get; set; } = 3 * 60 * 1000;

    [Parameter(
        ParameterSetName = "SimpleTls"
    )]
    public SwitchParameter SkipCACheck { get; set; }

    [Parameter(
        ParameterSetName = "SimpleTls"
    )]
    public SwitchParameter SkipCNCheck { get; set; }

    [Parameter(
        ParameterSetName = "SimpleTls"
    )]
    public X509Certificate? ClientCertificate { get; set; }

    [Parameter(
        ParameterSetName = "TlsOption"
    )]
    public SslClientAuthenticationOptions? TlsOption { get; set; }

    [Parameter]
    public SwitchParameter NoEncryption { get; set; }

    [Parameter]
    public string? SPNService { get; set; }

    [Parameter]
    public string? SPNHostName { get; set; }

    [Parameter]
    public AuthenticationMethod AuthMethod { get; set; } = AuthenticationMethod.Default;

    [Parameter]
    public AuthenticationProvider AuthProvider { get; set; } = AuthenticationProvider.Default;

    [Parameter]
    public SwitchParameter RequestKerberosDelegate { get; set; }

    [Parameter]
    public AuthenticationMethod CredSSPAuthMethod { get; set; } = AuthenticationMethod.Default;

    [Parameter]
    public SslClientAuthenticationOptions? CredSSPTlsOption { get; set; }

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string? TracePath { get; set; }

    protected override void EndProcessing()
    {
        WriteObject(new WinRMSessionOption()
        {
            NoMachineProfile = NoMachineProfile,
            Culture = Culture,
            UICulture = UICulture,
            MaxConnectionRetryCount = MaxConnectionRetryCount,
            ApplicationArguments = ApplicationArguments,
            OpenTimeout = TimeSpan.FromMilliseconds(OpenTimeout),
            CancelTimeout = TimeSpan.FromMilliseconds(CancelTimeout),
            OperationTimeout = TimeSpan.FromMilliseconds(OperationTimeout),
            SkipCACheck = SkipCACheck,
            SkipCNCheck = SkipCNCheck,
            ClientCertificate = ClientCertificate,
            TlsOption = TlsOption,
            NoEncryption = NoEncryption,
            SPNService = SPNService,
            SPNHostName = SPNHostName,
            AuthMethod = AuthMethod,
            AuthProvider = AuthProvider,
            RequestKerberosDelegate = RequestKerberosDelegate,
            CredSSPAuthMethod = CredSSPAuthMethod,
            CredSSPTlsOption = CredSSPTlsOption,
            // Resolved now so the path does not depend on the location when the options are used.
            TracePath = TracePath is null ? null : SessionState.Path.GetUnresolvedProviderPathFromPSPath(TracePath),
        });
    }
}
