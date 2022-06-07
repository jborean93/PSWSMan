using System;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Runspaces;
using System.Net.Security;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.New, "PSWSManSessionOption",
    DefaultParameterSetName = "SkipCert"
)]
[OutputType(typeof(PSSessionOption))]
public class NewPSWSManSessionOption : PSCmdlet
{
    [Parameter()]
    public int MaximumRedirection { get; set; } = 5;

    [Parameter()]
    public SwitchParameter NoMachineProfile { get; set; }

    [Parameter()]
    [ValidateNotNull()]
    public CultureInfo? Culture { get; set; }

    [Parameter()]
    [ValidateNotNull()]
    public CultureInfo? UICulture { get; set; }

    [Parameter()]
    public int? MaximumReceivedDataSizePerCommand { get; set; }

    [Parameter()]
    public int MaximumReceivedObjectSize { get; set; } = 209715200;

    [Parameter()]
    public OutputBufferingMode OutputBufferingMode { get; set; } = OutputBufferingMode.Block;

    [Parameter()]
    [ValidateRange(0, int.MaxValue)]
    public int MaxConnectionRetryCount { get; set; } = 5;

    [Parameter()]
    [ValidateNotNull()]
    public PSPrimitiveDictionary? ApplicationArguments { get; set; }

    [Parameter()]
    [Alias("OpenTimeoutMSec")]
    public int OpenTimeout { get; set; } = 3 * 60 * 1000;

    [Parameter()]
    [Alias("CancelTimeoutMSec")]
    [ValidateRange(0, Int32.MaxValue)]
    public int CancelTimeout { get; set; } = 60 * 1000;

    [Parameter()]
    [ValidateRange(-1, Int32.MaxValue)]
    [Alias("IdleTimeoutMSec")]
    public int IdleTimeout { get; set; } = 7200 * 1000;

    // TODO: Proxy options - ProxyAccessType, ProxyAuthentication, ProxyCredential

    [Parameter(
        ParameterSetName = "SkipCert"
    )]
    public SwitchParameter SkipCACheck { get; set; }

    [Parameter(
        ParameterSetName = "SkipCert"
    )]
    public SwitchParameter SkipCNCheck { get; set; }

    [Parameter(
        ParameterSetName = "SkipCert"
    )]
    public SwitchParameter SkipRevocationCheck { get; set; }

    [Parameter()]
    [Alias("OperationTimeoutMSec")]
    [ValidateRange(0, Int32.MaxValue)]
    public int OperationTimeout { get; set; } = 3 * 60 * 1000;

    [Parameter()]
    public SwitchParameter NoEncryption { get; set; }

    [Parameter()]
    public string? SPNService { get; set; }

    [Parameter()]
    public string? SPNHostName { get; set; }

    [Parameter()]
    public AuthenticationMethod AuthMethod { get; set; }

    [Parameter()]
    public SwitchParameter RequestKerberosDelegate { get; set; }

    [Parameter(
        ParameterSetName = "TlsOption"
    )]
    public SslClientAuthenticationOptions? TlsOption { get; set; }

    [Parameter()]
    public AuthenticationMethod CredSSPAuthMethod { get; set; } = AuthenticationMethod.Default;

    [Parameter()]
    public SslClientAuthenticationOptions? CredSSPTlsOption { get; set; }

    protected override void BeginProcessing()
    {
        PSSessionOption options = new()
        {
            MaximumConnectionRedirectionCount = MaximumRedirection,
            NoMachineProfile = NoMachineProfile,
            Culture = Culture,
            UICulture = UICulture,
            MaximumReceivedDataSizePerCommand = MaximumReceivedDataSizePerCommand,
            MaximumReceivedObjectSize = MaximumReceivedObjectSize,
            OutputBufferingMode = this.OutputBufferingMode,
            MaxConnectionRetryCount = MaxConnectionRetryCount,
            ApplicationArguments = ApplicationArguments,
            OpenTimeout = TimeSpan.FromMilliseconds(OpenTimeout),
            CancelTimeout = TimeSpan.FromMilliseconds(CancelTimeout),
            IdleTimeout = TimeSpan.FromMilliseconds(IdleTimeout),
            SkipCACheck = SkipCACheck,
            SkipCNCheck = SkipCNCheck,
            SkipRevocationCheck = SkipRevocationCheck,
            OperationTimeout = TimeSpan.FromMilliseconds(OperationTimeout),
            NoEncryption = NoEncryption,
        };

        PSWSManSessionOption extraOptions = new()
        {
            AuthMethod = AuthMethod,
            SPNService = SPNService,
            SPNHostName = SPNHostName,
            RequestKerberosDelegate = RequestKerberosDelegate,
            TlsOption = TlsOption,
            CredSSPAuthMethod = CredSSPAuthMethod,
            CredSSPTlsOption = CredSSPTlsOption,
        };
        // In order to smuggle the extra options into the patched WSMan connection code the data is added as an ETS
        // member which can be retrieved in the patched code.
        PSObject.AsPSObject(options).Properties.Add(
            new PSNoteProperty(PSWSManSessionOption.PSWSMAN_SESSION_OPTION_PROP, extraOptions));

        WriteObject(options);
    }
}
