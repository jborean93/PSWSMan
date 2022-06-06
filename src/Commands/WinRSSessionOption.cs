using System.Management.Automation;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.New, "WinRSSessionOption"
)]
[OutputType(typeof(WinRSSessionOption))]
public class New : PSCmdlet
{
    [Parameter()]
    public string? Culture { get; set; }

    [Parameter()]
    public string? UICulutre { get; set; }

    [Parameter()]
    public int OpenTimeout { get; set; }

    [Parameter()]
    public int IdleTimeout { get; set; }

    [Parameter()]
    public int OperationTimeout { get; set; }

    [Parameter()]
    public SwitchParameter NoEncryption { get; set; }

    [Parameter()]
    public SwitchParameter SkipCertificateCheck { get; set; }

    [Parameter()]
    public SwitchParameter RequestDelegate { get; set; }

    [Parameter()]
    public string? SPNService { get; set; }

    [Parameter()]
    public string? SPNHostname { get; set; }

    protected override void ProcessRecord()
    {
        WriteObject(new WinRSSessionOption()
        {
            Culture = Culture,
            UICulutre = UICulutre,
            OpenTimeout = OpenTimeout,
            IdleTimeout = IdleTimeout,
            OperationTimeout = OperationTimeout,
            NoEncryption = NoEncryption,
            SkipCertificateCheck = SkipCertificateCheck,
            RequestDelegate = RequestDelegate,
            SPNService = SPNService,
            SPNHostname = SPNHostname,
        });
    }
}
