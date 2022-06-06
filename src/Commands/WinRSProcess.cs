using System;
using System.Collections;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsLifecycle.Start, "WinRSProcess",
    DefaultParameterSetName = "ComputerName"
)]
[OutputType(typeof(WinRSProcess))]
public class StartWinRSProcess : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "Session"
    )]
    [ValidateNotNullOrEmpty]
    public WSManSession[] Session { get; set; } = Array.Empty<WSManSession>();

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "ComputerName"
    )]
    [ValidateNotNullOrEmpty]
    public string[] ComputerName { get; set; } = Array.Empty<string>();

    #region Process Parameters

    [Parameter(
        Mandatory = true,
        Position = 1
    )]
    [ValidateNotNullOrEmpty]
    [Alias("Path")]
    public string FilePath { get; set; } = "";

    [Parameter(
        Position = 2
    )]
    [ValidateNotNullOrEmpty]
    [Alias("Args")]
    public string[] ArgumentList { get; set; } = Array.Empty<string>();

    [Parameter()]
    [EncodingTransformer()]
    public Encoding OutputEncoding { get; set; } = new UTF8Encoding(false);

    [Parameter()]
    [EncodingTransformer()]
    public Encoding InputEncoding { get; set; } = new UTF8Encoding(false);

    [Parameter()]
    public SwitchParameter DoNotStart { get; set; }

    [Parameter()]
    public SwitchParameter Wait { get; set; }

    #endregion

    #region Connection Parameters

    #region Connection Network Parameters

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public SwitchParameter UseSSL { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public int Port { get; set; } = 0;

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public AuthenticationMethod Authentication { get; set; } = AuthenticationMethod.Default;

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public X509Certificate? Certificate { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public WinRSSessionOption? SessionOption { get; set; }

    #endregion

    #region Connection Shell Parameters

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [ValidateNotNullOrEmpty]
    [Credential]
    public PSCredential? Credential { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public int CodePage { get; set; } = 65001;

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public string? WorkingDirectory { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public SwitchParameter LoadUserProfile { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public IDictionary? Environment { get; set; }

    #endregion

    #endregion

    private CancellationTokenSource? CurrentCancelToken { get; set; }

    protected override void ProcessRecord()
    {
        if (ParameterSetName == "ComputerName")
        {
            throw new NotImplementedException();
        }

        using (CurrentCancelToken = new())
        {
            foreach (WSManSession s in Session)
            {
                WinRSProcess process = new(s, FilePath, ArgumentList);
                if (!DoNotStart)
                {
                    process.Start(CurrentCancelToken.Token);
                }

                WriteObject(process);
            }
        }
    }

    protected override void StopProcessing()
    {
        CurrentCancelToken?.Cancel();
    }
}
