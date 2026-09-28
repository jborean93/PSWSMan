using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.New, "WinRSShell",
    DefaultParameterSetName = "ComputerName"
)]
[OutputType(typeof(WinRSRemoteShell))]
public sealed class NewWinRSShell : WinRSConnectionCmdletBase
{
    [Parameter]
    [EncodingTransform]
    [EncodingCompletions]
    [ValidateNotNull]
    public Encoding ConsoleEncoding { get; set; } = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    protected override void EndProcessing()
    {
        Guard(() =>
        {
            WinRSRemoteShell shell = ConnectShell(ConsoleEncoding);
            if (Runspace.DefaultRunspace is Runspace runspace)
            {
                shell.RegisterRunspace(runspace);
            }
            WriteObject(shell);
        });
    }
}
