using System;
using System.Linq;
using System.Management.Automation;
using PSWSMan.Lib;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsData.ConvertTo, "WinRSCommandLine"
)]
[OutputType(typeof(string))]
public sealed class ConvertToWinRSCommandLine : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0
    )]
    [ValidateNotNullOrEmpty]
    public string FilePath { get; set; } = "";

    [Parameter(
        Position = 1,
        ValueFromRemainingArguments = true
    )]
    [AllowEmptyCollection]
    [AllowEmptyString]
    [AllowNull]
    public string?[]? ArgumentList { get; set; }

    protected override void EndProcessing()
    {
        string? commandLine = null;
        try
        {
            commandLine = WinRSCommandLine.Build(FilePath, ArgumentList?.OfType<string>() ?? []);
        }
        catch (ArgumentException e)
        {
            ThrowTerminatingError(new ErrorRecord(e, "WinRSCommandLineInvalidArgument", ErrorCategory.InvalidArgument,
                null));
        }

        WriteObject(commandLine);
    }
}
