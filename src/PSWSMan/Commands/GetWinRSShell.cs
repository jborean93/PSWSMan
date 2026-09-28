using System;
using System.Linq;
using System.Management.Automation;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.Get, "WinRSShell"
)]
[OutputType(typeof(WinRSRemoteShell))]
public sealed class GetWinRSShell : PSCmdlet
{
    [Parameter(
        Position = 0
    )]
    [ValidateNotNullOrEmpty]
    [SupportsWildcards]
    [Alias("Cn")]
    public string[]? ComputerName { get; set; }

    [Parameter]
    public Guid[]? ShellId { get; set; }

    protected override void ProcessRecord()
    {
        WildcardPattern[]? patterns = ComputerName?
            .Select(n => WildcardPattern.Get(n, WildcardOptions.IgnoreCase))
            .ToArray();
        foreach (WinRSRemoteShell shell in ModuleSettings.GetFromTLS().WinRSShells)
        {
            if (patterns is not null && !patterns.Any(p => p.IsMatch(shell.ComputerName)))
            {
                continue;
            }
            if (ShellId is not null && !ShellId.Contains(shell.ShellId))
            {
                continue;
            }

            WriteObject(shell);
        }
    }
}
