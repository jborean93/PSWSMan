using System;
using System.Management.Automation;
using System.Threading;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.Remove, "WinRSShell",
    SupportsShouldProcess = true
)]
public sealed class RemoveWinRSShell : PSCmdlet, IDisposable
{
    private readonly CancellationTokenSource _cts = new();

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true
    )]
    [ValidateNotNull]
    public WinRSRemoteShell[] Shell { get; set; } = [];

    protected override void ProcessRecord()
    {
        foreach (WinRSRemoteShell shell in Shell)
        {
            if (!ShouldProcess($"WinRS shell {shell.ShellId} on '{shell.ComputerName}'", "Remove"))
            {
                continue;
            }

            try
            {
                shell.Close(_cts.Token);
            }
            catch (OperationCanceledException) when (_cts.IsCancellationRequested)
            {
                // The shell was still aborted, the rest are left alone.
                return;
            }
            catch (Exception e) when (WinRSConnectionCmdletBase.IsTransportError(e))
            {
                WriteError(new ErrorRecord(e, "WinRSShellRemoveFailed",
                    WinRSConnectionCmdletBase.GetErrorCategory(e), shell));
            }
        }
    }

    protected override void StopProcessing()
    {
        _cts.Cancel();
    }

    public void Dispose()
    {
        _cts.Dispose();
        GC.SuppressFinalize(this);
    }
}
