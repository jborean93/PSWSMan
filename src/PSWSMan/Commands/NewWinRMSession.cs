using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.New, "WinRMSession",
    DefaultParameterSetName = "ComputerName"
)]
[OutputType(typeof(PSSession))]
public sealed class NewWinRMSession : WinRMCmdletBase
{
    private const int DefaultThrottleLimit = 32;

    private readonly List<(string Target, Uri Uri)> _targets = new();

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "ComputerName"
    )]
    [ValidateNotNullOrEmpty]
    [Alias("Cn")]
    public string[] ComputerName { get; set; } = [];

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "ConnectionUri"
    )]
    [ValidateNotNullOrEmpty]
    [Alias("URI", "CU")]
    public Uri[] ConnectionUri { get; set; } = [];

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string ConfigurationName { get; set; } = "Microsoft.PowerShell";

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string[]? Name { get; set; }

    [Parameter]
    public int ThrottleLimit { get; set; } = DefaultThrottleLimit;

    private protected override string ConnectionTarget => string.Join(", ", _targets.ConvertAll(t => t.Target));

    private protected override string ErrorIdPrefix => "WinRMSession";

    protected override void ProcessRecord()
    {
        if (ParameterSetName == "ConnectionUri")
        {
            foreach (Uri uri in ConnectionUri)
            {
                if (ValidateConnectionUri(uri) is ErrorRecord err)
                {
                    WriteError(err);
                    continue;
                }
                _targets.Add((uri.OriginalString, uri));
            }
        }
        else
        {
            foreach (string computerName in ComputerName)
            {
                _targets.Add((computerName, GetConnectionUri(computerName)));
            }
        }
    }

    protected override void EndProcessing()
    {
        int throttleLimit = ThrottleLimit > 0 ? ThrottleLimit : DefaultThrottleLimit;

        // The runspaces open on their own threads, only their results come back here so everything written to the
        // pipeline is written from the pipeline thread.
        BlockingCollection<OpenResult> results = new();
        Dictionary<int, (Runspace Runspace, CancellationTokenSource Abort)> opening = new();
        List<CancellationTokenSource> aborts = new();
        int next = 0;
        int finished = 0;
        try
        {
            while (finished < _targets.Count)
            {
                while (opening.Count < throttleLimit && next < _targets.Count)
                {
                    int index = next++;
                    CancellationTokenSource abort = new();
                    aborts.Add(abort);
                    opening[index] = (StartOpen(index, results, abort.Token), abort);
                }

                OpenResult result = results.Take(StopToken);
                opening.Remove(result.Index);
                finished++;

                string target = _targets[result.Index].Target;
                if (result.Error is not null)
                {
                    result.Runspace?.Dispose();
                    WriteError(new ErrorRecord(result.Error, $"{ErrorIdPrefix}OpenFailed", ErrorCategory.OpenError,
                        target));
                    continue;
                }

                PSSession session = PSSession.Create(result.Runspace!, "PSWSMan", this);
                if (Name is not null && result.Index < Name.Length)
                {
                    session.Name = Name[result.Index];
                }
                WriteObject(session);
            }
        }
        catch (OperationCanceledException) when (StopToken.IsCancellationRequested)
        {
            // Stopped with Ctrl+C, the sessions still opening are abandoned and the ones written are kept.
        }
        finally
        {
            foreach ((Runspace runspace, CancellationTokenSource abort) in opening.Values)
            {
                abort.Cancel();
                runspace.Dispose();
            }
            // Results that arrived after the stop hold runspaces nobody will use.
            while (results.TryTake(out OpenResult? leftover))
            {
                leftover.Runspace?.Dispose();
            }
            // Only a connection that is still opening is aborted, disposing leaves the opened sessions alone.
            foreach (CancellationTokenSource abort in aborts)
            {
                abort.Dispose();
            }
        }
    }

    private Runspace StartOpen(int index, BlockingCollection<OpenResult> results, CancellationToken abortToken)
    {
        (string target, Uri uri) = _targets[index];
        WriteVerbose($"Opening PSRP session to '{target}'");
        (Runspace runspace, Task opened) = StartOpenSession(uri, ConfigurationName, target, abortToken);
        opened.ContinueWith(t => results.Add(new(index, runspace, t.Exception?.InnerException)),
            TaskScheduler.Default);

        return runspace;
    }

    private sealed record OpenResult(int Index, Runspace? Runspace, Exception? Error);
}
