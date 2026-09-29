using System;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.Enter, "WinRMSession",
    DefaultParameterSetName = "ComputerName"
)]
public sealed class EnterWinRMSession : WinRMCmdletBase
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "ComputerName"
    )]
    [ValidateNotNullOrEmpty]
    [Alias("Cn")]
    public string ComputerName { get; set; } = "";

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "ConnectionUri"
    )]
    [ValidateNotNullOrEmpty]
    [Alias("URI", "CU")]
    public Uri? ConnectionUri { get; set; }

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string ConfigurationName { get; set; } = "Microsoft.PowerShell";

    private protected override string ConnectionTarget => ParameterSetName == "ConnectionUri"
        ? ConnectionUri!.OriginalString
        : ComputerName;

    private protected override string ErrorIdPrefix => "WinRMSession";

    protected override void ProcessRecord()
    {
        // The Host given to a cmdlet always implements the interface and throws when the actual host does not, it is
        // checked before connecting rather than on the push.
        IHostSupportsInteractiveSession? host = Host as IHostSupportsInteractiveSession;
        try
        {
            _ = host?.IsRunspacePushed;
        }
        catch (PSNotImplementedException)
        {
            host = null;
        }
        if (host is null)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("The host does not support entering an interactive session."),
                "HostDoesNotSupportPushRunspace",
                ErrorCategory.InvalidArgument,
                null));
            return;
        }

        // Enter-PSSession refuses to push a runspace from a nested prompt, $NestedPromptLevel is the public way to
        // tell.
        if (SessionState.PSVariable.GetValue("NestedPromptLevel") is int nestedLevel && nestedLevel > 0)
        {
            ThrowTerminatingError(new ErrorRecord(
                new InvalidOperationException("The session cannot be entered from a nested prompt."),
                "HostInNestedPrompt",
                ErrorCategory.InvalidOperation,
                null));
        }

        Uri uri;
        if (ParameterSetName == "ConnectionUri")
        {
            uri = ConnectionUri!;
            if (ValidateConnectionUri(uri) is ErrorRecord err)
            {
                WriteError(err);
                return;
            }
        }
        else
        {
            uri = GetConnectionUri(ComputerName);
        }

        Runspace runspace = CreateSessionRunspace(uri, ConfigurationName, StopToken);
        WriteVerbose($"Opening PSRP session to '{ConnectionTarget}'");
        try
        {
            runspace.Open();
        }
        catch (Exception e) when (e is not (PipelineStoppedException or FlowControlException))
        {
            runspace.Dispose();
            if (StopToken.IsCancellationRequested)
            {
                // Stopped with Ctrl+C while connecting, there is nothing to enter.
                return;
            }

            WriteError(new ErrorRecord(e, $"{ErrorIdPrefix}OpenFailed", ErrorCategory.OpenError, ConnectionTarget));
            return;
        }

        // Internal S.M.A API: RemoteRunspace.ShouldCloseOnPop is internal and only reachable through the assembly wide
        // IgnoresAccessChecksTo. Exit-PSSession and exit in the remote session pop the runspace through a host call
        // that closes it only when this is set, the same as Enter-PSSession -ComputerName does for the runspace it
        // creates. The host has no public pop event to close it otherwise. It is a known risk, a PowerShell release
        // that changes it breaks this cmdlet until PSWSMan is updated.
        ((RemoteRunspace)runspace).ShouldCloseOnPop = true;

        try
        {
            host.PushRunspace(runspace);
        }
        catch
        {
            // A host can throw anything, the runspace is only closed by the pop once it was pushed.
            runspace.Dispose();
            throw;
        }
    }
}
