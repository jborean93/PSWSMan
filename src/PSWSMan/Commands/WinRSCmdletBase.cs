using PSWSMan.Connection;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Remoting.Client;
using System.Text;
using System.Threading;

namespace PSWSMan.Commands;

/// <summary>
/// The shell handling shared by the cmdlets that run commands in a WinRS cmd shell, either one they create from the
/// connection parameters or one created by New-WinRSShell.
/// </summary>
public abstract class WinRSCmdletBase : WinRSConnectionCmdletBase
{
    private readonly List<WinRSCommand> _commands = new();
    private WinRSRemoteShell? _ownedShell;

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "Shell"
    )]
    [ValidateNotNull]
    public WinRSRemoteShell? Shell { get; set; }

    private protected override string ConnectionTarget => Shell?.ComputerName ?? base.ConnectionTarget;

    protected override void BeginProcessing()
    {
        base.BeginProcessing();

        if (Shell?.State == WinRSShellState.Closed)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException($"The WinRS shell {Shell.ShellId} on '{Shell.ComputerName}' has been closed."),
                "WinRSCommandInvalidParameter",
                ErrorCategory.InvalidArgument,
                Shell));
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (_ownedShell is not null)
            {
                // Aborting the shell kills a still running command on every exit path but the normal one.
                _ownedShell.Abort();
            }
            else
            {
                // The shell outlives the cmdlet so a command left running is terminated on its own.
                TerminateCommands();
            }
            foreach (WinRSCommand command in _commands)
            {
                command.Dispose();
            }
        }
        base.Dispose(disposing);
    }

    /// <summary>Gets the shell the commands of this cmdlet run in, creating it on first use without -Shell.</summary>
    /// <param name="consoleEncoding">The encoding whose code page a shell created by this cmdlet uses.</param>
    private protected WinRSShell OpenShell(Encoding consoleEncoding)
    {
        if (Shell is not null)
        {
            return Shell.Shell;
        }

        _ownedShell ??= ConnectShell(consoleEncoding);
        return _ownedShell.Shell;
    }

    /// <summary>Starts a command in the shell from <see cref="OpenShell"/>.</summary>
    /// <param name="commandLine">The command line to run.</param>
    /// <param name="description">What to call the command in verbose messages, defaults to the command line.</param>
    private protected WinRSCommand StartCommand(string commandLine, string? description = null)
    {
        WinRSShell shell = Shell?.Shell ?? _ownedShell?.Shell
            ?? throw new InvalidOperationException("The shell is not open.");
        WriteVerbose($"Starting command in WinRS shell {shell.ShellId}: {description ?? commandLine}");
        WinRSCommand command = WinRSCommand.Start(shell, commandLine, StopToken);
        WriteVerbose($"Started command {command.CommandId}");

        _commands.RemoveAll(c => c.IsTerminated);
        _commands.Add(command);
        return command;
    }

    /// <summary>Reports how a command finished and how much it sent and received.</summary>
    private protected void WriteCommandFinished(WinRSCommand command, WinRSReceiveCompletion completion)
    {
        WriteVerbose(string.Format(CultureInfo.CurrentCulture,
            "Command {0} finished with exit code {1}, sent {2:N0} bytes to stdin, received {3:N0} bytes of stdout and {4:N0} bytes of stderr",
            command.CommandId, completion.ExitCode?.ToString(CultureInfo.CurrentCulture) ?? "unknown",
            command.StdinLength, command.StdoutLength, command.StderrLength));
    }

    /// <summary>Deletes the shell on the server if this cmdlet created it.</summary>
    private protected void CloseShell()
    {
        // Leaving a stopped cmdlet's shell to the abort in Dispose.
        if (_ownedShell is not null && !StopToken.IsCancellationRequested)
        {
            WriteVerbose($"Closing WinRS shell {_ownedShell.ShellId}");
            _ownedShell.Close(StopToken);
            WriteVerbose($"Closed WinRS shell {_ownedShell.ShellId}");
        }
    }

    /// <summary>Terminates the commands this cmdlet started that are still held by the server.</summary>
    /// <remarks>
    /// The cmdlet's token may already be cancelled so the requests get their own deadline, and a failure is only
    /// traced as the process is left to the shell's lifetime.
    /// </remarks>
    private void TerminateCommands()
    {
        foreach (WinRSCommand command in _commands)
        {
            if (command.IsTerminated)
            {
                continue;
            }

            using CancellationTokenSource cts = new(StopGracePeriod);
            try
            {
                command.Terminate(cts.Token);
            }
            catch (Exception e)
            {
                Trace(
                    $"PSWSMan WinRS: failed to terminate command {command.CommandId}: {e.Message}");
            }
        }
    }
}
