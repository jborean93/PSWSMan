using System;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Threading;
using PSWSMan.Connection;

namespace PSWSMan;

public enum WinRSShellState
{
    Opened,
    Closed,
}

/// <summary>A WinRS cmd shell created by New-WinRSShell that the WinRS cmdlets can run commands in.</summary>
/// <remarks>
/// The shell owns its connections. It is deleted by Remove-WinRSShell, or aborted when the runspace that created
/// it closes so an unremoved shell does not stay on the server until its idle timeout. Until then it is listed by
/// Get-WinRSShell in that runspace.
/// </remarks>
public sealed class WinRSRemoteShell
{
    private readonly object _lock = new();
    private readonly WSManTransport _transport;
    private Runspace? _runspace;
    private bool _closed;

    internal WinRSRemoteShell(WSManTransport transport, WinRSShell shell, string computerName, Uri connectionUri,
        Encoding consoleEncoding)
    {
        _transport = transport;
        Shell = shell;
        ComputerName = computerName;
        ConnectionUri = connectionUri;
        ConsoleEncoding = consoleEncoding;
    }

    public string ComputerName { get; }

    public Uri ConnectionUri { get; }

    public Guid ShellId => Shell.ShellId ?? Guid.Empty;

    public WinRSShellState State => Shell.IsClosed ? WinRSShellState.Closed : WinRSShellState.Opened;

    public Encoding ConsoleEncoding { get; }

    internal WinRSShell Shell { get; }

    /// <summary>Lists the shell in the runspace and aborts it when the runspace closes.</summary>
    internal void RegisterRunspace(Runspace runspace)
    {
        lock (_lock)
        {
            if (_closed)
            {
                return;
            }
            _runspace = runspace;
            runspace.StateChanged += OnRunspaceStateChanged;

            ModuleSettings.GetForRunspace(runspace).AddWinRSShell(this);
        }
    }

    /// <summary>Deletes the shell on the server and closes the connections.</summary>
    /// <param name="cancellationToken">Cancels the Delete, the shell is still aborted.</param>
    internal void Close(CancellationToken cancellationToken)
    {
        if (!TryMarkClosed())
        {
            return;
        }

        try
        {
            Shell.Close(cancellationToken);
        }
        finally
        {
            _transport.Dispose();
        }
    }

    /// <summary>Stops everything in flight and makes a best effort attempt to delete the shell.</summary>
    internal void Abort()
    {
        if (!TryMarkClosed())
        {
            return;
        }

        try
        {
            Shell.Abort();
        }
        finally
        {
            _transport.Dispose();
        }
    }

    private bool TryMarkClosed()
    {
        lock (_lock)
        {
            if (_closed)
            {
                return false;
            }
            _closed = true;

            if (_runspace is not null)
            {
                _runspace.StateChanged -= OnRunspaceStateChanged;
                ModuleSettings.GetForRunspace(_runspace).RemoveWinRSShell(this);
                _runspace = null;
            }
        }

        return true;
    }

    private void OnRunspaceStateChanged(object? sender, RunspaceStateEventArgs e)
    {
        if (e.RunspaceStateInfo.State is RunspaceState.Closing or RunspaceState.Closed or RunspaceState.Broken)
        {
            Abort();
        }
    }
}
