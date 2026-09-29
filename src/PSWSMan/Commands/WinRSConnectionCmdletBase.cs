using PSWSMan.Connection;
using PSWSMan.Lib;
using System;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Remoting.Client;
using System.Text;

namespace PSWSMan.Commands;

/// <summary>The WinRS cmdlets that connect to a single host given by -ComputerName or -ConnectionUri.</summary>
public abstract class WinRSConnectionCmdletBase : WinRMCmdletBase
{
    private protected const string CmdShellUri = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

    // How long a stopped cmdlet gives the remote process to exit on its own before the shell is aborted.
    private protected static readonly TimeSpan StopGracePeriod = TimeSpan.FromSeconds(10);

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "ComputerName"
    )]
    [ValidateNotNullOrEmpty]
    [Alias("Cn")]
    public string ComputerName { get; set; } = "";

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "ConnectionUri"
    )]
    [ValidateNotNull]
    [Alias("URI", "CU")]
    public Uri? ConnectionUri { get; set; }

    private protected override string ConnectionTarget => ConnectionUri?.OriginalString ?? ComputerName;

    private protected override string ErrorIdPrefix => "WinRSCommand";

    protected override void BeginProcessing()
    {
        if (ConnectionUri is not null && ValidateConnectionUri(ConnectionUri) is ErrorRecord err)
        {
            ThrowTerminatingError(err);
        }

        base.BeginProcessing();
    }

    /// <summary>The endpoint the connection parameters describe.</summary>
    /// <remarks>A -ConnectionUri is used as is so without a port it means 80 or 443, the same as Invoke-Command.</remarks>
    private protected Uri GetConnectionUri() => ConnectionUri ?? GetConnectionUri(ComputerName);

    /// <summary>Connects and creates a cmd shell from the connection parameters.</summary>
    /// <param name="consoleEncoding">The encoding whose code page the shell's console uses.</param>
    /// <returns>The opened shell, the caller closes or aborts it.</returns>
    private protected WinRSRemoteShell ConnectShell(Encoding consoleEncoding)
    {
        WinRMSessionOption options = Options;
        Uri connectionUri = GetConnectionUri();

        WSManTransport transport = CreateTransport(connectionUri);
        WinRSShell shell = new(transport.Pool, transport.Client, CmdShellUri, Trace)
        {
            ReceiveRetries = Math.Max(options.MaxConnectionRetryCount, 0),
        };
        WinRSRemoteShell remoteShell = new(transport, shell, ConnectionUri is null ? ComputerName : connectionUri.Host,
            connectionUri, consoleEncoding);

        OptionSet shellOptions = new();
        shellOptions.Add("WINRS_CODEPAGE", consoleEncoding.CodePage.ToString(CultureInfo.InvariantCulture));
        if (options.NoMachineProfile)
        {
            shellOptions.Add("WINRS_NOPROFILE", "TRUE");
        }
        try
        {
            WriteVerbose($"Creating WinRS shell on '{ConnectionTarget}'");
            shell.Open(options: shellOptions, cancellationToken: StopToken);
            WriteVerbose($"Created WinRS shell {shell.ShellId}");
        }
        catch
        {
            remoteShell.Abort();
            throw;
        }

        return remoteShell;
    }
}
