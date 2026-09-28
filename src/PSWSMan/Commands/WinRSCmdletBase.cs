using PSWSMan.Connection;
using PSWSMan.Lib;
using System;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Remoting.Client;
using System.Management.Automation.Runspaces;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;

namespace PSWSMan.Commands;

/// <summary>The connection parameters and shell handling shared by the cmdlets that use a WinRS cmd shell.</summary>
public abstract class WinRSCmdletBase : PSCmdlet, IDisposable
{
    private protected const string CmdShellUri = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

    // How long a stopped cmdlet gives the remote process to exit on its own before the shell is aborted.
    private protected static readonly TimeSpan StopGracePeriod = TimeSpan.FromSeconds(10);

    private readonly CancellationTokenSource _cts = new();
    private WSManTransport? _transport;
    private WinRSShell? _shell;

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

    [Parameter]
    [Credential]
    public PSCredential? Credential { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [ValidateRange(1, 65535)]
    public int Port { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public SwitchParameter UseSSL { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [ValidateNotNullOrEmpty]
    public string ApplicationName { get; set; } = "wsman";

    [Parameter]
    public PSSessionOption? SessionOption { get; set; }

    [Parameter]
    public AuthenticationMethod Authentication { get; set; } = AuthenticationMethod.Default;

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string? CertificateThumbprint { get; set; }

    private protected CancellationToken StopToken => _cts.Token;

    private protected WinRSShell Shell => _shell ?? throw new InvalidOperationException("The shell is not open.");

    private protected string ConnectionTarget => ConnectionUri?.OriginalString ?? ComputerName;

    protected override void BeginProcessing()
    {
        if (ConnectionUri is not null && (!ConnectionUri.IsAbsoluteUri ||
            (ConnectionUri.Scheme != Uri.UriSchemeHttp && ConnectionUri.Scheme != Uri.UriSchemeHttps)))
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException($"The ConnectionUri '{ConnectionUri}' must be an absolute http or https URI."),
                "WinRSCommandInvalidParameter",
                ErrorCategory.InvalidArgument,
                ConnectionUri));
        }

        if (CertificateThumbprint is not null)
        {
            // The same combinations Invoke-Command rejects, plus the transport requirement it leaves to WinRM.
            string? problem = null;
            if (Credential is not null)
            {
                problem = "The Credential parameter and the CertificateThumbprint parameter cannot be used together.";
            }
            else if (Authentication != AuthenticationMethod.Default)
            {
                problem = "The Authentication parameter and the CertificateThumbprint parameter cannot be used together.";
            }
            else if (ConnectionUri is null ? !UseSSL : ConnectionUri.Scheme != Uri.UriSchemeHttps)
            {
                problem = "The CertificateThumbprint parameter requires UseSSL or a https ConnectionUri, certificate authentication is only available over HTTPS.";
            }

            if (problem is not null)
            {
                ThrowTerminatingError(new ErrorRecord(new ArgumentException(problem), "WinRSCommandInvalidParameter",
                    ErrorCategory.InvalidArgument, null));
            }
        }
    }

    protected override void StopProcessing()
    {
        _cts.Cancel();
    }

    /// <summary>Aborts anything still running, a no-op after a normal finish.</summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Disposing the shell aborts it, which kills a still running command on every exit path but the normal
            // one.
            _shell?.Dispose();
            _transport?.Dispose();
            _cts.Dispose();
        }
    }

    /// <summary>Connects and creates the cmd shell every command of this cmdlet runs in.</summary>
    /// <param name="codePage">The console code page of the shell.</param>
    private protected WinRSShell OpenShell(int codePage)
    {
        PSTraceSource tracer = BaseClientTransportManager.tracer;

        // Built the same way Invoke-Command builds it, so -SessionOption means the same thing for both.
        // A ConnectionUri is used as is, without a port that means 80 or 443 as it does for Invoke-Command.
        WSManConnectionInfo connInfo = ConnectionUri is null
            ? new(UseSSL, ComputerName, Port, ApplicationName, CmdShellUri, Credential)
            : new(ConnectionUri, CmdShellUri, Credential);
        if (CertificateThumbprint is not null)
        {
            // The setter rejects null rather than treating it as unset.
            connInfo.CertificateThumbprint = CertificateThumbprint;
        }
        PSWSManSessionOption? extraOptions = null;
        if (SessionOption is not null)
        {
            connInfo.SetSessionOptions(SessionOption);
            extraOptions = WSManTransportFactory.GetExtraOptions(SessionOption);
        }
        Uri connectionUri = WSManTransportFactory.GetConnectionUri(connInfo);

        _transport = WSManTransportFactory.Create(connectionUri, connInfo, extraOptions,
            WSManPSRPSession.DefaultMaxEnvelopeSize, tracer.WriteLine, Authentication);
        _shell = new WinRSShell(_transport.Pool, _transport.Client, CmdShellUri, tracer.WriteLine)
        {
            ReceiveRetries = Math.Max(connInfo.MaxConnectionRetryCount, 0),
        };

        OptionSet shellOptions = new();
        shellOptions.Add("WINRS_CODEPAGE", codePage.ToString(CultureInfo.InvariantCulture));
        if (connInfo.NoMachineProfile)
        {
            shellOptions.Add("WINRS_NOPROFILE", "TRUE");
        }
        WriteVerbose($"Creating WinRS shell on '{ConnectionTarget}'");
        _shell.Open(options: shellOptions, cancellationToken: StopToken);
        WriteVerbose($"Created WinRS shell {_shell.ShellId}");

        return _shell;
    }

    /// <summary>Starts a command in the shell opened by <see cref="OpenShell"/>.</summary>
    /// <param name="commandLine">The command line to run.</param>
    /// <param name="description">What to call the command in verbose messages, defaults to the command line.</param>
    private protected WinRSCommand StartCommand(string commandLine, string? description = null)
    {
        WinRSShell shell = Shell;
        WriteVerbose($"Starting command in WinRS shell {shell.ShellId}: {description ?? commandLine}");
        WinRSCommand command = WinRSCommand.Start(shell, commandLine, StopToken);
        WriteVerbose($"Started command {command.CommandId}");

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

    /// <summary>Deletes the shell on the server.</summary>
    private protected void CloseShell()
    {
        // Close marks the shell closed even when its Delete is cancelled, which would turn the abort in Dispose
        // into a no-op and leave the shell and its processes running on the server.
        if (_shell is not null && !_cts.IsCancellationRequested)
        {
            WriteVerbose($"Closing WinRS shell {_shell.ShellId}");
            _shell.Close(StopToken);
            WriteVerbose($"Closed WinRS shell {_shell.ShellId}");
        }
    }

    /// <summary>
    /// Called on the pipeline thread when the cmdlet is stopped, before the shell is aborted, to give the remote
    /// side a chance to finish cleanly. Nothing can be written to the pipeline by then.
    /// </summary>
    private protected virtual void OnStopping()
    {
    }

    /// <summary>Runs one phase of the cmdlet, turning transport failures into terminating errors.</summary>
    private protected void Guard(Action phase)
    {
        try
        {
            phase();
        }
        catch (Exception e) when (e is PipelineStoppedException or FlowControlException)
        {
            // Raised by PowerShell itself, like a write after the pipeline has been stopped, so it must reach the
            // engine unchanged rather than become an error record.
            if (e is PipelineStoppedException)
            {
                OnStopping();
            }
            throw;
        }
        catch (OperationCanceledException) when (_cts.IsCancellationRequested)
        {
            // Stopped with Ctrl+C or by the pipeline, Dispose tears the shell down.
            OnStopping();
        }
        catch (Exception e) when (e is WSManException or AuthenticationException or HttpRequestException
            or SocketException or IOException or TimeoutException or ArgumentException)
        {
            ErrorCategory category = e switch
            {
                AuthenticationException => ErrorCategory.AuthenticationError,
                WSManFault => ErrorCategory.InvalidOperation,
                ArgumentException => ErrorCategory.InvalidArgument,
                _ => ErrorCategory.ConnectionError,
            };
            ThrowTerminatingError(new ErrorRecord(e, "WinRSCommandFailed", category, ConnectionTarget));
        }
    }
}
