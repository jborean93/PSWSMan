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
using System.Text;
using System.Threading;

namespace PSWSMan.Commands;

/// <summary>The connection parameters and error handling shared by the cmdlets that create a WinRS cmd shell.</summary>
public abstract class WinRSConnectionCmdletBase : PSCmdlet, IDisposable
{
    private protected const string CmdShellUri = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

    // How long a stopped cmdlet gives the remote process to exit on its own before the shell is aborted.
    private protected static readonly TimeSpan StopGracePeriod = TimeSpan.FromSeconds(10);

    private readonly CancellationTokenSource _cts = new();

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

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "ConnectionUri"
    )]
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

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "ConnectionUri"
    )]
    public PSSessionOption? SessionOption { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "ConnectionUri"
    )]
    public AuthenticationMethod Authentication { get; set; } = AuthenticationMethod.Default;

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "ConnectionUri"
    )]
    [ValidateNotNullOrEmpty]
    public string? CertificateThumbprint { get; set; }

    private protected CancellationToken StopToken => _cts.Token;

    private protected virtual string ConnectionTarget => ConnectionUri?.OriginalString ?? ComputerName;

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

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            _cts.Dispose();
        }
    }

    /// <summary>Connects and creates a cmd shell from the connection parameters.</summary>
    /// <param name="consoleEncoding">The encoding whose code page the shell's console uses.</param>
    /// <returns>The opened shell, the caller closes or aborts it.</returns>
    private protected WinRSRemoteShell ConnectShell(Encoding consoleEncoding)
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

        WSManTransport transport = WSManTransportFactory.Create(connectionUri, connInfo, extraOptions,
            WSManPSRPSession.DefaultMaxEnvelopeSize, tracer.WriteLine, Authentication);
        WinRSShell shell = new(transport.Pool, transport.Client, CmdShellUri, tracer.WriteLine)
        {
            ReceiveRetries = Math.Max(connInfo.MaxConnectionRetryCount, 0),
        };
        WinRSRemoteShell remoteShell = new(transport, shell, connInfo.ComputerName, connectionUri,
            consoleEncoding);

        OptionSet shellOptions = new();
        shellOptions.Add("WINRS_CODEPAGE", consoleEncoding.CodePage.ToString(CultureInfo.InvariantCulture));
        if (connInfo.NoMachineProfile)
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

    /// <summary>
    /// Called on the pipeline thread when the cmdlet is stopped, before anything is torn down, to give the remote
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
        catch (Exception e) when (IsTransportError(e))
        {
            ThrowTerminatingError(new ErrorRecord(e, "WinRSCommandFailed", GetErrorCategory(e), ConnectionTarget));
        }
    }

    /// <summary>Whether an exception is a connection or server failure rather than a bug.</summary>
    internal static bool IsTransportError(Exception e) => e is WSManException or AuthenticationException
        or HttpRequestException or SocketException or IOException or TimeoutException or ArgumentException;

    internal static ErrorCategory GetErrorCategory(Exception e) => e switch
    {
        AuthenticationException => ErrorCategory.AuthenticationError,
        WSManFault => ErrorCategory.InvalidOperation,
        ArgumentException => ErrorCategory.InvalidArgument,
        _ => ErrorCategory.ConnectionError,
    };
}
