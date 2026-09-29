using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using PSWSMan.Lib;

namespace PSWSMan.Commands;

/// <summary>The connection options and error handling shared by the cmdlets that connect to a WinRM endpoint.</summary>
/// <remarks>
/// The target itself, -ComputerName or -ConnectionUri, is declared by the derived class as a cmdlet targets either
/// one host or many. The parameter sets are named after those parameters.
/// </remarks>
public abstract class WinRMCmdletBase : PSCmdlet, IDisposable
{
    private const string HttpsRequiredMessage = "The CertificateThumbprint parameter requires UseSSL or a https " +
        "ConnectionUri, certificate authentication is only available over HTTPS.";

    private readonly CancellationTokenSource _cts = new();
    private WinRMSessionOption? _options;
    private Action<string>? _trace;

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
    [WinRMSessionOptionTransform]
    public WinRMSessionOption? SessionOption { get; set; }

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

    /// <summary>The target named in error records and messages.</summary>
    private protected abstract string ConnectionTarget { get; }

    /// <summary>The prefix of the error ids the cmdlet reports.</summary>
    private protected abstract string ErrorIdPrefix { get; }

    /// <summary>The options from -SessionOption, or the defaults, with the TracePath resolved.</summary>
    private protected WinRMSessionOption Options => _options ??= (SessionOption ?? new()).ResolveTracePath(SessionState);

    /// <summary>Writes a diagnostic message to the TracePath file of the options, if set.</summary>
    /// <remarks>
    /// PowerShell's ClientTransport trace source is internal, only the builtin cmdlets patched by Enable-PSWSMan
    /// write to it.
    /// </remarks>
    private protected Action<string> Trace => _trace ??= FileTrace.Create(Options.TracePath) ?? (_ => { });

    protected override void BeginProcessing()
    {
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
            else if (ParameterSetName == "ComputerName" && !UseSSL)
            {
                problem = HttpsRequiredMessage;
            }

            if (problem is not null)
            {
                ThrowTerminatingError(new ErrorRecord(new ArgumentException(problem), $"{ErrorIdPrefix}InvalidParameter",
                    ErrorCategory.InvalidArgument, null));
            }
        }
    }

    /// <summary>Checks a -ConnectionUri value.</summary>
    /// <returns>The error to report for it, or null when it can be used.</returns>
    private protected ErrorRecord? ValidateConnectionUri(Uri connectionUri)
    {
        string? problem = null;
        if (!connectionUri.IsAbsoluteUri ||
            (connectionUri.Scheme != Uri.UriSchemeHttp && connectionUri.Scheme != Uri.UriSchemeHttps))
        {
            problem = $"The ConnectionUri '{connectionUri}' must be an absolute http or https URI.";
        }
        else if (CertificateThumbprint is not null && connectionUri.Scheme != Uri.UriSchemeHttps)
        {
            problem = HttpsRequiredMessage;
        }

        return problem is null
            ? null
            : new ErrorRecord(new ArgumentException(problem), $"{ErrorIdPrefix}InvalidParameter",
                ErrorCategory.InvalidArgument, connectionUri);
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

    /// <summary>The endpoint for a -ComputerName with the -Port, -UseSSL and -ApplicationName parameters.</summary>
    /// <remarks>Without a -Port the WSMan default for the scheme is used.</remarks>
    private protected Uri GetConnectionUri(string computerName)
    {
        int port = Port == 0 ? (UseSSL ? 5986 : 5985) : Port;
        // WSManConnectionInfo builds the URI the way Invoke-Command does, including IPv6 addresses. The shell URI is
        // not part of the endpoint URI, the resource a cmdlet uses is given separately when it connects.
        return new WSManConnectionInfo(UseSSL, computerName, port, ApplicationName, shellUri: null,
            credential: null).ConnectionUri;
    }

    /// <summary>Creates the transport from the connection parameters.</summary>
    private protected WSManTransport CreateTransport(Uri connectionUri)
    {
        return WSManTransportFactory.Create(connectionUri, Credential, CertificateThumbprint, Options,
            WSManPSRPSession.DefaultMaxEnvelopeSize, Trace, Authentication);
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
            // Stopped with Ctrl+C or by the pipeline, Dispose tears the connection down.
            OnStopping();
        }
        catch (Exception e) when (IsTransportError(e))
        {
            ThrowTerminatingError(new ErrorRecord(e, $"{ErrorIdPrefix}Failed", GetErrorCategory(e),
                ConnectionTarget));
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
