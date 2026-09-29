using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Management.Automation.Remoting;
using System.Management.Automation.Runspaces;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.PowerShell.Commands;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsLifecycle.Invoke, "WinRMCommand",
    DefaultParameterSetName = "ComputerName"
)]
[Alias("iwcm")]
[OutputType(typeof(object))]
public sealed class InvokeWinRMCommand : WinRMCmdletBase
{
    private const int DefaultThrottleLimit = 32;

    private readonly BlockingCollection<Action> _pipeline = new();
    private readonly List<Target> _targets = new();
    private Task? _worker;
    private bool _propagateThrows;

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "FilePathComputerName"
    )]
    [ValidateNotNullOrEmpty]
    [Alias("Cn")]
    public string[] ComputerName { get; set; } = [];

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "ConnectionUri"
    )]
    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "FilePathConnectionUri"
    )]
    [ValidateNotNullOrEmpty]
    [Alias("URI", "CU")]
    public Uri[] ConnectionUri { get; set; } = [];

    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "Session"
    )]
    [Parameter(
        Mandatory = true,
        Position = 0,
        ParameterSetName = "FilePathSession"
    )]
    [ValidateNotNullOrEmpty]
    public PSSession[] Session { get; set; } = [];

    [Parameter(
        Mandatory = true,
        Position = 1,
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        Mandatory = true,
        Position = 1,
        ParameterSetName = "ConnectionUri"
    )]
    [Parameter(
        Mandatory = true,
        Position = 1,
        ParameterSetName = "Session"
    )]
    [Alias("Command")]
    public ScriptBlock ScriptBlock { get; set; } = null!;

    [Parameter(
        Mandatory = true,
        Position = 1,
        ParameterSetName = "FilePathComputerName"
    )]
    [Parameter(
        Mandatory = true,
        Position = 1,
        ParameterSetName = "FilePathConnectionUri"
    )]
    [Parameter(
        Mandatory = true,
        Position = 1,
        ParameterSetName = "FilePathSession"
    )]
    [Alias("PSPath")]
    public string FilePath { get; set; } = "";

    [Parameter]
    [ArgumentsOrParametersTransform]
    [Alias("Args")]
    public ArgumentsOrParameters? ArgumentList { get; set; }

    [Parameter(
        ValueFromPipeline = true
    )]
    public PSObject? InputObject { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "ConnectionUri"
    )]
    [Parameter(
        ParameterSetName = "FilePathComputerName"
    )]
    [Parameter(
        ParameterSetName = "FilePathConnectionUri"
    )]
    [ValidateNotNullOrEmpty]
    public string ConfigurationName { get; set; } = "Microsoft.PowerShell";

    [Parameter]
    public int ThrottleLimit { get; set; } = DefaultThrottleLimit;

    [Parameter]
    [Alias("HCN")]
    public SwitchParameter HideComputerName { get; set; }

    // The connection parameters of the base class are only in its ComputerName and ConnectionUri sets, these add them
    // to the FilePath variants of the sets.
    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "ConnectionUri"
    )]
    [Parameter(
        ParameterSetName = "FilePathComputerName"
    )]
    [Parameter(
        ParameterSetName = "FilePathConnectionUri"
    )]
    [Credential]
    public new PSCredential? Credential
    {
        get => base.Credential;
        set => base.Credential = value;
    }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "FilePathComputerName"
    )]
    [ValidateRange(1, 65535)]
    public new int Port
    {
        get => base.Port;
        set => base.Port = value;
    }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "FilePathComputerName"
    )]
    public new SwitchParameter UseSSL
    {
        get => base.UseSSL;
        set => base.UseSSL = value;
    }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "FilePathComputerName"
    )]
    [ValidateNotNullOrEmpty]
    public new string ApplicationName
    {
        get => base.ApplicationName;
        set => base.ApplicationName = value;
    }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "ConnectionUri"
    )]
    [Parameter(
        ParameterSetName = "FilePathComputerName"
    )]
    [Parameter(
        ParameterSetName = "FilePathConnectionUri"
    )]
    [WinRMSessionOptionTransform]
    public new WinRMSessionOption? SessionOption
    {
        get => base.SessionOption;
        set => base.SessionOption = value;
    }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "ConnectionUri"
    )]
    [Parameter(
        ParameterSetName = "FilePathComputerName"
    )]
    [Parameter(
        ParameterSetName = "FilePathConnectionUri"
    )]
    public new AuthenticationMethod Authentication
    {
        get => base.Authentication;
        set => base.Authentication = value;
    }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    [Parameter(
        ParameterSetName = "ConnectionUri"
    )]
    [Parameter(
        ParameterSetName = "FilePathComputerName"
    )]
    [Parameter(
        ParameterSetName = "FilePathConnectionUri"
    )]
    [ValidateNotNullOrEmpty]
    public new string? CertificateThumbprint
    {
        get => base.CertificateThumbprint;
        set => base.CertificateThumbprint = value;
    }

    private protected override string ConnectionTarget => string.Join(", ", _targets.ConvertAll(t => t.ErrorTarget));

    private protected override string ErrorIdPrefix => "WinRMCommand";

    private protected override bool UsesComputerName => ParameterSetName is "ComputerName" or "FilePathComputerName";

    protected override void BeginProcessing()
    {
        base.BeginProcessing();

        // Like Invoke-Command a remote throw statement ends the calling script when there is a single target, with
        // several targets it is an error of the host it came from like any other.
        _propagateThrows = ParameterSetName switch
        {
            "Session" or "FilePathSession" => Session.Length == 1,
            "ConnectionUri" or "FilePathConnectionUri" => ConnectionUri.Length == 1,
            _ => ComputerName.Length == 1,
        };

        RemoteScript script = GetRemoteScript();
        if (!AddTargets())
        {
            _pipeline.CompleteAdding();
            return;
        }

        if (!MyInvocation.ExpectingInput)
        {
            // Without pipeline input the command reads nothing but -InputObject, when given, so its input ends here
            // rather than leaving it waiting for more.
            foreach (Target target in _targets)
            {
                if (MyInvocation.BoundParameters.ContainsKey(nameof(InputObject)))
                {
                    target.Input.Add(InputObject);
                }
                target.Input.Complete();
            }
        }

        // The workers connect from their own threads, the options are resolved against the session state here.
        _ = Options;
        int throttleLimit = ThrottleLimit > 0 ? ThrottleLimit : DefaultThrottleLimit;
        _worker = Task.Run(async () =>
        {
            try
            {
                await RunAllAsync(script, throttleLimit).ConfigureAwait(false);
            }
            finally
            {
                _pipeline.CompleteAdding();
            }
        });
    }

    protected override void ProcessRecord()
    {
        if (MyInvocation.ExpectingInput)
        {
            foreach (Target target in _targets)
            {
                target.Input.Add(InputObject);
            }
        }

        while (_pipeline.TryTake(out Action? write))
        {
            write();
        }
    }

    protected override void EndProcessing()
    {
        foreach (Target target in _targets)
        {
            target.Input.Complete();
        }

        try
        {
            foreach (Action write in _pipeline.GetConsumingEnumerable(StopToken))
            {
                write();
            }
        }
        catch (OperationCanceledException) when (StopToken.IsCancellationRequested)
        {
            // Stopped with Ctrl+C, the workers stop the remote commands and close the connections they opened.
        }
    }

    protected override void Dispose(bool disposing)
    {
        // After a stop the workers can still be stopping the remote commands and closing the connections, they keep
        // using the collections until they are done so those are left to the garbage collector.
        if (disposing && (_worker is null || _worker.IsCompleted))
        {
            foreach (Target target in _targets)
            {
                target.Input.Dispose();
            }
            _pipeline.Dispose();
        }
        base.Dispose(disposing);
    }

    /// <summary>Gets the script to run from -ScriptBlock or -FilePath with the values of its $using: expressions.</summary>
    private RemoteScript GetRemoteScript()
    {
        string text;
        Ast ast;
        if (ParameterSetName.StartsWith("FilePath", StringComparison.Ordinal))
        {
            string path = SessionState.Path.GetUnresolvedProviderPathFromPSPath(FilePath, out ProviderInfo provider,
                out _);
            if (provider.ImplementingType != typeof(FileSystemProvider))
            {
                ThrowTerminatingError(new ErrorRecord(
                    new ArgumentException($"The FilePath '{FilePath}' is not a file system path."),
                    $"{ErrorIdPrefix}FilePathNotFileSystem",
                    ErrorCategory.InvalidArgument,
                    FilePath));
            }
            if (!File.Exists(path))
            {
                ThrowTerminatingError(new ErrorRecord(
                    new FileNotFoundException($"Cannot find the FilePath '{path}' because it does not exist.", path),
                    $"{ErrorIdPrefix}FilePathNotFound",
                    ErrorCategory.ObjectNotFound,
                    FilePath));
            }

            text = File.ReadAllText(path);
            ast = Parser.ParseInput(text, path, out _, out ParseError[] errors);
            if (errors.Length > 0)
            {
                ThrowTerminatingError(new ErrorRecord(
                    new ParseException(errors),
                    $"{ErrorIdPrefix}FilePathParseError",
                    ErrorCategory.ParserError,
                    FilePath));
            }
        }
        else
        {
            text = ScriptBlock.ToString();
            ast = ScriptBlock.Ast;
        }

        Hashtable usingValues;
        try
        {
            usingValues = UsingVariableParser.GetUsingParameters(SessionState, ast);
        }
        catch (ArgumentException e)
        {
            ThrowTerminatingError(new ErrorRecord(
                e,
                "UsingVariableIsUndefined",
                ErrorCategory.InvalidArgument,
                null));
            throw;
        }

        return new(text, usingValues);
    }

    /// <summary>Adds a target for each host or session, writing an error for those that cannot be used.</summary>
    /// <returns>Whether there is any target to run the command on.</returns>
    private bool AddTargets()
    {
        if (ParameterSetName is "Session" or "FilePathSession")
        {
            foreach (PSSession session in Session)
            {
                RunspaceState state = session.Runspace.RunspaceStateInfo.State;
                if (state != RunspaceState.Opened)
                {
                    WriteError(new ErrorRecord(
                        new InvalidOperationException(
                            $"The session '{session.Name}' to '{session.ComputerName}' is {state}, a command can only run in an open session."),
                        $"{ErrorIdPrefix}SessionNotOpen",
                        ErrorCategory.InvalidOperation,
                        session));
                    continue;
                }
                _targets.Add(new(session.ComputerName, session.Name, null, session));
            }
        }
        else if (ParameterSetName is "ConnectionUri" or "FilePathConnectionUri")
        {
            foreach (Uri uri in ConnectionUri)
            {
                if (ValidateConnectionUri(uri) is ErrorRecord err)
                {
                    WriteError(err);
                    continue;
                }
                _targets.Add(new(uri.Host, uri.OriginalString, uri, null));
            }
        }
        else
        {
            foreach (string computerName in ComputerName)
            {
                _targets.Add(new(computerName, computerName, GetConnectionUri(computerName), null));
            }
        }

        return _targets.Count > 0;
    }

    private async Task RunAllAsync(RemoteScript script, int throttleLimit)
    {
        using SemaphoreSlim throttle = new(throttleLimit);
        List<Task> running = new();
        foreach (Target target in _targets)
        {
            try
            {
                await throttle.WaitAsync(StopToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            running.Add(Task.Run(async () =>
            {
                try
                {
                    await RunTargetAsync(target, script).ConfigureAwait(false);
                }
                finally
                {
                    throttle.Release();
                }
            }));
        }

        await Task.WhenAll(running).ConfigureAwait(false);
    }

    private async Task RunTargetAsync(Target target, RemoteScript script)
    {
        Runspace? runspace = target.Session?.Runspace;
        bool owned = runspace is null;
        try
        {
            if (owned)
            {
                (runspace, Task opened) = StartOpenSession(target.Uri!, ConfigurationName, target.ErrorTarget,
                    StopToken);
                try
                {
                    await opened.ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    if (!StopToken.IsCancellationRequested)
                    {
                        Post(() => WriteError(new ErrorRecord(e, $"{ErrorIdPrefix}OpenFailed", ErrorCategory.OpenError,
                            target.ErrorTarget)));
                    }
                    return;
                }
            }

            await InvokeAsync(target, runspace!, script).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            // Nothing may escape a worker, the pipeline thread would never hear about it.
            if (!StopToken.IsCancellationRequested)
            {
                Post(() => WriteError(new ErrorRecord(e, $"{ErrorIdPrefix}Failed", ErrorCategory.NotSpecified,
                    target.ErrorTarget)));
            }
        }
        finally
        {
            if (owned)
            {
                runspace?.Dispose();
            }
        }
    }

    private async Task InvokeAsync(Target target, Runspace runspace, RemoteScript script)
    {
        OriginInfo origin = new(target.Name, runspace.InstanceId);
        bool showComputerName = !HideComputerName;

        using PowerShell ps = PowerShell.Create();
        ps.Runspace = runspace;
        ps.AddScript(script.Text);
        if (ArgumentList is not null)
        {
            foreach (object? argument in ArgumentList.Arguments)
            {
                ps.AddArgument(argument);
            }
            foreach (KeyValuePair<string, object?> parameter in ArgumentList.Parameters)
            {
                ps.AddParameter(parameter.Key, parameter.Value);
            }
        }
        if (script.UsingValues.Count > 0)
        {
            // How PowerShell passes the $using: values of a script, the same as Invoke-Command does.
            ps.AddParameter("--%", script.UsingValues);
        }

        // Each stream is handed to the pipeline thread as its records arrive, and taken out of the collection so a
        // long running command does not keep them all. The remote host has already shown the warning, verbose, debug
        // and progress records through the host of the session, Invoke-Command only puts the warnings in
        // -WarningVariable rather than showing them again.
        using PSDataCollection<PSObject?> output = new();
        Forward(output, obj => WriteObject(AddOrigin(obj, target.Name, runspace.InstanceId, showComputerName)));
        Forward(ps.Streams.Error, r => WriteError(new RemotingErrorRecord(r, origin)));
        Forward(ps.Streams.Warning, AppendWarningVariable);
        Forward<VerboseRecord>(ps.Streams.Verbose, null);
        Forward<DebugRecord>(ps.Streams.Debug, null);
        Forward<ProgressRecord>(ps.Streams.Progress, null);
        Forward(ps.Streams.Information, r =>
        {
            // The same for Write-Host, it was shown through the host so the record is only added to the stream.
            if (r.Tags.Contains("PSHOST") && !r.Tags.Contains("FORWARDED"))
            {
                r.Tags.Add("FORWARDED");
            }
            WriteInformation(new RemotingInformationRecord(r, origin));
        });

        using CancellationTokenRegistration stop = StopToken.Register(() =>
        {
            try
            {
                ps.BeginStop(null, null);
            }
            catch (Exception)
            {
                // The command may have finished or failed already.
            }
        });

        try
        {
            await ps.InvokeAsync(target.Input, output).ConfigureAwait(false);
        }
        catch (PipelineStoppedException) when (StopToken.IsCancellationRequested)
        {
        }
        catch (RemoteException e) when (_propagateThrows && IsFromThrowStatement(e))
        {
            // Thrown from the pipeline thread with the flag set PowerShell treats it as a throw in the calling script
            // rather than wrapping it as a cmdlet failure, so -ErrorAction does not apply and try/catch catches it.
            e.WasThrownFromThrowStatement = true;
            Post(() => throw e);
        }
        catch (RuntimeException e) when (e is not PSRemotingTransportException)
        {
            // Any other terminating error in the remote command is an error of the host, like Invoke-Command does.
            Post(() => WriteError(new RemotingErrorRecord(e.ErrorRecord, origin)));
        }
    }

    /// <summary>Whether the remote error came from a throw statement in the remote command.</summary>
    private static bool IsFromThrowStatement(RemoteException exception)
        => exception.SerializedRemoteException?.Properties["WasThrownFromThrowStatement"]?.Value is true;

    /// <summary>Hands each record added to the collection to the pipeline thread, or just drops it without a writer.</summary>
    private void Forward<T>(PSDataCollection<T> collection, Action<T>? write)
    {
        collection.DataAdded += (_, _) =>
        {
            foreach (T item in collection.ReadAll())
            {
                if (write is not null)
                {
                    Post(() => write(item));
                }
            }
        };
    }

    /// <summary>Adds a remote warning to the -WarningVariable of the cmdlet without showing it again.</summary>
    /// <remarks>
    /// PowerShell creates the list the variable holds before the cmdlet runs, adding to it is what WriteWarning does
    /// minus the host output, which is internal.
    /// </remarks>
    private void AppendWarningVariable(WarningRecord record)
    {
        if (MyInvocation.BoundParameters.TryGetValue("WarningVariable", out object? name) &&
            name is string variableName &&
            SessionState.PSVariable.GetValue(variableName.TrimStart('+')) is IList warnings)
        {
            warnings.Add(record);
        }
    }

    /// <summary>Queues an action for the pipeline thread, dropping it when the cmdlet is already done.</summary>
    private void Post(Action write)
    {
        try
        {
            _pipeline.Add(write);
        }
        catch (Exception e) when (e is ObjectDisposedException or InvalidOperationException)
        {
            // The cmdlet has stopped or finished, nothing can be written any more.
        }
    }

    /// <summary>Adds the properties Invoke-Command puts on each output object.</summary>
    private static PSObject? AddOrigin(PSObject? obj, string computerName, Guid runspaceId, bool showComputerName)
    {
        if (obj is null)
        {
            return null;
        }

        SetNoteProperty(obj, "PSComputerName", computerName);
        SetNoteProperty(obj, "RunspaceId", runspaceId);
        SetNoteProperty(obj, "PSShowComputerName", showComputerName);
        return obj;
    }

    private static void SetNoteProperty(PSObject obj, string name, object value)
    {
        obj.Properties.Remove(name);
        obj.Properties.Add(new PSNoteProperty(name, value));
    }

    private sealed record RemoteScript(string Text, Hashtable UsingValues);

    /// <param name="Name">The host name shown as PSComputerName.</param>
    /// <param name="ErrorTarget">What the user gave for the host, the target of its errors.</param>
    /// <param name="Uri">The endpoint to connect to, null for a session.</param>
    /// <param name="Session">The session to run the command in, null to connect to <paramref name="Uri"/>.</param>
    private sealed record Target(string Name, string ErrorTarget, Uri? Uri, PSSession? Session)
    {
        public PSDataCollection<PSObject?> Input { get; } = new();
    }
}
