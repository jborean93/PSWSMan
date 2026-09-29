using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Security;

namespace PSWSMan.CustomTransport;

/// <summary>
/// The host given to a WinRM session runspace, it forwards everything to the host of the cmdlet that created the
/// session and only steps in for the remote Clear-Host.
/// </summary>
/// <remarks>
/// Host calls from the remote session run against the host of the runspace, which is how the remote Clear-Host is
/// fixed without patching PowerShell, see <see cref="RemoteClearHost"/>.
/// </remarks>
internal sealed class WinRMClientHost : PSHost, IHostSupportsInteractiveSession
{
    private readonly PSHost _host;
    private readonly WinRMClientHostUI? _ui;

    public WinRMClientHost(PSHost host)
    {
        _host = host;
        _ui = host.UI is null ? null : new(host.UI);
    }

    public override string Name => _host.Name;

    public override Version Version => _host.Version;

    public override Guid InstanceId => _host.InstanceId;

    public override PSHostUserInterface? UI => _ui;

    public override CultureInfo CurrentCulture => _host.CurrentCulture;

    public override CultureInfo CurrentUICulture => _host.CurrentUICulture;

    public override PSObject? PrivateData => _host.PrivateData;

    public override bool DebuggerEnabled
    {
        get => _host.DebuggerEnabled;
        set => _host.DebuggerEnabled = value;
    }

    public override void SetShouldExit(int exitCode) => _host.SetShouldExit(exitCode);

    public override void EnterNestedPrompt() => _host.EnterNestedPrompt();

    public override void ExitNestedPrompt() => _host.ExitNestedPrompt();

    public override void NotifyBeginApplication() => _host.NotifyBeginApplication();

    public override void NotifyEndApplication() => _host.NotifyEndApplication();

    // The remote Exit-PSSession pops the runspace through these, they must reach the real host so it is popped and
    // closed.
    private IHostSupportsInteractiveSession InteractiveHost => _host as IHostSupportsInteractiveSession
        ?? throw new PSNotImplementedException();

    public bool IsRunspacePushed => InteractiveHost.IsRunspacePushed;

    public Runspace? Runspace => InteractiveHost.Runspace;

    public void PushRunspace(Runspace runspace) => InteractiveHost.PushRunspace(runspace);

    public void PopRunspace() => InteractiveHost.PopRunspace();
}

internal sealed class WinRMClientHostUI : PSHostUserInterface, IHostUISupportsMultipleChoiceSelection
{
    private readonly PSHostUserInterface _ui;
    private readonly WinRMClientHostRawUI? _rawUI;

    public WinRMClientHostUI(PSHostUserInterface ui)
    {
        _ui = ui;
        _rawUI = ui.RawUI is null ? null : new(ui.RawUI);
    }

    public override PSHostRawUserInterface? RawUI => _rawUI;

    public override bool SupportsVirtualTerminal => _ui.SupportsVirtualTerminal;

    public override string ReadLine() => _ui.ReadLine();

    public override SecureString ReadLineAsSecureString() => _ui.ReadLineAsSecureString();

    public override void Write(string value) => _ui.Write(value);

    public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
        => _ui.Write(foregroundColor, backgroundColor, value);

    public override void WriteLine() => _ui.WriteLine();

    public override void WriteLine(string value) => _ui.WriteLine(value);

    public override void WriteLine(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
        => _ui.WriteLine(foregroundColor, backgroundColor, value);

    public override void WriteErrorLine(string value) => _ui.WriteErrorLine(value);

    public override void WriteDebugLine(string message) => _ui.WriteDebugLine(message);

    public override void WriteProgress(long sourceId, ProgressRecord record) => _ui.WriteProgress(sourceId, record);

    public override void WriteVerboseLine(string message) => _ui.WriteVerboseLine(message);

    public override void WriteWarningLine(string message) => _ui.WriteWarningLine(message);

    public override void WriteInformation(InformationRecord record) => _ui.WriteInformation(record);

    public override Dictionary<string, PSObject> Prompt(string caption, string message,
        Collection<FieldDescription> descriptions)
        => _ui.Prompt(caption, message, descriptions);

    public override PSCredential PromptForCredential(string caption, string message, string userName,
        string targetName)
        => _ui.PromptForCredential(caption, message, userName, targetName);

    public override PSCredential PromptForCredential(string caption, string message, string userName,
        string targetName, PSCredentialTypes allowedCredentialTypes, PSCredentialUIOptions options)
        => _ui.PromptForCredential(caption, message, userName, targetName, allowedCredentialTypes, options);

    public override int PromptForChoice(string caption, string message, Collection<ChoiceDescription> choices,
        int defaultChoice)
        => _ui.PromptForChoice(caption, message, choices, defaultChoice);

    public Collection<int> PromptForChoice(string? caption, string? message, Collection<ChoiceDescription> choices,
        IEnumerable<int>? defaultChoices)
    {
        if (_ui is IHostUISupportsMultipleChoiceSelection multiChoice)
        {
            return multiChoice.PromptForChoice(caption, message, choices, defaultChoices);
        }

        throw new PSNotImplementedException();
    }
}

internal sealed class WinRMClientHostRawUI : PSHostRawUserInterface
{
    private readonly PSHostRawUserInterface _rawUI;

    public WinRMClientHostRawUI(PSHostRawUserInterface rawUI)
    {
        _rawUI = rawUI;
    }

    public override ConsoleColor ForegroundColor
    {
        get => _rawUI.ForegroundColor;
        set => _rawUI.ForegroundColor = value;
    }

    public override ConsoleColor BackgroundColor
    {
        get => _rawUI.BackgroundColor;
        set => _rawUI.BackgroundColor = value;
    }

    public override Coordinates CursorPosition
    {
        get => _rawUI.CursorPosition;
        set => _rawUI.CursorPosition = value;
    }

    public override Coordinates WindowPosition
    {
        get => _rawUI.WindowPosition;
        set => _rawUI.WindowPosition = value;
    }

    public override int CursorSize
    {
        get => _rawUI.CursorSize;
        set => _rawUI.CursorSize = value;
    }

    public override Size BufferSize
    {
        get => _rawUI.BufferSize;
        set => _rawUI.BufferSize = value;
    }

    public override Size WindowSize
    {
        get => _rawUI.WindowSize;
        set => _rawUI.WindowSize = value;
    }

    public override Size MaxWindowSize => _rawUI.MaxWindowSize;

    public override Size MaxPhysicalWindowSize => _rawUI.MaxPhysicalWindowSize;

    public override bool KeyAvailable => _rawUI.KeyAvailable;

    public override string WindowTitle
    {
        get => _rawUI.WindowTitle;
        set => _rawUI.WindowTitle = value;
    }

    public override KeyInfo ReadKey(ReadKeyOptions options) => _rawUI.ReadKey(options);

    public override void FlushInputBuffer() => _rawUI.FlushInputBuffer();

    public override void SetBufferContents(Coordinates origin, BufferCell[,] contents)
        => _rawUI.SetBufferContents(origin, contents);

    public override void SetBufferContents(Rectangle rectangle, BufferCell fill)
    {
        try
        {
            _rawUI.SetBufferContents(rectangle, fill);
        }
        catch (NotImplementedException) when (RemoteClearHost.IsClearScreen(rectangle, fill))
        {
            RemoteClearHost.Clear();
        }
    }

    public override BufferCell[,] GetBufferContents(Rectangle rectangle) => _rawUI.GetBufferContents(rectangle);

    public override void ScrollBufferContents(Rectangle source, Coordinates destination, Rectangle clip,
        BufferCell fill)
        => _rawUI.ScrollBufferContents(source, destination, clip, fill);

    public override int LengthInBufferCells(string source) => _rawUI.LengthInBufferCells(source);

    public override int LengthInBufferCells(string source, int offset) => _rawUI.LengthInBufferCells(source, offset);

    public override int LengthInBufferCells(char source) => _rawUI.LengthInBufferCells(source);
}
