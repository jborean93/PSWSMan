// PSHost implementations for the tests that record every member called on them. Each call is recorded as
// Member(arguments) in Calls and every member returns a distinct value, so a test can check a call reached the host
// with its arguments and that the value made it back.
//
// RecordingHost implements the optional host interfaces like the console host does, PlainHost does not. With
// throwOnClear the RawUI fails SetBufferContents(Rectangle, BufferCell) the way the console host on non-Windows does.
#nullable enable
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Security;

namespace PSWSManTests;

public abstract class RecordingHostBase : PSHost
{
    private readonly List<string> _calls = new();
    private bool _debuggerEnabled = true;

    public static readonly Guid FixedInstanceId = new("6b8f64e3-5a44-4ac1-9c5c-2f2c0f1b8f3e");

    public string[] Calls
    {
        get
        {
            lock (_calls)
            {
                return _calls.ToArray();
            }
        }
    }

    public void ClearCalls()
    {
        lock (_calls)
        {
            _calls.Clear();
        }
    }

    internal T Return<T>(T result, string member, params object?[] args)
    {
        Record(member, args);
        return result;
    }

    internal void Record(string member, params object?[] args)
    {
        string entry = $"{member}({string.Join(", ", args.Select(Format))})";
        lock (_calls)
        {
            _calls.Add(entry);
        }
    }

    private static string Format(object? value) => value switch
    {
        null => "null",
        string s => s,
        Rectangle r => $"{r.Left},{r.Top},{r.Right},{r.Bottom}",
        Coordinates c => $"{c.X},{c.Y}",
        Size s => $"{s.Width}x{s.Height}",
        BufferCell b => $"'{b.Character}' {b.ForegroundColor}/{b.BackgroundColor}",
        BufferCell[,] cells => $"cells {cells.GetLength(0)}x{cells.GetLength(1)} '{cells[0, 0].Character}'",
        Collection<FieldDescription> fields => string.Join("|", fields.Select(f => f.Name)),
        Collection<ChoiceDescription> choices => string.Join("|", choices.Select(c => c.Label)),
        IEnumerable<int> ints => string.Join("|", ints),
        ProgressRecord p => $"{p.ActivityId} {p.Activity} {p.StatusDescription}",
        InformationRecord i => $"{i.MessageData}",
        Runspace r => $"runspace {r.Name}",
        _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "",
    };

    public override string Name => Return("RecordingHost", "get_Name");
    public override Version Version => Return(new Version(1, 2, 3), "get_Version");
    public override Guid InstanceId => Return(FixedInstanceId, "get_InstanceId");
    public override CultureInfo CurrentCulture => Return(new CultureInfo("de-DE"), "get_CurrentCulture");
    public override CultureInfo CurrentUICulture => Return(new CultureInfo("fr-FR"), "get_CurrentUICulture");
    public override PSObject PrivateData => Return(new PSObject("private data"), "get_PrivateData");

    public override bool DebuggerEnabled
    {
        get => Return(_debuggerEnabled, "get_DebuggerEnabled");
        set
        {
            Record("set_DebuggerEnabled", value);
            _debuggerEnabled = value;
        }
    }

    public override void SetShouldExit(int exitCode) => Record("SetShouldExit", exitCode);
    public override void EnterNestedPrompt() => Record("EnterNestedPrompt");
    public override void ExitNestedPrompt() => Record("ExitNestedPrompt");
    public override void NotifyBeginApplication() => Record("NotifyBeginApplication");
    public override void NotifyEndApplication() => Record("NotifyEndApplication");
}

public sealed class RecordingHost : RecordingHostBase, IHostSupportsInteractiveSession
{
    private readonly PSHostUserInterface? _ui;

    public RecordingHost(bool throwOnClear = false, bool withUI = true, bool withRawUI = true)
    {
        _ui = withUI ? new RecordingUI(this, withRawUI ? new RecordingRawUI(this, throwOnClear) : null) : null;
    }

    public override PSHostUserInterface? UI => _ui;

    public bool IsRunspacePushed => Return(true, "get_IsRunspacePushed");
    public Runspace? Runspace => Return<Runspace?>(null, "get_Runspace");
    /// <summary>The runspace given to the last PushRunspace call.</summary>
    public Runspace? PushedRunspace { get; private set; }

    /// <summary>Thrown by PushRunspace when set, after the call is recorded.</summary>
    public Exception? PushException { get; set; }

    public void PushRunspace(Runspace runspace)
    {
        Record("PushRunspace", runspace);
        PushedRunspace = runspace;
        if (PushException is not null)
        {
            throw PushException;
        }
    }
    public void PopRunspace() => Record("PopRunspace");
}

public sealed class PlainHost : RecordingHostBase
{
    private readonly PSHostUserInterface? _ui;

    public PlainHost(bool withUI = true)
    {
        _ui = withUI ? new RecordingUIBase(this, null) : null;
    }

    public override PSHostUserInterface? UI => _ui;
}

public class RecordingUIBase : PSHostUserInterface
{
    private readonly PSHostRawUserInterface? _rawUI;

    internal RecordingUIBase(RecordingHostBase host, PSHostRawUserInterface? rawUI)
    {
        Host = host;
        _rawUI = rawUI;
    }

    internal RecordingHostBase Host { get; }

    public override PSHostRawUserInterface? RawUI => _rawUI;
    public override bool SupportsVirtualTerminal => Host.Return(true, "get_SupportsVirtualTerminal");

    public override string ReadLine() => Host.Return("read line", "ReadLine");

    public override SecureString ReadLineAsSecureString()
    {
        SecureString value = new();
        foreach (char c in "secret line")
        {
            value.AppendChar(c);
        }
        return Host.Return(value, "ReadLineAsSecureString");
    }

    public override void Write(string value) => Host.Record("Write", value);
    public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
        => Host.Record("Write", foregroundColor, backgroundColor, value);
    public override void WriteLine() => Host.Record("WriteLine");
    public override void WriteLine(string value) => Host.Record("WriteLine", value);
    public override void WriteLine(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
        => Host.Record("WriteLine", foregroundColor, backgroundColor, value);
    public override void WriteErrorLine(string value) => Host.Record("WriteErrorLine", value);
    public override void WriteDebugLine(string message) => Host.Record("WriteDebugLine", message);
    public override void WriteProgress(long sourceId, ProgressRecord record)
        => Host.Record("WriteProgress", sourceId, record);
    public override void WriteVerboseLine(string message) => Host.Record("WriteVerboseLine", message);
    public override void WriteWarningLine(string message) => Host.Record("WriteWarningLine", message);
    public override void WriteInformation(InformationRecord record) => Host.Record("WriteInformation", record);

    public override Dictionary<string, PSObject> Prompt(string caption, string message,
        Collection<FieldDescription> descriptions)
    {
        Dictionary<string, PSObject> result = new();
        foreach (FieldDescription field in descriptions)
        {
            result[field.Name] = new PSObject($"value of {field.Name}");
        }
        return Host.Return(result, "Prompt", caption, message, descriptions);
    }

    public override PSCredential PromptForCredential(string caption, string message, string userName,
        string targetName)
        => Host.Return(NewCredential("credential user"), "PromptForCredential", caption, message, userName,
            targetName);

    public override PSCredential PromptForCredential(string caption, string message, string userName,
        string targetName, PSCredentialTypes allowedCredentialTypes, PSCredentialUIOptions options)
        => Host.Return(NewCredential("credential user options"), "PromptForCredential", caption, message, userName,
            targetName, allowedCredentialTypes, options);

    public override int PromptForChoice(string caption, string message, Collection<ChoiceDescription> choices,
        int defaultChoice)
        => Host.Return(1, "PromptForChoice", caption, message, choices, defaultChoice);

    private static PSCredential NewCredential(string userName)
    {
        SecureString password = new();
        foreach (char c in "credential password")
        {
            password.AppendChar(c);
        }
        return new PSCredential(userName, password);
    }
}

public sealed class RecordingUI : RecordingUIBase, IHostUISupportsMultipleChoiceSelection
{
    internal RecordingUI(RecordingHostBase host, PSHostRawUserInterface? rawUI) : base(host, rawUI)
    {
    }

    public Collection<int> PromptForChoice(string? caption, string? message, Collection<ChoiceDescription> choices,
        IEnumerable<int>? defaultChoices)
        => Host.Return(new Collection<int> { 0, 2 }, "PromptForChoice", caption, message, choices, defaultChoices);
}

public sealed class RecordingRawUI : PSHostRawUserInterface
{
    private readonly RecordingHostBase _host;
    private readonly bool _throwOnClear;

    internal RecordingRawUI(RecordingHostBase host, bool throwOnClear)
    {
        _host = host;
        _throwOnClear = throwOnClear;
    }

    public override ConsoleColor ForegroundColor
    {
        get => _host.Return(ConsoleColor.DarkCyan, "get_ForegroundColor");
        set => _host.Record("set_ForegroundColor", value);
    }

    public override ConsoleColor BackgroundColor
    {
        get => _host.Return(ConsoleColor.DarkMagenta, "get_BackgroundColor");
        set => _host.Record("set_BackgroundColor", value);
    }

    public override Coordinates CursorPosition
    {
        get => _host.Return(new Coordinates(3, 4), "get_CursorPosition");
        set => _host.Record("set_CursorPosition", value);
    }

    public override Coordinates WindowPosition
    {
        get => _host.Return(new Coordinates(5, 6), "get_WindowPosition");
        set => _host.Record("set_WindowPosition", value);
    }

    public override int CursorSize
    {
        get => _host.Return(17, "get_CursorSize");
        set => _host.Record("set_CursorSize", value);
    }

    public override Size BufferSize
    {
        get => _host.Return(new Size(121, 3001), "get_BufferSize");
        set => _host.Record("set_BufferSize", value);
    }

    public override Size WindowSize
    {
        get => _host.Return(new Size(119, 41), "get_WindowSize");
        set => _host.Record("set_WindowSize", value);
    }

    public override Size MaxWindowSize => _host.Return(new Size(201, 61), "get_MaxWindowSize");
    public override Size MaxPhysicalWindowSize => _host.Return(new Size(301, 81), "get_MaxPhysicalWindowSize");
    public override bool KeyAvailable => _host.Return(true, "get_KeyAvailable");

    public override string WindowTitle
    {
        get => _host.Return("recording title", "get_WindowTitle");
        set => _host.Record("set_WindowTitle", value);
    }

    public override KeyInfo ReadKey(ReadKeyOptions options)
        => _host.Return(new KeyInfo(65, 'A', ControlKeyStates.ShiftPressed, true), "ReadKey", options);

    public override void FlushInputBuffer() => _host.Record("FlushInputBuffer");

    public override void SetBufferContents(Coordinates origin, BufferCell[,] contents)
        => _host.Record("SetBufferContents", origin, contents);

    public override void SetBufferContents(Rectangle rectangle, BufferCell fill)
    {
        _host.Record("SetBufferContents", rectangle, fill);
        if (_throwOnClear)
        {
            throw new NotImplementedException("The method or operation is not implemented.");
        }
    }

    public override BufferCell[,] GetBufferContents(Rectangle rectangle)
    {
        BufferCell[,] cells = new BufferCell[1, 2];
        cells[0, 0] = new BufferCell('g', ConsoleColor.Green, ConsoleColor.Black, BufferCellType.Complete);
        return _host.Return(cells, "GetBufferContents", rectangle);
    }

    public override void ScrollBufferContents(Rectangle source, Coordinates destination, Rectangle clip,
        BufferCell fill)
        => _host.Record("ScrollBufferContents", source, destination, clip, fill);

    public override int LengthInBufferCells(string source) => _host.Return(101, "LengthInBufferCells", source);

    public override int LengthInBufferCells(string source, int offset)
        => _host.Return(102, "LengthInBufferCells", source, offset);

    public override int LengthInBufferCells(char source) => _host.Return(103, "LengthInBufferCells", source);
}
