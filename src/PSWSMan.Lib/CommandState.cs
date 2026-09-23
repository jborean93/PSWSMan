namespace PSWSMan.Lib;

/// <summary>The state URIs of a WinRS command as reported in a Receive response.</summary>
public static class CommandState
{
    /// <summary>The command has finished running.</summary>
    public const string Done = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done";

    /// <summary>The command is pending and has not started yet.</summary>
    public const string Pending = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Pending";

    /// <summary>The command is still running.</summary>
    public const string Running = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running";
}
