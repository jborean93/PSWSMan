namespace PSWSMan.Lib;

/// <summary>The signal code URIs that can be sent to a WinRS shell or command.</summary>
public static class SignalCode
{
    /// <summary>Sends a Ctrl+C to the command.</summary>
    public const string CtrlC = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c";

    /// <summary>Sends a Ctrl+Break to the command.</summary>
    public const string CtrlBreak = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_break";

    /// <summary>Terminates the command.</summary>
    public const string Terminate = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/Terminate";

    /// <summary>The PowerShell specific Ctrl+C signal used to stop a pipeline.</summary>
    public const string PSCtrlC = "powershell/signal/crtl_c";
}
