using System;
using System.Management.Automation.Host;

namespace PSWSMan;

/// <summary>Makes a remote Clear-Host clear the screen of a client host that cannot do it itself.</summary>
/// <remarks>
/// Clear-Host on a Windows server moves the cursor to 0,0 and calls RawUI.SetBufferContents with a rectangle of -1
/// and a space fill, which means clear the whole screen. The console host on non-Windows does not implement
/// SetBufferContents at all so the remote Clear-Host only moves the cursor and fails with 'The method or operation is
/// not implemented'.
///
/// The host is always called first and this only replaces its not implemented failure for the full screen clear, so a
/// host that does implement SetBufferContents, the Windows console host or a custom host, keeps its own behaviour.
/// Console.Clear() is what the console host would do for this call and matches the local Clear-Host on non-Windows.
///
/// The WinRM session cmdlets apply it through WinRMClientHost, the host they give the runspace. The builtin cmdlets
/// create the runspace with their own host so Enable-PSWSMan applies it with a patch of
/// RemoteHostCall.ExecuteVoidMethod. Both should be removed if/when PowerShell fixes the problem.
///
/// https://github.com/PowerShell/PowerShell/issues/28115
/// https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/InitialSessionState.cs#L4090
/// https://github.com/PowerShell/PowerShell/blob/3f3d79d4758704c8dad5ca7c12690ba62fd03a3b/src/System.Management.Automation/engine/remoting/common/WireDataFormat/RemoteHost.cs#L169
/// </remarks>
internal static class RemoteClearHost
{
    /// <summary>Whether the SetBufferContents arguments are the full screen clear of the remote Clear-Host.</summary>
    public static bool IsClearScreen(Rectangle rectangle, BufferCell fill)
        => rectangle is { Left: -1, Top: -1, Right: -1, Bottom: -1 } && fill.Character == ' ';

    /// <summary>Clears the screen in place of the host.</summary>
    public static void Clear()
    {
        // There is no screen to clear when stdout is redirected, Unix treats that as a no-op but Windows throws.
        if (!Console.IsOutputRedirected)
        {
            Console.Clear();
        }
    }
}
