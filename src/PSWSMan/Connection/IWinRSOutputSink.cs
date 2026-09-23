using System;

namespace PSWSMan.Connection;

/// <summary>Receives the output pumped from a shell or command by a <see cref="WinRSReceivePump"/>.</summary>
/// <remarks>
/// Both methods are called on the pump's own thread. They should hand the data off quickly and must not block on
/// anything the shell needs to close, as <see cref="WinRSShell.Close"/> waits for the pump to exit.
/// </remarks>
internal interface IWinRSOutputSink
{
    /// <summary>Called for each stream chunk in a Receive response, in the order the server returned them.</summary>
    /// <param name="stream">The name of the output stream, e.g. stdout.</param>
    /// <param name="data">The raw bytes of the chunk.</param>
    void OnData(string stream, byte[] data);

    /// <summary>Called exactly once when the pump stops, after the last <see cref="OnData"/>.</summary>
    /// <param name="completion">Why the pump stopped and the exit code if the command finished.</param>
    void OnCompleted(WinRSReceiveCompletion completion);
}

/// <summary>Why a <see cref="WinRSReceivePump"/> stopped.</summary>
internal enum WinRSReceiveReason
{
    /// <summary>The server reported the command state as Done.</summary>
    Done,

    /// <summary>The shell was cancelled or closed locally.</summary>
    Cancelled,

    /// <summary>The server reported the shell or command no longer exists, see <see cref="WinRSReceiveCompletion.Error"/>.</summary>
    ShellClosed,

    /// <summary>An unexpected error stopped the pump, see <see cref="WinRSReceiveCompletion.Error"/>.</summary>
    Failed,
}

/// <summary>The final state of a <see cref="WinRSReceivePump"/>.</summary>
/// <param name="Reason">Why the pump stopped.</param>
/// <param name="ExitCode">The exit code reported with the Done state, if any.</param>
/// <param name="Error">The fault or exception that stopped the pump, if any.</param>
internal sealed record WinRSReceiveCompletion(WinRSReceiveReason Reason, int? ExitCode, Exception? Error);
