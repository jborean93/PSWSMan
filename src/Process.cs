using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan;

public sealed class WinRSProcess : IDisposable
{
    private readonly WSManSession _mainSession;
    private Guid _commandId = Guid.Empty;
    private WSManSession? _receiveSession;
    private Task _receiveTask;
    private int _exitCode = -1;


    public string Executable { get; }
    public string[]? ArgumentList { get; }

    internal WinRSProcess(WSManSession session, string executable, IList<string>? arguments)
    {
        _mainSession = session;
        Executable = executable;
        ArgumentList = arguments?.ToArray();
    }

    public void Start(CancellationToken cancelToken)
    {
        _receiveSession = _mainSession.Copy();
        string commandPayload = _receiveSession.WinRS.Command(Executable, ArgumentList);
        WSManCommandResponse resp = _receiveSession.PostRequest<WSManCommandResponse>(
            commandPayload, cancelToken).GetAwaiter().GetResult();
        _commandId = resp.CommandId;
        _receiveTask = Task.Run(() => ReceiveProcessor(_receiveSession));
    }

    public int WaitForExit()
    {
        _receiveTask.GetAwaiter().GetResult();
        return _exitCode;
    }

    private async void ReceiveProcessor(WSManSession session)
    {
        try
        {
            while (true)
            {
                string payload = session.WinRS.Receive("stdout stderr", commandId: _commandId);
                WSManReceiveResponse response = await session.PostRequest<WSManReceiveResponse>(payload);

                if (response.Streams.TryGetValue("stdout", out var stdoutEntries))
                {
                    foreach (byte[] stdout in stdoutEntries)
                    {
                        Console.WriteLine(Encoding.UTF8.GetString(stdout));
                    }
                }
                if (response.Streams.TryGetValue("stderr", out var stderrEntries))
                {
                    foreach (byte[] stderr in stderrEntries)
                    {
                        Console.Error.WriteLine(Encoding.UTF8.GetString(stderr));
                    }
                }

                if (response.State == CommandState.Done)
                {
                    _exitCode = response.ExitCode ?? -1;
                    break;
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"Unknown failure in receive processor: {e.Message}");
            throw;
        }
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
    ~WinRSProcess() { Dispose(); }
}
