using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan;

public class DataReceivedEventArgs : EventArgs
{
    public string Data { get; set; }

    public DataReceivedEventArgs(string data)
    {
        Data = data;
    }
}

public class RawDataReceivedEventArgs : EventArgs
{
    public byte[] Data { get; set; }

    public RawDataReceivedEventArgs(byte[] data)
    {
        Data = data;
    }
}

public sealed class WinRSProcess : IDisposable
{
    private readonly WSManSession _mainSession;
    private Guid _commandId = Guid.Empty;
    private WSManSession? _receiveSession;
    private Task? _receiveTask;

    public Encoding? OutputEncoding { get; }
    public Encoding? InputEncoding { get; }
    public int ExitCode { get; internal set; } = -1;

    public string Executable { get; }
    public string[]? ArgumentList { get; }

    internal WinRSProcess(WSManSession session, string executable, IList<string>? arguments, Encoding? outputEncoding,
        Encoding? inputEncoding)
    {
        _mainSession = session;
        Executable = executable;
        ArgumentList = arguments?.ToArray();
        OutputEncoding = outputEncoding;
        InputEncoding = inputEncoding;
    }

    public event EventHandler? Exited;
    public event EventHandler<DataReceivedEventArgs>? ErrorDataReceived;
    public event EventHandler<RawDataReceivedEventArgs>? RawErrorDataReceived;
    public event EventHandler<DataReceivedEventArgs>? OutputDataReceived;
    public event EventHandler<RawDataReceivedEventArgs>? RawOutputDataReceived;

    public void Kill()
    {
        KillAsync(default).GetAwaiter().GetResult();
    }

    public async Task KillAsync(CancellationToken cancelToken)
    {
        string signalPayload = _mainSession.WinRS.Signal(SignalCode.Terminate, commandId: _commandId);
        await _mainSession.PostRequest<WSManSignalResponse>(signalPayload, cancelToken);
    }

    public void Start()
    {
        StartAsync(default).GetAwaiter().GetResult();
    }

    public async Task StartAsync(CancellationToken cancelToken)
    {
        _receiveSession = _mainSession.Copy();
        string commandPayload = _receiveSession.WinRS.Command(Executable, ArgumentList);
        WSManCommandResponse resp = await _receiveSession.PostRequest<WSManCommandResponse>(
            commandPayload, cancelToken);
        _commandId = resp.CommandId;
        _receiveTask = Task.Run(() => ReceiveProcessor(_receiveSession));
    }

    public void WaitForExit()
    {
        _receiveTask?.GetAwaiter().GetResult();
    }

    public bool WaitForExit(int milliseconds)
    {
        if (_receiveTask is null)
        {
            return true;
        }
        return _receiveTask.Wait(milliseconds);
    }

    public async Task WaitForExitAsync(CancellationToken cancellationToken)
    {
        if (_receiveTask is null)
        {
            return;
        }

        await _receiveTask.WaitAsync(cancellationToken);
    }

    private async Task ReceiveProcessor(WSManSession session)
    {
        while (true)
        {
            string payload = session.WinRS.Receive("stdout stderr", commandId: _commandId);
            WSManReceiveResponse response = await session.PostRequest<WSManReceiveResponse>(payload);

            if (response.Streams.TryGetValue("stdout", out var stdoutEntries))
            {
                foreach (byte[] stdout in stdoutEntries)
                {
                    //string line = Encoding.UTF8.GetString(stdout);
                    //Console.Write(line);
                    if (OutputEncoding is null)
                    {
                        RawOutputDataReceived?.Invoke(this, new RawDataReceivedEventArgs(stdout));
                    }
                    else
                    {
                        OutputDataReceived?.Invoke(this, new DataReceivedEventArgs(OutputEncoding.GetString(stdout)));
                    }
                }
            }
            if (response.Streams.TryGetValue("stderr", out var stderrEntries))
            {
                foreach (byte[] stderr in stderrEntries)
                {
                    if (OutputEncoding is null)
                    {
                        RawErrorDataReceived?.Invoke(this, new RawDataReceivedEventArgs(stderr));
                    }
                    else
                    {
                        ErrorDataReceived?.Invoke(this, new DataReceivedEventArgs(OutputEncoding.GetString(stderr)));
                    }
                }
            }

            if (response.State == CommandState.Done)
            {
                ExitCode = response.ExitCode ?? -1;
                break;
            }
        }

        Exited?.Invoke(this, EventArgs.Empty);
    }

    public void Dispose()
    {
        _receiveSession?.Dispose();
        GC.SuppressFinalize(this);
    }
    ~WinRSProcess() { Dispose(); }
}
