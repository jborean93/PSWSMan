using System;
using System.Threading;
using System.Xml.Linq;
using PSWSMan.Lib;

namespace PSWSMan.Connection;

/// <summary>The WSMan shell operations the <see cref="OutOfProcWSManTranslator"/> drives.</summary>
/// <remarks>
/// The translator only decides which operation to send and when, this is what sends them. Keeping it behind an
/// interface lets the translator's protocol handling be tested without a server.
/// </remarks>
internal interface IWSManShellOperations : IDisposable
{
    /// <summary>The largest envelope the requests may use.</summary>
    int MaxEnvelopeSize { get; }

    /// <summary>Raises or lowers the largest envelope the requests may use.</summary>
    void UpdateMaxEnvelopeSize(int size);

    /// <summary>Creates the shell, see <see cref="WinRSShell.Open"/>.</summary>
    void Open(string inputStreams, string outputStreams, Guid shellId, XElement extra, OptionSet options);

    /// <summary>Starts a command in the shell with one argument.</summary>
    void RunCommand(Guid commandId, string argument);

    /// <summary>Sends input to the shell or a command.</summary>
    void Send(string stream, byte[] data, Guid? commandId);

    /// <summary>Sends a signal to a command, see <see cref="SignalCode"/>.</summary>
    void Signal(string code, Guid commandId);

    /// <summary>Starts receiving the stdout of the shell or a command into the sink.</summary>
    void StartReceive(IWinRSOutputSink sink, Guid? commandId, CancellationToken cancellationToken);

    /// <summary>Deletes the shell.</summary>
    void Close();
}

/// <summary>Sends the translator's operations to a WinRS shell over a connection pool.</summary>
internal sealed class WSManShellOperations : IWSManShellOperations
{
    private readonly WSManConnectionPool _pool;
    private readonly WSManClient _client;
    private readonly WinRSShell _shell;

    public WSManShellOperations(WSManConnectionPool pool, WSManClient client, string shellUri, int receiveRetries,
        Action<string>? trace)
    {
        _pool = pool;
        _client = client;
        _shell = new WinRSShell(pool, client, shellUri, trace)
        {
            ReceiveRetries = receiveRetries,
        };
    }

    public int MaxEnvelopeSize => _client.MaxEnvelopeSize;

    public void UpdateMaxEnvelopeSize(int size) => _client.UpdateMaxEnvelopeSize(size);

    public void Open(string inputStreams, string outputStreams, Guid shellId, XElement extra, OptionSet options)
        => _shell.Open(inputStreams, outputStreams, shellId, extra, options);

    public void RunCommand(Guid commandId, string argument)
        => _shell.RunCommand("", [argument], commandId: commandId);

    public void Send(string stream, byte[] data, Guid? commandId) => _shell.Send(stream, data, commandId);

    public void Signal(string code, Guid commandId) => _shell.Signal(code, commandId);

    public void StartReceive(IWinRSOutputSink sink, Guid? commandId, CancellationToken cancellationToken)
        => _shell.StartReceive(sink, "stdout", commandId, cancellationToken);

    public void Close() => _shell.Close();

    /// <summary>Aborts the shell if it is still open and closes the connections.</summary>
    public void Dispose()
    {
        try
        {
            _shell.Dispose();
        }
        finally
        {
            _pool.Dispose();
        }
    }
}
