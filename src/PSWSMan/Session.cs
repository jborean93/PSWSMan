using PSWSMan.Authentication;
using PSWSMan.Lib;
using System;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan;

internal sealed class WSManSession : IDisposable
{
    internal WSManConnection Connection { get; }

    internal WSManClient Client { get; }

    public WSManSession(WSManConnection connection, WSManClient client)
    {
        Connection = connection;
        Client = client;
    }

    internal async Task<T> PostRequest<T>(WSManRequest request, CancellationToken cancelToken = default)
        where T : IWSManPayload<T>
    {
        byte[] resp = await Connection.SendMessage(request.Content, cancelToken);
        return T.Parse(resp, request.MessageId);
    }

    public void Dispose()
    {
        Connection?.Dispose();
        GC.SuppressFinalize(this);
    }
    ~WSManSession() { Dispose(); }
}

internal sealed class WSManSessionOption
{
    internal const int DefaultMaxEnvelopeSize = 153600;

    private string? _dataLocale;

    public Uri ConnectionUri { get; set; }

    public int OpenTimeout { get; set; }

    public int OperationTimeout { get; set; }

    public int MaxEnvelopeSize { get; set; } = DefaultMaxEnvelopeSize;

    public string Locale { get; set; }

    public string DataLocale
    {
        get => _dataLocale ?? Locale;
        set => _dataLocale = value;
    }

    public SslClientAuthenticationOptions? TlsOptions { get; set; }

    public bool NoEncryption { get; set; }

    public WSManCredential Credential { get; set; }

    public NegotiateOptions? NegotiateOptions { get; set; }

    public WSManSessionOption(Uri connectionUri, int openTimeout, int operationTimeout, string locale,
        WSManCredential credential)
    {
        OpenTimeout = openTimeout;
        ConnectionUri = connectionUri;
        OperationTimeout = operationTimeout;
        Locale = locale;
        Credential = credential;
    }
}
