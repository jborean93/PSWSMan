using PSWSMan.Shared;
using PSWSMan.Shared.Authentication;
using PSWSMan.Shared.Authentication.Native;
using RemoteForge;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace WinRSForge;

public sealed class WinRSForge : IRemoteForge
{
    public static string ForgeName => "winrs";
    public static string ForgeDescription => "WinRM/WinRS PowerShell session";

    public Uri ConnectionUri { get; }
    public NetworkCredential? Credential { get; }

    private WinRSForge(
        Uri connectionUri,
        NetworkCredential? credential)
    {
        ConnectionUri = connectionUri;
        Credential = credential;
    }

    public static IRemoteForge Create(string info)
    {
        UriCreationOptions co = new();
        if (Uri.TryCreate(info, co, out Uri? infoUri) && (infoUri.Scheme == "http" || infoUri.Scheme == "https"))
        {
            return new WinRSForge(infoUri, null);
        }
        else if (Uri.TryCreate($"custom://{info}", co, out infoUri) &&
            Uri.CheckHostName(infoUri.DnsSafeHost) != UriHostNameType.Unknown)
        {
            string scheme = infoUri.Port == 443 || infoUri.Port == 5986
                ? "https"
                : "http";
            int port = infoUri.Port == -1
                ? 5985
                : infoUri.Port;
            string path = infoUri.PathAndQuery == "/"
                ? "/wsman"
                : infoUri.AbsolutePath;

            UriBuilder builder = new(scheme, infoUri.DnsSafeHost, port, path)
            {
                Query = infoUri.Query,
            };

            return new WinRSForge(builder.Uri, null);
        }
        else
        {
            throw new ArgumentException($"WinRS connection string '{info}' must be a valid hostname for use in a URI");
        }
    }

    public RemoteTransport CreateTransport()
        => new WinRSTransport(
            ConnectionUri,
            Credential);
}

public sealed class WinRSTransport : RemoteTransport
{
    private readonly Uri _connectionUri;
    private readonly NetworkCredential? _credential;
    private readonly Channel<string> _channel = Channel.CreateUnbounded<string>();
    private WSManSession? _session;
    private WinRSClient? _client;
    private Guid? _cmdId;

    public WinRSTransport(
        Uri connectionUri,
        NetworkCredential? credential)
    {
        _connectionUri = connectionUri;
        _credential = credential;
    }

    protected override async Task Open(CancellationToken cancellationToken)
    {
        _session = CreateSession();
        _client = new(_session.Client);

        string payload = _client.Create(
            "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
            inputStreams: "stdin",
            outputStreams: "stdout stderr");
        WSManCreateResponse resp = await _session.PostRequest<WSManCreateResponse>(
            payload,
            cancellationToken);
        _client.ProcessCreateResponse(resp);

        payload = _client.Command(
            "pwsh.exe",
            new[] { "-NoLogo", "-NoProfile", "-ServerMode" });
        WSManCommandResponse cmdResp = await _session.PostRequest<WSManCommandResponse>(
            payload,
            cancellationToken);
        _cmdId = cmdResp.CommandId;
        Task _ = Task.Run(async () => await ReceiveOutput(_client, cmdResp.CommandId));
    }

    private async Task ReceiveOutput(WinRSClient client, Guid cmdId)
    {
        using WSManSession session = CreateSession();

        string? buffer = null;
        while (true)
        {
            string payload = client.Receive("stdout stderr", commandId: cmdId);
            WSManReceiveResponse resp;
            try
            {
                resp = await session.PostRequest<WSManReceiveResponse>(payload);
            }
            catch (WSManFault e) when (e.WSManFaultCode == unchecked((int)0x80338029))
            {
                // ERROR_WSMAN_OPERATION_TIMEDOUT - try it again
                continue;
            }
            catch (WSManFault e) when (
                e.WSManFaultCode == 0x000003E3 || // ERROR_OPERATION_ABORTED - 0x000003E3
                e.WSManFaultCode == 0x000004C7 || // ERROR_CANCELLED - 0x000004C7
                e.WSManFaultCode == unchecked((int)0x8033805B) || // ERROR_WSMAN_UNEXPECTED_SELECTORS - 0x8033805B
                e.WSManFaultCode == unchecked((int)0x803381C4) || // ERROR_WINRS_SHELL_DISCONNECTED - 0x803381C4
                e.WSManFaultCode == unchecked((int)0x803381DE) // ERROR_WSMAN_SERVICE_STREAM_DISCONNECTED - 0x803381DE
            )
            {
                _channel.Writer.TryComplete();
                break;
            }

            foreach (KeyValuePair<string, byte[][]> entry in resp.Streams)
            {
                StringBuilder sb = new(buffer);
                foreach (byte[] stream in entry.Value)
                {
                    sb.Append(Encoding.UTF8.GetString(stream));
                }

                if (entry.Key == "stderr")
                {
                    throw new Exception(sb.ToString());
                }
                else
                {
                    (buffer, string[] lines) = ParseLines(sb.ToString());
                    foreach (string l in lines)
                    {
                        await _channel.Writer.WriteAsync(l);
                    }
                }
            }
        }
    }

    private static (string?, string[]) ParseLines(string value)
    {
        ReadOnlySpan<char> valueSpan = value.AsSpan();
        ReadOnlySpan<char> newLine = stackalloc char[2] { '\r', '\n' };

        List<string> lines = new();
        while (valueSpan.Length > 0)
        {
            int newlineIdx = valueSpan.IndexOf(newLine);
            if (newlineIdx == -1)
            {
                break;
            }

            lines.Add(valueSpan[..newlineIdx].ToString());
            valueSpan = valueSpan[(newlineIdx + 2)..];
        }

        return (valueSpan.ToString(), lines.ToArray());
    }

    protected override async Task Close(CancellationToken cancellationToken)
    {
        if (_session == null || _client == null)
        {
            return;
        }

        string payload;
        if (_cmdId != null)
        {
            payload = _client.Signal(SignalCode.CtrlC, commandId: _cmdId);
            await _session.PostRequest<WSManSignalResponse>(payload, cancellationToken);
            _cmdId = null;
        }

        payload = _client.Delete();
        await _session.PostRequest<WSManDeleteResponse>(payload, cancellationToken);
    }

    protected override async Task<string?> ReadOutput(CancellationToken cancellationToken)
    {
        try
        {
            return await _channel.Reader.ReadAsync(cancellationToken);
        }
        catch (ChannelClosedException)
        {
            return null;
        }
    }

    protected override async Task WriteInput(string line, CancellationToken cancellationToken)
    {
        Debug.Assert(_session != null);
        Debug.Assert(_client != null);
        Debug.Assert(_cmdId != null);

        string payload = _client.Send(
            "stdin",
            Encoding.UTF8.GetBytes(line + "\r\n"),
            commandId: _cmdId);
        await _session.PostRequest<WSManSendResponse>(payload, cancellationToken);
    }

    private WSManSession CreateSession()
    {
        GssapiProvider gssapi = new(NativeLibrary.Load("libgssapi_krb5.so.2"));
        PSWSMan.Shared.Authentication.GssapiCredential cred = new(
                gssapi,
                _credential?.UserName,
                _credential?.Password,
                NegotiateMethod.Negotiate);
        WSManSessionOption option = new(
            _connectionUri,
            0,
            30,
            "en-US",
            cred)
        {
            NegotiateOptions = new()
            {
                SPNService = "http",
                SPNHostName = _connectionUri.DnsSafeHost,
            },
        };
        WSManConnection connection = new(
            option.ConnectionUri,
            option.Credential,
            option.NegotiateOptions ?? new(),
            option.TlsOptions,
            true,
            null);
        WSManClient client = new(
            option.ConnectionUri,
            option.MaxEnvelopeSize,
            option.OperationTimeout,
            option.Locale,
            dataLocale: option.DataLocale);

        return new(connection, client);
    }

    protected override void Dispose(bool isDisposing)
    {
        if (isDisposing)
        {
            _session?.Dispose();
        }
        base.Dispose(isDisposing);
    }
}
