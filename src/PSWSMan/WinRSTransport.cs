#if NET8_0_OR_GREATER
using PSWSMan.Shared;
using PSWSMan.Shared.Authentication;
using RemoteForge;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan;

public sealed class WinRSForge : IRemoteForge
{
    public static string ForgeName => "winrs";
    public static string ForgeDescription => "WinRM/WinRS PowerShell session";

    public static IRemoteForge Create(string info)
        => new WinRSForge();

    public RemoteTransport CreateTransport()
        => new WinRSTransport();
}

public sealed class WinRSTransport : RemoteTransport
{
    private WSManSession? _session;
    private WinRSClient? _client;
    private Guid? _cmdId;

    public WinRSTransport()
    { }

    protected override async Task Open(CancellationToken cancellationToken)
    {
        WSManSessionOption option = new(
            new Uri("http://server2022.domain.test:5985/wsman"),
            0,
            30,
            "en-US",
            new GssapiCredential(
                GlobalState.Gssapi!,
                "vagrant-domain@DOMAIN.TEST",
                "VagrantPass1",
                NegotiateMethod.Negotiate)
        );
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
        _session = new(connection, client);
        _client = new(client);

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
            payload = _client.Signal(SignalCode.Terminate, commandId: _cmdId);
            await _session.PostRequest<WSManSignalResponse>(payload, cancellationToken);
            _cmdId = null;
        }

        payload = _client.Delete();
        await _session.PostRequest<WSManDeleteResponse>(payload, cancellationToken);
    }

    protected override async Task<string?> ReadOutput(CancellationToken cancellationToken)
    {
        Debug.Assert(_session != null);
        Debug.Assert(_client != null);
        Debug.Assert(_cmdId != null);

        string payload = _client.Receive("stdout stderr", commandId: _cmdId);
        while (true)
        {
            WSManReceiveResponse resp;
            try
            {
                resp = await _session.PostRequest<WSManReceiveResponse>(payload, cancellationToken);
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
                break;
            }

            foreach (KeyValuePair<string, byte[][]> entry in resp.Streams)
            {
                StringBuilder sb = new();
                foreach (byte[] stream in entry.Value)
                {
                    sb.AppendLine(Encoding.UTF8.GetString(stream));
                }

                if (entry.Key == "stderr")
                {
                    throw new Exception(sb.ToString());
                }
                else
                {
                    return sb.ToString();
                }
            }
        }

        return null;
    }

    protected override async Task WriteInput(string line, CancellationToken cancellationToken)
    {
        Debug.Assert(_session != null);
        Debug.Assert(_client != null);
        Debug.Assert(_cmdId != null);

        string payload = _client.Send(
            "stdin",
            Encoding.UTF8.GetBytes(line),
            commandId: _cmdId);
        await _session.PostRequest<WSManSendResponse>(payload, cancellationToken);
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
#endif
