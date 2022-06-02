using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Net.Security;
using System.Text;
using System.Threading;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.New, "WSManSession",
    DefaultParameterSetName = "ComputerName"
)]
//[OutputType(typeof(OpenADSession))]
public class NewWSManSession : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "Uri"
    )]
    public Uri? Uri { get; set; }

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "ComputerName"
    )]
    [ValidateNotNullOrEmpty]
    [Alias("Server")]
    public string ComputerName { get; set; } = "";

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public int Port { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public SwitchParameter UseTLS { get; set; }

    [Parameter()]
    public PSCredential? Credential { get; set; }

    [Parameter()]
    public AuthenticationMethod Authentication { get; set; } = AuthenticationMethod.Default;

    [Parameter()]
    public SwitchParameter SkipCertificateCheck { get; set; }

    [Parameter()]
    public SwitchParameter NoEncryption { get; set; }

    private CancellationTokenSource? CurrentCancelToken { get; set; }

    protected override void ProcessRecord()
    {
        // Until net7 is the minimum we need to rewrite the URI to connect to the TLS port but specify the http scheme
        // so .NET doesn't try and wrap out connection stream with it's own. When setting net7 as the minimum there is
        // a check that will just not wrap the stream if the connection output is already an SslStream.
        // https://github.com/dotnet/runtime/pull/63851
        if (Uri == null)
        {
            int port = Port != 0 ? Port : (UseTLS ? 5986 : 5985);
            Uri = new Uri($"http://{ComputerName}:{port}/wsman");
        }
        else if (Uri.Scheme == Uri.UriSchemeHttps)
        {
            UseTLS = true;
            UriBuilder uriBuilder = new(Uri);
            uriBuilder.Scheme = "http";
            Uri = uriBuilder.Uri;
        }

        // Hardcoded Create message here
        WSManClient wsman = new(Uri, 153600, 20, "en-US");
        WinRSClient winrs = new(wsman, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
            shellId: new Guid("3E80F257-2C19-423F-BE49-58DAC431A78C"),
            inputStreams: "stdin", outputStreams: "stdout stderr");

        // string createRP = "AAAAAAAAAAEAAAAAAAAAAAMAAADHAgAAAAIAAQBX8oA+GSw/Qr5JWNrEMaeMAAAAAAAAAAAAAAAAAAAAADxPYmogUmVmSWQ9IjAiPjxNUz48VmVyc2lvbiBOPSJQU1ZlcnNpb24iPjIuMDwvVmVyc2lvbj48VmVyc2lvbiBOPSJwcm90b2NvbHZlcnNpb24iPjIuMzwvVmVyc2lvbj48VmVyc2lvbiBOPSJTZXJpYWxpemF0aW9uVmVyc2lvbiI+MS4xLjAuMTwvVmVyc2lvbj48L01TPjwvT2JqPgAAAAAAAAACAAAAAAAAAAADAAADfwIAAAAEAAEAV/KAPhksP0K+SVjaxDGnjAAAAAAAAAAAAAAAAAAAAAA8T2JqIFJlZklkPSIwIj48TVM+PEkzMiBOPSJNaW5SdW5zcGFjZXMiPjE8L0kzMj48STMyIE49Ik1heFJ1bnNwYWNlcyI+MTwvSTMyPjxPYmogUmVmSWQ9IjEiIE49IlBTVGhyZWFkT3B0aW9ucyI+PEkzMj4wPC9JMzI+PFROIFJlZklkPSIwIj48VD5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlJ1bnNwYWNlcy5QU1RocmVhZE9wdGlvbnM8L1Q+PFQ+U3lzdGVtLkVudW08L1Q+PFQ+U3lzdGVtLlZhbHVlVHlwZTwvVD48VD5TeXN0ZW0uT2JqZWN0PC9UPjwvVE4+PFRvU3RyaW5nPkRlZmF1bHQ8L1RvU3RyaW5nPjwvT2JqPjxPYmogUmVmSWQ9IjIiIE49IkFwYXJ0bWVudFN0YXRlIj48STMyPjI8L0kzMj48VE4gUmVmSWQ9IjEiPjxUPlN5c3RlbS5UaHJlYWRpbmcuQXBhcnRtZW50U3RhdGU8L1Q+PFQ+U3lzdGVtLkVudW08L1Q+PFQ+U3lzdGVtLlZhbHVlVHlwZTwvVD48VD5TeXN0ZW0uT2JqZWN0PC9UPjwvVE4+PFRvU3RyaW5nPlVua25vd248L1RvU3RyaW5nPjwvT2JqPjxPYmogUmVmSWQ9IjMiIE49Ikhvc3RJbmZvIj48TVM+PEIgTj0iX2lzSG9zdE51bGwiPnRydWU8L0I+PEIgTj0iX2lzSG9zdFVJTnVsbCI+dHJ1ZTwvQj48QiBOPSJfaXNIb3N0UmF3VUlOdWxsIj50cnVlPC9CPjxCIE49Il91c2VSdW5zcGFjZUhvc3QiPnRydWU8L0I+PC9NUz48L09iaj48T2JqIFJlZklkPSI0IiBOPSJBcHBsaWNhdGlvbkFyZ3VtZW50cyI+PFROIFJlZklkPSIyIj48VD5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlBTUHJpbWl0aXZlRGljdGlvbmFyeTwvVD48VD5TeXN0ZW0uQ29sbGVjdGlvbnMuSGFzaHRhYmxlPC9UPjxUPlN5c3RlbS5PYmplY3Q8L1Q+PC9UTj48RENUIC8+PC9PYmo+PC9NUz48L09iaj4=";
        // XElement creationXml = new(WSManNamespace.pwsh + "creationXml", createRP);

        // OptionSet psrpOptions = new();
        // psrpOptions.Add("protocolversion", "2.3", new(){ {"MustComply", true } });

        // string payload = winrs.Create(extra: creationXml, options: psrpOptions);
        string payload = winrs.Create();

        SslClientAuthenticationOptions? sslOptions = null;
        if (UseTLS)
        {
            sslOptions = new()
            {
                TargetHost = Uri.DnsSafeHost,
            };

            if (SkipCertificateCheck)
            {
                sslOptions.RemoteCertificateValidationCallback = (_1, _2, _3, _4) => true;
            }
        }

        if (Authentication == AuthenticationMethod.Default)
        {
            // FIXME: Select based on whether GSSAPI/Negotiate is present
            Authentication = AuthenticationMethod.Negotiate;
        }

        AuthenticationProvider authProvider;
        if (Authentication == AuthenticationMethod.Basic)
        {
            authProvider = new BasicAuthProvider(
                Credential?.UserName,
                Credential?.GetNetworkCredential()?.Password
            );
        }
        else if (Authentication == AuthenticationMethod.Certificate)
        {
            // Need to set the relevant sslOptions for this somehow.
            // request.Headers.Add("Authorization", "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual");
            throw new NotImplementedException(Authentication.ToString());
        }
        else if (Authentication == AuthenticationMethod.CredSSP)
        {
            throw new NotImplementedException(Authentication.ToString());
        }
        else
        {
            authProvider =  new NegotiateAuthProvider(
                Credential?.UserName,
                Credential?.GetNetworkCredential()?.Password,
                "host",
                Uri.DnsSafeHost,
                Authentication,
                Authentication == AuthenticationMethod.Kerberos ? "Kerberos" : "Negotiate",
                !(UseTLS || NoEncryption)
            );
        }

        using (CurrentCancelToken = new CancellationTokenSource())
        {
            using WSManConnection client = new(Uri, authProvider, sslOptions);
            string response = client.SendMessage(payload).GetAwaiter().GetResult();
            WriteObject(winrs.ReceiveData<WSManCreateResponse>(response));

            //payload = winrs.Command("whoami.exe", new[] { "/all" });
            payload = winrs.Command("powershell.exe", new[] { "-Command", "$input" });
            response = client.SendMessage(payload).GetAwaiter().GetResult();
            WSManCommandResponse cmdResponse = winrs.ReceiveData<WSManCommandResponse>(response);
            WriteObject(cmdResponse);

            payload = winrs.Send("stdin", Encoding.UTF8.GetBytes("input data"), commandId: cmdResponse.CommandId,
                end: true);
            response = client.SendMessage(payload).GetAwaiter().GetResult();
            WriteObject(winrs.ReceiveData<WSManSendResponse>(response));

            while (true)
            {
                payload = winrs.Receive("stdout stderr", commandId: cmdResponse.CommandId);
                response = client.SendMessage(payload).GetAwaiter().GetResult();
                WSManReceiveResponse receiveResponse;
                try
                {
                    receiveResponse = winrs.ReceiveData<WSManReceiveResponse>(response);
                }
                catch (WSManFault e)
                {
                    if (e.WSManFaultCode == -2144108503)
                    {
                        // OperationTimeout - retry request
                        continue;
                    }
                    throw;
                }
                WriteObject(receiveResponse);

                foreach (KeyValuePair<string, byte[][]> kvp in receiveResponse.Streams)
                {
                    foreach (byte[] line in kvp.Value)
                    {
                        WriteObject($"{kvp.Key.ToUpperInvariant()} - {Encoding.UTF8.GetString(line)}");
                    }
                }

                if (receiveResponse.State == CommandState.Done)
                {
                    break;
                }
            }

            payload = winrs.Signal(SignalCode.Terminate, cmdResponse.CommandId);
            response = client.SendMessage(payload).GetAwaiter().GetResult();
            WriteObject(winrs.ReceiveData<WSManSignalResponse>(response));

            payload = winrs.Close();
            response = client.SendMessage(payload).GetAwaiter().GetResult();
            WriteObject(winrs.ReceiveData<WSManDeleteResponse>(response));
        }
    }

    protected override void StopProcessing()
    {
        CurrentCancelToken?.Cancel();
    }
}
