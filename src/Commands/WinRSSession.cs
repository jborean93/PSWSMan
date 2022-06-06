using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Security.Authentication;
using System.Threading;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.New, "WinRSSession",
    DefaultParameterSetName = "ComputerName"
)]
[OutputType(typeof(WSManSession))]
public class NewWinRSSession : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "ConnectionUri"
    )]
    public Uri[] ConnectionUri { get; set; } = Array.Empty<Uri>();

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "ComputerName"
    )]
    [ValidateNotNullOrEmpty]
    public string[] ComputerName { get; set; } = Array.Empty<string>();

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public int Port { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public SwitchParameter UseSSL { get; set; }

    [Parameter()]
    [ValidateNotNullOrEmpty]
    [Credential]
    public PSCredential? Credential { get; set; }

    [Parameter()]
    public AuthenticationMethod Authentication { get; set; } = AuthenticationMethod.Default;

    [Parameter()]
    public WinRSSessionOption SessionOption { get; set; } = new();

    private CancellationTokenSource? CurrentCancelToken { get; set; }

    protected override void ProcessRecord()
    {
        if (ParameterSetName == "ComputerName")
        {
            List<Uri> uris = new();
            foreach (string computer in ComputerName)
            {
                int port = Port != 0 ? Port : (UseSSL ? 5986 : 5985);
                string scheme = UseSSL ? "https" : "http";
                uris.Add(new Uri($"{scheme}://{computer}:{port}/wsman"));
            }
            ConnectionUri = uris.ToArray();
        }

        foreach (Uri uri in ConnectionUri)
        {
            // Until net7 is the minimum we need to rewrite the URI to connect to the TLS port but specify the http
            // scheme so .NET doesn't try and wrap out connection stream with it's own. When setting net7 as the
            // minimum there is a check that will just not wrap the stream if the connection output is already an
            // SslStream.
            // https://github.com/dotnet/runtime/pull/63851
            bool isTls = uri.Scheme == Uri.UriSchemeHttps;
            UriBuilder uriBuilder = new(uri);
            uriBuilder.Scheme = "http";

            try
            {
                WSManSession session = WSManSessionFactory.Create(
                    uriBuilder.Uri,
                    isTls,
                    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
                    Authentication,
                    Credential,
                    SessionOption);

                string payload = session.WinRS.Create(
                    inputStreams: "stdin",
                    outputStreams: "stdout stderr");

                using (CurrentCancelToken = new())
                {
                    session.PostRequest<WSManCreateResponse>(
                        payload, CurrentCancelToken.Token).GetAwaiter().GetResult();
                }

                WriteObject(session);
            }
            catch (WSManFault e)
            {
                WriteError(new ErrorRecord(e, "WSManFault", ErrorCategory.ProtocolError, null));
            }
            catch (ArgumentException e)
            {
                WriteError(new ErrorRecord(e, "InvalidParameter", ErrorCategory.InvalidArgument, null));
            }
            catch (AuthenticationException e)
            {
                WriteError(new ErrorRecord(e, "AuthError", ErrorCategory.AuthenticationError, null));
            }
        }
    }

    protected override void StopProcessing()
    {
        CurrentCancelToken?.Cancel();
    }
}

[Cmdlet(
    VerbsCommon.Remove, "WinRSSession"
)]
public class RemoveWinRSSession : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    public WSManSession[] Session { get; set; } = Array.Empty<WSManSession>();

    private CancellationTokenSource? CurrentCancelToken { get; set; }

    protected override void ProcessRecord()
    {
        using (CurrentCancelToken = new())
        {
            foreach (WSManSession s in Session)
            {
                string payload = s.WinRS.Close();
                s.PostRequest<WSManDeleteResponse>(payload, CurrentCancelToken.Token).GetAwaiter().GetResult();
            }
        }
    }

    protected override void StopProcessing()
    {
        CurrentCancelToken?.Cancel();
    }
}
