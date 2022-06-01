using System;
using System.Management.Automation;
using System.Xml.Linq;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.New, "WSManPayload"
)]
[OutputType(typeof(string))]
public class NewWSmanPayload : PSCmdlet
{
    protected override void EndProcessing()
    {
        WSManClient wsman = new(new Uri("http://hostname/wsman"), 153600, 20, "en-US");
        WinRSClient winrs = new(wsman, new Guid("3E80F257-2C19-423F-BE49-58DAC431A78C"),
            "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
            inputStreams: "stdin pr", outputStreams: "stdout");

        string createRP = "AAAAAAAAAAEAAAAAAAAAAAMAAADHAgAAAAIAAQBX8oA+GSw/Qr5JWNrEMaeMAAAAAAAAAAAAAAAAAAAAADxPYmogUmVmSWQ9IjAiPjxNUz48VmVyc2lvbiBOPSJQU1ZlcnNpb24iPjIuMDwvVmVyc2lvbj48VmVyc2lvbiBOPSJwcm90b2NvbHZlcnNpb24iPjIuMzwvVmVyc2lvbj48VmVyc2lvbiBOPSJTZXJpYWxpemF0aW9uVmVyc2lvbiI+MS4xLjAuMTwvVmVyc2lvbj48L01TPjwvT2JqPgAAAAAAAAACAAAAAAAAAAADAAADfwIAAAAEAAEAV/KAPhksP0K+SVjaxDGnjAAAAAAAAAAAAAAAAAAAAAA8T2JqIFJlZklkPSIwIj48TVM+PEkzMiBOPSJNaW5SdW5zcGFjZXMiPjE8L0kzMj48STMyIE49Ik1heFJ1bnNwYWNlcyI+MTwvSTMyPjxPYmogUmVmSWQ9IjEiIE49IlBTVGhyZWFkT3B0aW9ucyI+PEkzMj4wPC9JMzI+PFROIFJlZklkPSIwIj48VD5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlJ1bnNwYWNlcy5QU1RocmVhZE9wdGlvbnM8L1Q+PFQ+U3lzdGVtLkVudW08L1Q+PFQ+U3lzdGVtLlZhbHVlVHlwZTwvVD48VD5TeXN0ZW0uT2JqZWN0PC9UPjwvVE4+PFRvU3RyaW5nPkRlZmF1bHQ8L1RvU3RyaW5nPjwvT2JqPjxPYmogUmVmSWQ9IjIiIE49IkFwYXJ0bWVudFN0YXRlIj48STMyPjI8L0kzMj48VE4gUmVmSWQ9IjEiPjxUPlN5c3RlbS5UaHJlYWRpbmcuQXBhcnRtZW50U3RhdGU8L1Q+PFQ+U3lzdGVtLkVudW08L1Q+PFQ+U3lzdGVtLlZhbHVlVHlwZTwvVD48VD5TeXN0ZW0uT2JqZWN0PC9UPjwvVE4+PFRvU3RyaW5nPlVua25vd248L1RvU3RyaW5nPjwvT2JqPjxPYmogUmVmSWQ9IjMiIE49Ikhvc3RJbmZvIj48TVM+PEIgTj0iX2lzSG9zdE51bGwiPnRydWU8L0I+PEIgTj0iX2lzSG9zdFVJTnVsbCI+dHJ1ZTwvQj48QiBOPSJfaXNIb3N0UmF3VUlOdWxsIj50cnVlPC9CPjxCIE49Il91c2VSdW5zcGFjZUhvc3QiPnRydWU8L0I+PC9NUz48L09iaj48T2JqIFJlZklkPSI0IiBOPSJBcHBsaWNhdGlvbkFyZ3VtZW50cyI+PFROIFJlZklkPSIyIj48VD5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlBTUHJpbWl0aXZlRGljdGlvbmFyeTwvVD48VD5TeXN0ZW0uQ29sbGVjdGlvbnMuSGFzaHRhYmxlPC9UPjxUPlN5c3RlbS5PYmplY3Q8L1Q+PC9UTj48RENUIC8+PC9PYmo+PC9NUz48L09iaj4=";
        XElement creationXml = new(WSManNamespace.pwsh + "creationXml", createRP);

        OptionSet psrpOptions = new();
        psrpOptions.Add("protocolversion", "2.3", new(){ {"MustComply", true } });

        WriteObject(winrs.Create(extra: creationXml, baseOptions: psrpOptions));

        string resp = "<s:Envelope xml:lang=\"en-US\" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:x=\"http://schemas.xmlsoap.org/ws/2004/09/transfer\" xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\" xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse</a:Action><a:MessageID>uuid:3BE6820B-6D01-44A3-91EF-D324CDE86EEF</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:BAE399C6-C6D4-41C1-85CF-7B3E43F82C32</a:RelatesTo></s:Header><s:Body><x:ResourceCreated><a:Address>http://server2019.domain.test:5986/wsman</a:Address><a:ReferenceParameters><w:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.PowerShell</w:ResourceURI><w:SelectorSet><w:Selector Name=\"ShellId\">3E80F257-2C19-423F-BE49-58DAC431A78C</w:Selector></w:SelectorSet></a:ReferenceParameters></x:ResourceCreated><rsp:Shell xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\"><rsp:ShellId>3E80F257-2C19-423F-BE49-58DAC431A78C</rsp:ShellId><rsp:ResourceUri>http://schemas.microsoft.com/powershell/Microsoft.PowerShell</rsp:ResourceUri><rsp:Owner>DOMAIN\\vagrant-domain</rsp:Owner><rsp:ClientIP>192.168.56.1</rsp:ClientIP><rsp:ProcessId>3344</rsp:ProcessId><rsp:IdleTimeOut>PT7200.000S</rsp:IdleTimeOut><rsp:InputStreams>stdin pr</rsp:InputStreams><rsp:OutputStreams>stdout</rsp:OutputStreams><rsp:MaxIdleTimeOut>PT2147483.647S</rsp:MaxIdleTimeOut><rsp:Locale>en-US</rsp:Locale><rsp:DataLocale>en-US</rsp:DataLocale><rsp:CompressionMode>NoCompression</rsp:CompressionMode><rsp:ProfileLoaded>Yes</rsp:ProfileLoaded><rsp:Encoding>UTF8</rsp:Encoding><rsp:BufferMode>Block</rsp:BufferMode><rsp:State>Connected</rsp:State><rsp:ShellRunTime>P0DT0H0M0S</rsp:ShellRunTime><rsp:ShellInactivity>P0DT0H0M0S</rsp:ShellInactivity></rsp:Shell></s:Body></s:Envelope>";
        WSManCreateResponse createResp = winrs.ReceiveData<WSManCreateResponse>(resp);
        WriteObject(createResp);
    }
}
