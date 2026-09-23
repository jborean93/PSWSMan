using System.Xml.Linq;

namespace PSWSMan.Lib;

/// <summary>Common XML namespaces used in WSMan messages.</summary>
public static class WSManNamespace
{
    public static readonly XNamespace s = "http://www.w3.org/2003/05/soap-envelope";
    public static readonly XNamespace xs = "http://www.w3.org/2001/XMLSchema";
    public static readonly XNamespace xsi = "http://www.w3.org/2001/XMLSchema-instance";
    public static readonly XNamespace wsa = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
    public static readonly XNamespace wsman = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd";
    public static readonly XNamespace wsmid = "http://schemas.dmtf.org/wbem/wsman/identify/1/wsmanidentity.xsd";
    public static readonly XNamespace wsmanfault = "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault";
    public static readonly XNamespace cim = "http://schemas.dmtf.org/wbem/wscim/1/common";
    public static readonly XNamespace wsmv = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd";
    public static readonly XNamespace cfg = "http://schemas.microsoft.com/wbem/wsman/1/config";
    public static readonly XNamespace sub = "http://schemas.microsoft.com/wbem/wsman/1/subscription";
    public static readonly XNamespace rsp = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";
    public static readonly XNamespace m = "http://schemas.microsoft.com/wbem/wsman/1/machineid";
    public static readonly XNamespace cert = "http://schemas.microsoft.com/wbem/wsman/1/config/service/certmapping";
    public static readonly XNamespace plugin = "http://schemas.microsoft.com/wbem/wsman/1/config/PluginConfiguration";
    public static readonly XNamespace wsen = "http://schemas.xmlsoap.org/ws/2004/09/enumeration";
    public static readonly XNamespace wsdl = "http://schemas.xmlsoap.org/wsdl";
    public static readonly XNamespace wst = "http://schemas.xmlsoap.org/ws/2004/09/transfer";
    public static readonly XNamespace wsp = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    public static readonly XNamespace wse = "http://schemas.xmlsoap.org/ws/2004/08/eventing";
    public static readonly XNamespace i = "http://schemas.microsoft.com/wbem/wsman/1/cim/interactive.xsd";
    public static readonly XNamespace xml = "http://www.w3.org/XML/1998/namespace";
    public static readonly XNamespace pwsh = "http://schemas.microsoft.com/powershell";
}
