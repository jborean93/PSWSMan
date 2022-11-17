using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using System.Xml.Linq;

namespace PSWSMan;

public class WSManFault : Exception
{
    public string? Code { get; }
    public string? SubCode { get; }
    public string? Reason { get; }
    public string? FaultDetail { get; }
    public int? WSManFaultCode { get; }
    public string? Machine { get; }
    public string? FaultMessage { get; }

    public WSManFault() { }

    public WSManFault(string message) : base(message) { }

    public WSManFault(string message, Exception innerException) :
        base(message, innerException)
    { }

    internal WSManFault(string message, string? code, string? subCode, string? reason, string? faultDetail,
        int? wsmanFaultCode, string? machine, string? faultMessage) : base(message)
    {
        Code = code;
        SubCode = subCode;
        Reason = reason;
        FaultDetail = faultDetail;
        WSManFaultCode = wsmanFaultCode;
        Machine = machine;
        FaultMessage = faultMessage;
    }

    internal static WSManFault FromPayload(XElement payload)
    {
        XElement fault = payload.Elements(WSManNamespace.s + "Body")
            .Elements(WSManNamespace.s + "Fault")
            .First();

        XElement code = fault.Elements(WSManNamespace.s + "Code").First();
        string? codeValue = code.Elements(WSManNamespace.s + "Value").FirstOrDefault()?.Value;
        string? subCode = code.Elements(WSManNamespace.s + "Subcode")
            .Elements(WSManNamespace.s + "Value")
            .FirstOrDefault()?.Value;

        string? reason = fault.Elements(WSManNamespace.s + "Reason")
            .Elements(WSManNamespace.s + "Text")
            .FirstOrDefault()?.Value;

        XElement? detail = fault.Elements(WSManNamespace.s + "Detail").FirstOrDefault();
        string? faultDetail = detail?.Elements(WSManNamespace.wsman + "FaultDetail").FirstOrDefault()?.Value;

        XElement? wsmanFault = detail?.Elements(WSManNamespace.wsmanfault + "WSManFault").FirstOrDefault();
        int? wsmanFaultCode = uint.TryParse(wsmanFault?.Attribute("Code")?.Value, out var tempCode)
            ? (int?)tempCode : null;
        string? machine = wsmanFault?.Attribute("Machine")?.Value;

        // The fault message can either contain just the string or an unknown structure. Try to set the raw string
        // if that's the case otherwise serialize the XML value for the complex scenario.
        XElement? faultMessage = wsmanFault?.Elements(WSManNamespace.wsmanfault + "Message").FirstOrDefault();
        string? faultMsgStr = faultMessage?.HasElements == true ? faultMessage?.ToString() : faultMessage?.Value;

        List<string> msgDetails = new();
        if (!string.IsNullOrWhiteSpace(codeValue))
        {
            msgDetails.Add($"Code: {codeValue.Trim()}");
        }
        if (!string.IsNullOrWhiteSpace(subCode))
        {
            msgDetails.Add($"SubCode: {subCode.Trim()}");
        }
        if (!string.IsNullOrWhiteSpace(reason))
        {
            msgDetails.Add($"Reason: {reason.Trim()}");
        }
        if (!string.IsNullOrEmpty(faultDetail))
        {
            msgDetails.Add($"FaultDetail: {faultDetail.Trim()}");
        }
        if (wsmanFaultCode != null)
        {
            msgDetails.Add(string.Format("WSManFaultCode: 0x{0:X8}", wsmanFaultCode));
        }
        if (!string.IsNullOrWhiteSpace(faultMsgStr))
        {
            msgDetails.Add($"- {faultMsgStr.Trim()}");
        }

        string msg = $"Received a WSManFault: {string.Join(" ", msgDetails)}";

        return new WSManFault(msg, codeValue, subCode, reason, faultDetail, wsmanFaultCode, machine, faultMsgStr);
    }
}

public enum CommandState
{
    Done,
    Pending,
    Running,
}

public enum SignalCode
{
    CtrlC,
    CtrlBreak,
    Terminate,
    PSCtrlC,
}

public enum WSManAction
{
    Get,
    GetResponse,
    Put,
    PutResponse,
    Create,
    CreateResponse,
    Delete,
    DeleteResponse,
    Enumerate,
    EnumerateResponse,
    Fault,
    FaultAddressing,
    Pull,
    PullResponse,
    Command,
    CommandResponse,
    Connect,
    ConnectionResponse,
    Disconnect,
    DisconnectResponse,
    Receive,
    ReceiveResponse,
    Reconnect,
    ReconnectResponse,
    Send,
    SendResponse,
    Signal,
    SignalResponse,
}

internal static class WSManEnumMapper
{
    internal static string WSManValue(this CommandState state) => state switch
    {
        CommandState.Done => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done",
        CommandState.Pending => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Pending",
        CommandState.Running => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running",
        _ => throw new ArgumentOutOfRangeException(nameof(state), $"Unknown CommandState value: {state}"),
    };

    internal static string WSManValue(this SignalCode code) => code switch
    {
        SignalCode.CtrlC => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c",
        SignalCode.CtrlBreak => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_break",
        SignalCode.Terminate => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/Terminate",
        SignalCode.PSCtrlC => "powershell/signal/crtl_c",
        _ => throw new ArgumentOutOfRangeException(nameof(code), $"Unknown SignalCode value: {code}"),
    };

    internal static string WSManValue(this WSManAction action) => action switch
    {
        WSManAction.Get => "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get",
        WSManAction.GetResponse => "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse",
        WSManAction.Put => "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put",
        WSManAction.PutResponse => "http://schemas.xmlsoap.org/ws/2004/09/transfer/PutResponse",
        WSManAction.Create => "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
        WSManAction.CreateResponse => "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse",
        WSManAction.Delete => "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
        WSManAction.DeleteResponse => "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse",
        WSManAction.Enumerate => "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate",
        WSManAction.EnumerateResponse => "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse",
        WSManAction.Fault => "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault",
        WSManAction.FaultAddressing => "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault",
        WSManAction.Pull => "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull",
        WSManAction.PullResponse => "http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse",
        WSManAction.Command => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
        WSManAction.CommandResponse => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse",
        WSManAction.Connect => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Connect",
        WSManAction.ConnectionResponse => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ConnectResponse",
        WSManAction.Disconnect => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Disconnect",
        WSManAction.DisconnectResponse => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/DisconnectResponse",
        WSManAction.Receive => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
        WSManAction.ReceiveResponse => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse",
        WSManAction.Reconnect => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Reconnect",
        WSManAction.ReconnectResponse => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReconnectResponse",
        WSManAction.Send => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send",
        WSManAction.SendResponse => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SendResponse",
        WSManAction.Signal => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal",
        WSManAction.SignalResponse => "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SignalResponse",
        _ => throw new ArgumentOutOfRangeException(nameof(action), $"Unknown WSManAction value: {action}"),
    };
}

internal static class WSManNamespace
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

internal class WSManSet
{
    private readonly XElement _raw;
    private readonly string _valueLabel;

    public WSManSet(string label, string valueLabel, bool mustUnderstand)
    {
        _valueLabel = valueLabel;
        _raw = new(WSManNamespace.wsman + label,
            new XAttribute(WSManNamespace.s + "mustUnderstand", mustUnderstand)
        );
    }

    protected WSManSet(XElement raw, string valueLabel)
    {
        _valueLabel = valueLabel;
        _raw = raw;
    }

    protected WSManSet(WSManSet fromCopy) : this(new(fromCopy._raw), fromCopy._valueLabel)
    { }

    public void Add(string name, object value, Dictionary<string, object>? attributes = null)
    {
        XElement element = new(WSManNamespace.wsman + _valueLabel,
            new XAttribute("Name", name),
            value);
        foreach (KeyValuePair<string, object> attr in attributes ?? new())
        {
            element.Add(new XAttribute(attr.Key, attr.Value));
        }
        _raw.Add(element);
    }

    public static explicit operator XElement(WSManSet set) => set._raw;
}

internal class SelectorSet : WSManSet
{
    public SelectorSet() : base("SelectorSet", "Selector", false)
    { }

    internal SelectorSet(SelectorSet fromCopy) : base(fromCopy)
    { }

    internal SelectorSet(XElement raw) : base(raw, "Selector")
    { }
}

internal class OptionSet : WSManSet
{
    public OptionSet() : base("OptionSet", "Option", true)
    { }

    internal OptionSet(OptionSet fromCopy) : base(fromCopy)
    { }

    internal OptionSet(XElement raw) : base(raw, "Option")
    { }
}

internal class WSManPayload
{
    public string Action { get; }
    public Guid MessageId { get; }

    public WSManPayload(XElement envelope)
    {
        XElement header = envelope.Elements(WSManNamespace.s + "Header").First();

        Action = header.Elements(WSManNamespace.wsa + "Action").First().Value;
        MessageId = new(header.Elements(WSManNamespace.wsa + "MessageID").First().Value[5..]);
    }

    protected void CheckAction(WSManAction expected)
    {
        if (expected.WSManValue() != Action)
        {
            throw new ArgumentException($"Expecting action '{expected.WSManValue()}' but got '{Action}'");
        }
    }
}

internal class WSManResponsePayload : WSManPayload
{
    public Guid RelatesTo { get; }

    public WSManResponsePayload(XElement envelope) : base(envelope)
    {
        XElement header = envelope.Elements(WSManNamespace.s + "Header").First();

        RelatesTo = new(header.Elements(WSManNamespace.wsa + "RelatesTo").First().Value[5..]);
    }
}

internal class WSManCommandResponse : WSManResponsePayload
{
    public Guid CommandId { get; }

    public WSManCommandResponse(XElement envelope) : base(envelope)
    {
        CheckAction(WSManAction.CommandResponse);

        CommandId = new(envelope.Elements(WSManNamespace.s + "Body")
            .Elements(WSManNamespace.rsp + "CommandResponse")
            .Elements(WSManNamespace.rsp + "CommandId")
            .First().Value);
    }
}

internal class WSManCreateResponse : WSManResponsePayload
{
    public SelectorSet Selectors { get; }
    public Guid ShellId { get; }
    public string ResourceUri { get; }
    public string? State { get; }

    public WSManCreateResponse(XElement envelope) : base(envelope)
    {
        CheckAction(WSManAction.CreateResponse);
        XElement body = envelope.Elements(WSManNamespace.s + "Body").First();

        Selectors = new(body.Elements(WSManNamespace.wst + "ResourceCreated")
            .Elements(WSManNamespace.wsa + "ReferenceParameters")
            .Elements(WSManNamespace.wsman + "SelectorSet")
            .First());

        XElement shell = body.Elements(WSManNamespace.rsp + "Shell").First();
        ShellId = new(shell.Elements(WSManNamespace.rsp + "ShellId").First().Value);
        ResourceUri = shell.Elements(WSManNamespace.rsp + "ResourceUri").First().Value;
        State = shell.Elements(WSManNamespace.rsp + "State").FirstOrDefault()?.Value;
    }
}

internal class WSManReceiveResponse : WSManResponsePayload
{
    public CommandState? State { get; }
    public int? ExitCode { get; }
    public Dictionary<string, byte[][]> Streams { get; } = new();

    public WSManReceiveResponse(XElement envelope) : base(envelope)
    {
        CheckAction(WSManAction.ReceiveResponse);

        XElement resp = envelope.Elements(WSManNamespace.s + "Body")
            .Elements(WSManNamespace.rsp + "ReceiveResponse")
            .First();

        Dictionary<string, List<byte[]>> rawStreams = new();
        foreach (XElement stream in resp.Elements(WSManNamespace.rsp + "Stream"))
        {
            string streamName = stream.Attributes("Name").First().Value;
            if (!rawStreams.ContainsKey(streamName))
            {
                rawStreams[streamName] = new();
            }

            rawStreams[streamName].Add(Convert.FromBase64String(stream.Value));
        }

        foreach (KeyValuePair<string, List<byte[]>> kvp in rawStreams)
        {
            Streams[kvp.Key] = kvp.Value.ToArray();
        }

        XElement? commandState = resp.Elements(WSManNamespace.rsp + "CommandState").FirstOrDefault();
        if (commandState is not null)
        {
            string? rawRC = commandState.Elements(WSManNamespace.rsp + "ExitCode").FirstOrDefault()?.Value;
            if (!string.IsNullOrWhiteSpace(rawRC))
            {
                ExitCode = int.Parse(rawRC);
            }

            string state = commandState.Attributes("State").First().Value;
            if (state == CommandState.Done.WSManValue())
            {
                State = CommandState.Done;
            }
            else if (state == CommandState.Pending.WSManValue())
            {
                State = CommandState.Pending;
            }
            else if (state == CommandState.Running.WSManValue())
            {
                State = CommandState.Running;
            }
        }
    }
}

internal class WSManDeleteResponse : WSManResponsePayload
{
    public WSManDeleteResponse(XElement envelope) : base(envelope)
    {
        CheckAction(WSManAction.DeleteResponse);
    }
}

internal class WSManSendResponse : WSManResponsePayload
{
    public WSManSendResponse(XElement envelope) : base(envelope)
    {
        CheckAction(WSManAction.SendResponse);
    }
}

internal class WSManSignalResponse : WSManResponsePayload
{
    public WSManSignalResponse(XElement envelope) : base(envelope)
    {
        CheckAction(WSManAction.SignalResponse);
    }
}

internal class WSManClient
{
    public Guid SessionId { get; }
    public Uri ConnectionUri { get; set; }
    public int MaxEnvelopeSize { get; set; }
    public int OperationTimeout { get; set; }
    public string Locale { get; set; }
    public string DataLocale { get; set; }

    public WSManClient(Uri connectionUri, int maxEnvelopeSize, int operationTimeout, string locale,
        string? dataLocale = null)
    {
        SessionId = Guid.NewGuid();
        ConnectionUri = connectionUri;
        MaxEnvelopeSize = maxEnvelopeSize;
        OperationTimeout = operationTimeout;

        // This value is from pwsh but derived from CultureInfo.CurrentCulture but it may be set to InvariantCulture.
        // Just fallback to en-US as one must be set here.
        Locale = string.IsNullOrWhiteSpace(locale) ? "en-US" : locale;
        DataLocale = string.IsNullOrWhiteSpace(dataLocale) ? Locale : dataLocale;
    }

    public static T ParseWSManPayload<T>(string data) where T : WSManPayload
    {
        XElement envelope;
        try
        {
            envelope = XElement.Parse(data);
        }
        catch (XmlException e)
        {
            // ExchangeOnline can return a helpful error that isn't XML so just display the response.
            throw new WSManFault($"Received non-xml response: {data}", e);
        }

        string action = envelope.Descendants(WSManNamespace.wsa + "Action").First().Value;

        if (action == WSManAction.Fault.WSManValue() || action == WSManAction.FaultAddressing.WSManValue())
        {
            throw WSManFault.FromPayload(envelope);
        }

        WSManPayload payload;
        if (typeof(T) == typeof(WSManPayload))
        {
            payload = new WSManPayload(envelope);
        }
        else if (typeof(T) == typeof(WSManResponsePayload))
        {
            payload = new WSManResponsePayload(envelope);
        }
        else if (typeof(T) == typeof(WSManCommandResponse))
        {
            payload = new WSManCommandResponse(envelope);
        }
        else if (typeof(T) == typeof(WSManCreateResponse))
        {
            payload = new WSManCreateResponse(envelope);
        }
        else if (typeof(T) == typeof(WSManReceiveResponse))
        {
            payload = new WSManReceiveResponse(envelope);
        }
        else if (typeof(T) == typeof(WSManDeleteResponse))
        {
            payload = new WSManDeleteResponse(envelope);
        }
        else if (typeof(T) == typeof(WSManSendResponse))
        {
            payload = new WSManSendResponse(envelope);
        }
        else if (typeof(T) == typeof(WSManSignalResponse))
        {
            payload = new WSManSignalResponse(envelope);
        }
        else
        {
            throw new NotImplementedException($"Cannot unpack {typeof(T)}");
        }

        return (T)payload;
    }

    public string Command(string resourceUri, XElement resource, OptionSet? options = null,
        SelectorSet? selectors = null, int? timeout = null)
    {
        return CreateEnvelope(WSManAction.Command, resourceUri, new[] { resource }, options: options,
            selectors: selectors, timeout: timeout);
    }


    public string Create(string resourceUri, XElement resource, OptionSet? options = null,
        SelectorSet? selectors = null, int? timeout = null)
    {
        return CreateEnvelope(WSManAction.Create, resourceUri, new[] { resource }, options: options,
            selectors: selectors, timeout: timeout);
    }

    public string Delete(string resourceUri, OptionSet? options = null, SelectorSet? selectors = null,
        int? timeout = null)
    {
        return CreateEnvelope(WSManAction.Delete, resourceUri, Array.Empty<object>(), options: options,
            selectors: selectors, timeout: timeout);
    }

    public string Receive(string resourceUri, XElement resource, OptionSet? options = null,
        SelectorSet? selectors = null, int? timeout = null)
    {
        return CreateEnvelope(WSManAction.Receive, resourceUri, new[] { resource }, options: options,
            selectors: selectors, timeout: timeout);
    }

    public string Send(string resourceUri, XElement resource, OptionSet? options = null,
        SelectorSet? selectors = null, int? timeout = null)
    {
        return CreateEnvelope(WSManAction.Send, resourceUri, new[] { resource }, options: options,
            selectors: selectors, timeout: timeout);
    }

    public string Signal(string resourceUri, XElement resource, OptionSet? options = null,
        SelectorSet? selectors = null, int? timeout = null)
    {
        return CreateEnvelope(WSManAction.Signal, resourceUri, new[] { resource }, options: options,
            selectors: selectors, timeout: timeout);
    }

    private string CreateEnvelope(WSManAction action, string resourceUri, object[] body, OptionSet? options,
        SelectorSet? selectors, int? timeout = null)
    {
        XElement envelope = new(WSManNamespace.s + "Envelope",
            new XAttribute(XNamespace.Xmlns + "rsp", WSManNamespace.rsp),
            new XAttribute(XNamespace.Xmlns + "s", WSManNamespace.s),
            new XAttribute(XNamespace.Xmlns + "wsa", WSManNamespace.wsa),
            new XAttribute(XNamespace.Xmlns + "wsman", WSManNamespace.wsman),
            new XAttribute(XNamespace.Xmlns + "wsmv", WSManNamespace.wsmv),
            new XAttribute(XNamespace.Xmlns + "xml", WSManNamespace.xml),
            CreateHeader(action, resourceUri, out var _, options: options, selectors: selectors,
                timeout: timeout),
            new XElement(WSManNamespace.s + "Body", body)
        );

        // FIXME: Do not pretty serialize
        return envelope.ToString();
    }

    private XElement CreateHeader(WSManAction action, string resourceUri, out Guid messageId,
        OptionSet? options = null, SelectorSet? selectors = null, int? timeout = null)
    {
        messageId = Guid.NewGuid();
        string messageIdStr = messageId.ToString().ToUpperInvariant();
        XAttribute mustUnderstandTrue = new(WSManNamespace.s + "mustUnderstand", true);
        XAttribute mustUnderstandFalse = new(WSManNamespace.s + "mustUnderstand", false);

        if (timeout == null)
        {
            timeout = OperationTimeout;
        }

        XElement header = new(WSManNamespace.s + "Header",
            new XElement(WSManNamespace.wsa + "Action",
                mustUnderstandTrue,
                action.WSManValue()),
            new XElement(WSManNamespace.wsmv + "DataLocale",
                mustUnderstandFalse,
                new XAttribute(WSManNamespace.xml + "lang", DataLocale)),
            new XElement(WSManNamespace.wsman + "Locale",
                mustUnderstandFalse,
                new XAttribute(WSManNamespace.xml + "lang", Locale)),
            new XElement(WSManNamespace.wsman + "MaxEnvelopeSize",
                mustUnderstandTrue,
                MaxEnvelopeSize),
            new XElement(WSManNamespace.wsa + "MessageID", $"uuid:{messageIdStr}"),
            new XElement(WSManNamespace.wsman + "OperationTimeout", $"PT{timeout}S"),
            new XElement(WSManNamespace.wsa + "ReplyTo",
                new XElement(WSManNamespace.wsa + "Address",
                    mustUnderstandTrue,
                    "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous")),
            new XElement(WSManNamespace.wsman + "ResourceURI",
                mustUnderstandTrue,
                resourceUri),
            new XElement(WSManNamespace.wsmv + "SessionId",
                mustUnderstandFalse,
                $"uuid:{SessionId.ToString().ToUpperInvariant()}"),
            new XElement(WSManNamespace.wsa + "To", ConnectionUri)
        );

        if (options is not null)
        {
            header.Add((XElement)options);
        }

        if (selectors is not null)
        {
            header.Add((XElement)selectors);
        }

        return header;
    }
}
