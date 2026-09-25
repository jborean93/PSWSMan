using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace PSWSMan.Lib;

/// <summary>An exception representing a fault returned by the WSMan server.</summary>
public class WSManFault : WSManException
{
    /// <summary>The SOAP fault code.</summary>
    public string? Code { get; }

    /// <summary>The SOAP fault subcode.</summary>
    public string? SubCode { get; }

    /// <summary>The SOAP fault reason text.</summary>
    public string? Reason { get; }

    /// <summary>The WSMan fault detail URI.</summary>
    public string? FaultDetail { get; }

    /// <summary>The WSMan error code.</summary>
    public int? WSManFaultCode { get; }

    /// <summary>The machine that reported the fault.</summary>
    public string? Machine { get; }

    /// <summary>The WSMan fault message.</summary>
    public string? FaultMessage { get; }

    /// <summary>Creates a new WSMan fault.</summary>
    public WSManFault() { }

    /// <summary>Creates a new WSMan fault with a message.</summary>
    /// <param name="message">The error message.</param>
    public WSManFault(string message) : base(message) { }

    /// <summary>Creates a new WSMan fault with a message and inner exception.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The exception that caused this fault.</param>
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

    internal static WSManFault FromPayload(XElement body)
    {
        XElement fault = body.Element(WSManNamespace.s + "Fault")
            ?? throw new WSManProtocolException("WSMan fault response is missing the s:Fault element");

        XElement? code = fault.Element(WSManNamespace.s + "Code");
        string? codeValue = code?.Element(WSManNamespace.s + "Value")?.Value;
        string? subCode = code?.Element(WSManNamespace.s + "Subcode")
            ?.Element(WSManNamespace.s + "Value")?.Value;

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
        string? faultMsgStr = null;
        if (faultMessage is not null)
        {
            faultMsgStr = faultMessage.HasElements ? faultMessage.ToString() : faultMessage.Value;
        }

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
