namespace PSWSMan.Lib;

/// <summary>The known WSMan action URIs used in the wsa:Action header.</summary>
public static class WSManAction
{
    /// <summary>WS-Transfer Get.</summary>
    public const string Get = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get";

    /// <summary>WS-Transfer GetResponse.</summary>
    public const string GetResponse = "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse";

    /// <summary>WS-Transfer Put.</summary>
    public const string Put = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put";

    /// <summary>WS-Transfer PutResponse.</summary>
    public const string PutResponse = "http://schemas.xmlsoap.org/ws/2004/09/transfer/PutResponse";

    /// <summary>WS-Transfer Create.</summary>
    public const string Create = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";

    /// <summary>WS-Transfer CreateResponse.</summary>
    public const string CreateResponse = "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse";

    /// <summary>WS-Transfer Delete.</summary>
    public const string Delete = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";

    /// <summary>WS-Transfer DeleteResponse.</summary>
    public const string DeleteResponse = "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse";

    /// <summary>WS-Enumeration Enumerate.</summary>
    public const string Enumerate = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate";

    /// <summary>WS-Enumeration EnumerateResponse.</summary>
    public const string EnumerateResponse = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse";

    /// <summary>WSMan fault.</summary>
    public const string Fault = "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault";

    /// <summary>WS-Addressing fault.</summary>
    public const string FaultAddressing = "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault";

    /// <summary>WS-Enumeration Pull.</summary>
    public const string Pull = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull";

    /// <summary>WS-Enumeration PullResponse.</summary>
    public const string PullResponse = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse";

    /// <summary>WinRS Command.</summary>
    public const string Command = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";

    /// <summary>WinRS CommandResponse.</summary>
    public const string CommandResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse";

    /// <summary>WinRS Connect.</summary>
    public const string Connect = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Connect";

    /// <summary>WinRS ConnectResponse.</summary>
    public const string ConnectResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ConnectResponse";

    /// <summary>WinRS Disconnect.</summary>
    public const string Disconnect = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Disconnect";

    /// <summary>WinRS DisconnectResponse.</summary>
    public const string DisconnectResponse =
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/DisconnectResponse";

    /// <summary>WinRS Receive.</summary>
    public const string Receive = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";

    /// <summary>WinRS ReceiveResponse.</summary>
    public const string ReceiveResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse";

    /// <summary>WinRS Reconnect.</summary>
    public const string Reconnect = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Reconnect";

    /// <summary>WinRS ReconnectResponse.</summary>
    public const string ReconnectResponse =
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReconnectResponse";

    /// <summary>WinRS Send.</summary>
    public const string Send = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send";

    /// <summary>WinRS SendResponse.</summary>
    public const string SendResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SendResponse";

    /// <summary>WinRS Signal.</summary>
    public const string Signal = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";

    /// <summary>WinRS SignalResponse.</summary>
    public const string SignalResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SignalResponse";
}
