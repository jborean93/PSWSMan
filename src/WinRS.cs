using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace PSWSMan;

internal class WinRSClient
{
    private readonly WSManClient _wsman;
    private string _resourceUri = "";
    private SelectorSet? _selectors;

    public WinRSClient(WSManClient wsman)
    {
        _wsman = wsman;
    }

    public T ReceiveData<T>(string data) where T : WSManPayload
    {
        T resp = WSManClient.ParseWSManPayload<T>(data);
        if (resp is WSManCreateResponse createResp)
        {
            _resourceUri = createResp.ResourceUri;
            _selectors = createResp.Selectors;
        }

        return resp;
    }

    public string Close()
    {
        return _wsman.Delete(_resourceUri, selectors: _selectors);
    }

    public string Command(string executable, IList<string>? arguments = null, bool noShell = false,
        Guid? commandId = null)
    {
        OptionSet options = new();
        options.Add("WINRS_SKIP_CMD_SHELL", noShell, new());

        XElement cmd = new(WSManNamespace.rsp + "CommandLine",
            new XElement(WSManNamespace.rsp + "Command", executable));

        if (arguments is not null)
        {
            foreach (string arg in arguments)
            {
                cmd.Add(new XElement(WSManNamespace.rsp + "Arguments", arg));
            }
        }
        if (commandId is not null)
        {
            cmd.SetAttributeValue("CommandId", commandId?.ToString()?.ToUpperInvariant());
        }

        return _wsman.Command(_resourceUri, cmd, options: options, selectors: _selectors);
    }

    public string Create(
        string resourceUri,
        string inputStreams = "stdin",
        string outputStreams = "stdout stderr",
        Guid? shellId = null,
        XElement? extra = null,
        OptionSet? options = null)
    {
        XElement shell = new(WSManNamespace.rsp + "Shell",
            new XElement(WSManNamespace.rsp + "InputStreams", inputStreams),
            new XElement(WSManNamespace.rsp + "OutputStreams", outputStreams)
        );
        if (shellId is not null)
        {
            shell.SetAttributeValue("ShellId", shellId?.ToString()?.ToUpperInvariant());
        }
        if (extra is not null)
        {
            shell.Add(extra);
        }

        return _wsman.Create(resourceUri, shell, options: options);
    }

    public string Receive(string stream, Guid? commandId = null)
    {
        XElement desiredStream = new(WSManNamespace.rsp + "DesiredStream", stream);
        if (commandId is not null)
        {
            desiredStream.SetAttributeValue("CommandId", commandId?.ToString()?.ToUpperInvariant());
        }
        XElement receive = new(WSManNamespace.rsp + "Receive", desiredStream);
        OptionSet options = new();
        options.Add("WSMAN_CMDSHELL_OPTION_KEEPALIVE", true, new());

        return _wsman.Receive(_resourceUri, receive, options: options, selectors: _selectors);
    }

    public string Send(string stream, byte[] data, Guid? commandId = null, bool end = false)
    {
        XElement streamMsg = new(WSManNamespace.rsp + "Stream",
            new XAttribute("Name", stream),
            Convert.ToBase64String(data)
        );
        if (end)
        {
            streamMsg.SetAttributeValue("End", end);
        }
        if (commandId is not null)
        {
            streamMsg.SetAttributeValue("CommandId", commandId?.ToString()?.ToUpperInvariant());
        }

        XElement send = new(WSManNamespace.rsp + "Send", streamMsg);

        return _wsman.Send(_resourceUri, send, selectors: _selectors);
    }

    public string Signal(SignalCode code, Guid? commandId = null)
    {
        XElement signal = new(WSManNamespace.rsp + "Signal",
            new XElement(WSManNamespace.rsp + "Code", code.WSManValue())
        );
        if (commandId is not null)
        {
            signal.SetAttributeValue("CommandId", commandId?.ToString()?.ToUpperInvariant());
        }

        return _wsman.Signal(_resourceUri, signal, selectors: _selectors);
    }
}
