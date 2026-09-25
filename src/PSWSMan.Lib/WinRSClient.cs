using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace PSWSMan.Lib;

/// <summary>Builds WinRS (Windows Remote Shell) messages on top of a <see cref="WSManClient"/>.</summary>
public class WinRSClient
{
    private readonly WSManClient _wsman;

    /// <summary>The resource URI of the shell.</summary>
    public string ResourceUri { get; private set; }

    /// <summary>The selectors that identify the shell, set once the shell exists.</summary>
    public SelectorSet? Selectors { get; private set; }

    /// <summary>Creates a WinRS client for a shell resource.</summary>
    /// <param name="wsman">The WSMan client used to build the envelopes.</param>
    /// <param name="resourceUri">The resource URI of the shell.</param>
    /// <param name="selectors">Optional selectors of an existing shell to target.</param>
    public WinRSClient(WSManClient wsman, string resourceUri, SelectorSet? selectors = null)
    {
        _wsman = wsman;
        ResourceUri = resourceUri;
        Selectors = selectors;
    }

    /// <summary>Creates a Command message to start a new command in the shell.</summary>
    /// <param name="executable">The executable or command to run.</param>
    /// <param name="arguments">Optional arguments for the executable.</param>
    /// <param name="noShell">Skip running the command through cmd.exe.</param>
    /// <param name="commandId">Optional command identifier to use.</param>
    /// <returns>The WSMan request to send.</returns>
    public WSManRequest Command(
        string executable,
        IList<string>? arguments = null,
        bool noShell = false,
        Guid? commandId = null)
    {
        OptionSet options = new();
        options.Add("WINRS_SKIP_CMD_SHELL", noShell.ToString());

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

        return _wsman.CreateRequest(WSManAction.Command, ResourceUri, body: cmd, options: options,
            selectors: Selectors);
    }

    /// <summary>Creates a Create message to open a new shell.</summary>
    /// <param name="inputStreams">Space separated list of input stream names.</param>
    /// <param name="outputStreams">Space separated list of output stream names.</param>
    /// <param name="shellId">Optional shell identifier to use.</param>
    /// <param name="extra">Optional extra element to add to the Shell body.</param>
    /// <param name="options">Optional WSMan options to add to the header.</param>
    /// <returns>The WSMan request to send.</returns>
    public WSManRequest Create(
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

        return _wsman.CreateRequest(WSManAction.Create, ResourceUri, body: shell, options: options);
    }

    /// <summary>Stores the shell details from the Create response for use in subsequent messages.</summary>
    /// <param name="response">The Create response from the server.</param>
    public void ProcessCreateResponse(WSManCreateResponse response)
    {
        ResourceUri = response.ResourceUri;
        Selectors = response.Selectors;
    }

    /// <summary>Creates a Delete message to close the shell.</summary>
    /// <returns>The WSMan request to send.</returns>
    public WSManRequest Delete()
    {
        return _wsman.CreateRequest(WSManAction.Delete, ResourceUri, selectors: Selectors);
    }

    /// <summary>Creates a Receive message to get output from the shell or command.</summary>
    /// <param name="stream">Space separated list of stream names to receive.</param>
    /// <param name="commandId">Optional command identifier to receive the output for.</param>
    /// <returns>The WSMan request to send.</returns>
    public WSManRequest Receive(string stream, Guid? commandId = null)
    {
        XElement desiredStream = new(WSManNamespace.rsp + "DesiredStream", stream);
        if (commandId is not null)
        {
            desiredStream.SetAttributeValue("CommandId", commandId?.ToString()?.ToUpperInvariant());
        }
        XElement receive = new(WSManNamespace.rsp + "Receive", desiredStream);
        OptionSet options = new();
        options.Add("WSMAN_CMDSHELL_OPTION_KEEPALIVE", bool.TrueString);

        return _wsman.CreateRequest(WSManAction.Receive, ResourceUri, body: receive, options: options,
            selectors: Selectors);
    }

    /// <summary>Creates a Send message to send input data to the shell or command.</summary>
    /// <param name="stream">The name of the input stream.</param>
    /// <param name="data">The data to send.</param>
    /// <param name="commandId">Optional command identifier to send the data to.</param>
    /// <param name="end">Marks this as the last input for the stream.</param>
    /// <returns>The WSMan request to send.</returns>
    public WSManRequest Send(string stream, byte[] data, Guid? commandId = null, bool end = false)
    {
        XElement streamMsg = new(WSManNamespace.rsp + "Stream",
            new XAttribute("Name", stream),
            Convert.ToBase64String(data)
        );
        if (end)
        {
            streamMsg.SetAttributeValue("End", bool.TrueString);
        }
        if (commandId is not null)
        {
            streamMsg.SetAttributeValue("CommandId", commandId?.ToString()?.ToUpperInvariant());
        }

        XElement send = new(WSManNamespace.rsp + "Send", streamMsg);

        return _wsman.CreateRequest(WSManAction.Send, ResourceUri, body: send, selectors: Selectors);
    }

    /// <summary>Creates a Signal message to send to the shell or command.</summary>
    /// <param name="code">The signal code URI to send, see <see cref="SignalCode"/> for known values.</param>
    /// <param name="commandId">Optional command identifier to signal.</param>
    /// <returns>The WSMan request to send.</returns>
    public WSManRequest Signal(string code, Guid? commandId = null)
    {
        XElement signal = new(WSManNamespace.rsp + "Signal",
            new XElement(WSManNamespace.rsp + "Code", code)
        );
        if (commandId is not null)
        {
            signal.SetAttributeValue("CommandId", commandId?.ToString()?.ToUpperInvariant());
        }

        return _wsman.CreateRequest(WSManAction.Signal, ResourceUri, body: signal, selectors: Selectors);
    }
}
