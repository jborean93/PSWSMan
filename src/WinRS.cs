using System;
using System.Xml.Linq;

namespace PSWSMan;

internal class WinRSClient
{
    private readonly WSManClient _wsman;
    private SelectorSet? _selectors;

    public Guid ShellId { get; }
    public string ResourceUri { get; }
    public string InputStreams { get; }
    public string OutputStreams { get; }

    public WinRSClient(WSManClient wsman, Guid shellId, string resourceUri, string inputStreams = "stdin",
        string outputStreams = "stdout stderr")
    {
        _wsman = wsman;
        ShellId = shellId;
        ResourceUri = resourceUri;
        InputStreams = inputStreams;
        OutputStreams = outputStreams;
    }

    public T ReceiveData<T>(string data) where T : WSManPayload
    {
        T resp = WSManClient.ParseWSManPayload<T>(data);
        if (resp is WSManCreateResponse createResp)
        {
            _selectors = createResp.Selectors;
        }

        return resp;
    }

    public string Close()
    {
        return _wsman.Delete(ResourceUri, selectors: _selectors);
    }

    public string Create(XElement? extra = null, OptionSet? baseOptions = null)
    {
        XElement shell = new(WSManNamespace.rsp + "Shell",
            new XAttribute("ShellId", ShellId.ToString().ToUpperInvariant()),
            new XElement(WSManNamespace.rsp + "InputStreams", InputStreams),
            new XElement(WSManNamespace.rsp + "OutputStreams", OutputStreams)
        );
        if (extra is not null)
        {
            shell.Add(extra);
        }

        OptionSet options = baseOptions is null ? new OptionSet() : new OptionSet(baseOptions);

        return _wsman.Create(ResourceUri, shell, options: options);
    }
}
