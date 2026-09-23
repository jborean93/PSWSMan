using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PSWSMan.Lib.Tests;

public class WinRSClientTests
{
    private static XElement? OptionSet(XElement envelope)
    {
        return envelope.Header().Element(WSManNamespace.wsman + "OptionSet");
    }

    private static string? OptionValue(XElement envelope, string name)
    {
        return OptionSet(envelope)?.Elements(WSManNamespace.wsman + "Option")
            .FirstOrDefault(o => o.Attribute("Name")?.Value == name)?.Value;
    }

    private static string? SelectorValue(XElement envelope, string name)
    {
        return envelope.Header().Element(WSManNamespace.wsman + "SelectorSet")
            ?.Elements(WSManNamespace.wsman + "Selector")
            .FirstOrDefault(o => o.Attribute("Name")?.Value == name)?.Value;
    }

    [Test]
    public async Task Constructor_SetsResourceUriAndSelectors()
    {
        Guid shellId = Guid.NewGuid();
        WinRSClient client = TestHelpers.NewWinRSClient(TestHelpers.NewShellSelectors(shellId));

        await Assert.That(client.ResourceUri).IsEqualTo(TestHelpers.ShellUri);
        await Assert.That(client.Selectors).IsNotNull();
        await Assert.That(TestHelpers.NewWinRSClient().Selectors).IsNull();
    }

    [Test]
    public async Task Create_UsesDefaults()
    {
        WSManRequest request = TestHelpers.NewWinRSClient().Create();
        XElement envelope = TestHelpers.ParseRequest(request);

        await Assert.That(envelope.HeaderValue(WSManNamespace.wsa + "Action")).IsEqualTo(WSManAction.Create);
        await Assert.That(envelope.HeaderValue(WSManNamespace.wsman + "ResourceURI")).IsEqualTo(TestHelpers.ShellUri);
        await Assert.That(OptionSet(envelope)).IsNull();

        XElement shell = envelope.Body().Element(WSManNamespace.rsp + "Shell")!;
        await Assert.That(shell.Attribute("ShellId")).IsNull();
        await Assert.That(shell.Element(WSManNamespace.rsp + "InputStreams")?.Value).IsEqualTo("stdin");
        await Assert.That(shell.Element(WSManNamespace.rsp + "OutputStreams")?.Value).IsEqualTo("stdout stderr");
        await Assert.That(shell.Elements().Count()).IsEqualTo(2);
    }

    [Test]
    public async Task Create_WithShellIdExtraAndOptions()
    {
        // Mirrors how the PSRP shim opens a runspace pool.
        Guid shellId = Guid.Parse("f7c4b4ab-3f2b-4f0d-9b8e-1a2b3c4d5e6f");
        XElement creationXml = new(WSManNamespace.pwsh + "creationXml", "AAAA");
        OptionSet options = new();
        options.Add("protocolversion", "2.3", new() { { "MustComply", "true" } });
        options.Add("WINRS_NOPROFILE", "1", new() { { "MustComply", "true" } });

        WSManRequest request = TestHelpers.NewWinRSClient().Create(
            inputStreams: "stdin pr",
            outputStreams: "stdout",
            shellId: shellId,
            extra: creationXml,
            options: options);
        XElement envelope = TestHelpers.ParseRequest(request);

        XElement shell = envelope.Body().Element(WSManNamespace.rsp + "Shell")!;
        await Assert.That(shell.Attribute("ShellId")?.Value).IsEqualTo("F7C4B4AB-3F2B-4F0D-9B8E-1A2B3C4D5E6F");
        await Assert.That(shell.Element(WSManNamespace.rsp + "InputStreams")?.Value).IsEqualTo("stdin pr");
        await Assert.That(shell.Element(WSManNamespace.rsp + "OutputStreams")?.Value).IsEqualTo("stdout");
        await Assert.That(shell.Element(WSManNamespace.pwsh + "creationXml")?.Value).IsEqualTo("AAAA");
        await Assert.That(shell.Elements().Last().Name).IsEqualTo(WSManNamespace.pwsh + "creationXml");

        await Assert.That(OptionValue(envelope, "protocolversion")).IsEqualTo("2.3");
        await Assert.That(OptionValue(envelope, "WINRS_NOPROFILE")).IsEqualTo("1");
        await Assert.That(OptionSet(envelope)!.Elements().First().Attribute("MustComply")?.Value).IsEqualTo("true");
    }

    [Test]
    public async Task Create_DoesNotIncludeExistingSelectors()
    {
        WinRSClient client = TestHelpers.NewWinRSClient(TestHelpers.NewShellSelectors(Guid.NewGuid()));

        XElement envelope = TestHelpers.ParseRequest(client.Create());

        await Assert.That(envelope.Header().Element(WSManNamespace.wsman + "SelectorSet")).IsNull();
    }

    [Test]
    public async Task ProcessCreateResponse_UpdatesShellDetailsForLaterRequests()
    {
        const string serverResourceUri = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell.Server";
        Guid shellId = Guid.NewGuid();
        WinRSClient client = TestHelpers.NewWinRSClient();
        byte[] response = TestHelpers.Response(WSManAction.CreateResponse, null,
            TestHelpers.CreateResponseBody(shellId, resourceUri: serverResourceUri));

        client.ProcessCreateResponse(WSManCreateResponse.Parse(response));

        await Assert.That(client.ResourceUri).IsEqualTo(serverResourceUri);
        await Assert.That(client.Selectors).IsNotNull();

        XElement envelope = TestHelpers.ParseRequest(client.Delete());
        await Assert.That(envelope.HeaderValue(WSManNamespace.wsman + "ResourceURI")).IsEqualTo(serverResourceUri);
        await Assert.That(SelectorValue(envelope, "ShellId")).IsEqualTo(shellId.ToString().ToUpperInvariant());
    }

    [Test]
    public async Task Command_Defaults()
    {
        Guid shellId = Guid.NewGuid();
        WinRSClient client = TestHelpers.NewWinRSClient(TestHelpers.NewShellSelectors(shellId));

        XElement envelope = TestHelpers.ParseRequest(client.Command("hostname.exe"));

        await Assert.That(envelope.HeaderValue(WSManNamespace.wsa + "Action")).IsEqualTo(WSManAction.Command);
        await Assert.That(OptionValue(envelope, "WINRS_SKIP_CMD_SHELL")).IsEqualTo("False");
        await Assert.That(SelectorValue(envelope, "ShellId")).IsEqualTo(shellId.ToString().ToUpperInvariant());

        XElement commandLine = envelope.Body().Element(WSManNamespace.rsp + "CommandLine")!;
        await Assert.That(commandLine.Attribute("CommandId")).IsNull();
        await Assert.That(commandLine.Element(WSManNamespace.rsp + "Command")?.Value).IsEqualTo("hostname.exe");
        await Assert.That(commandLine.Elements(WSManNamespace.rsp + "Arguments").Count()).IsEqualTo(0);
    }

    [Test]
    public async Task Command_WithArgumentsNoShellAndCommandId()
    {
        Guid commandId = Guid.Parse("0b3f5c2e-8d1a-4c6b-9e7f-2a1b3c4d5e6f");

        XElement envelope = TestHelpers.ParseRequest(TestHelpers.NewWinRSClient().Command(
            "powershell.exe",
            new[] { "-NoProfile", "-Command", "Get-Item 'C:\\Program Files'" },
            noShell: true,
            commandId: commandId));

        await Assert.That(OptionValue(envelope, "WINRS_SKIP_CMD_SHELL")).IsEqualTo("True");

        XElement commandLine = envelope.Body().Element(WSManNamespace.rsp + "CommandLine")!;
        await Assert.That(commandLine.Attribute("CommandId")?.Value).IsEqualTo("0B3F5C2E-8D1A-4C6B-9E7F-2A1B3C4D5E6F");
        await Assert.That(commandLine.Element(WSManNamespace.rsp + "Command")?.Value).IsEqualTo("powershell.exe");

        string[] args = commandLine.Elements(WSManNamespace.rsp + "Arguments").Select(a => a.Value).ToArray();
        await Assert.That(args).IsEquivalentTo(new[] { "-NoProfile", "-Command", "Get-Item 'C:\\Program Files'" });
    }

    [Test]
    public async Task Command_WithEmptyExecutableAndPayloadArgument()
    {
        // The PSRP shim sends the pipeline fragment as the only argument with no executable.
        string payload = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 });

        XElement envelope = TestHelpers.ParseRequest(TestHelpers.NewWinRSClient().Command("", new[] { payload }));
        XElement commandLine = envelope.Body().Element(WSManNamespace.rsp + "CommandLine")!;

        await Assert.That(commandLine.Element(WSManNamespace.rsp + "Command")?.Value).IsEqualTo("");
        await Assert.That(commandLine.Element(WSManNamespace.rsp + "Arguments")?.Value).IsEqualTo(payload);
    }

    [Test]
    public async Task Receive_ForShell()
    {
        XElement envelope = TestHelpers.ParseRequest(TestHelpers.NewWinRSClient().Receive("stdout stderr"));

        await Assert.That(envelope.HeaderValue(WSManNamespace.wsa + "Action")).IsEqualTo(WSManAction.Receive);
        await Assert.That(OptionValue(envelope, "WSMAN_CMDSHELL_OPTION_KEEPALIVE")).IsEqualTo("True");

        XElement desiredStream = envelope.Body()
            .Element(WSManNamespace.rsp + "Receive")!
            .Element(WSManNamespace.rsp + "DesiredStream")!;
        await Assert.That(desiredStream.Value).IsEqualTo("stdout stderr");
        await Assert.That(desiredStream.Attribute("CommandId")).IsNull();
    }

    [Test]
    public async Task Receive_ForCommand()
    {
        Guid commandId = Guid.NewGuid();

        XElement envelope = TestHelpers.ParseRequest(TestHelpers.NewWinRSClient().Receive("stdout", commandId));
        XElement desiredStream = envelope.Body()
            .Element(WSManNamespace.rsp + "Receive")!
            .Element(WSManNamespace.rsp + "DesiredStream")!;

        await Assert.That(desiredStream.Value).IsEqualTo("stdout");
        await Assert.That(desiredStream.Attribute("CommandId")?.Value)
            .IsEqualTo(commandId.ToString().ToUpperInvariant());
    }

    [Test]
    public async Task Send_Defaults()
    {
        byte[] data = Encoding.UTF8.GetBytes("hello world");

        XElement envelope = TestHelpers.ParseRequest(TestHelpers.NewWinRSClient().Send("stdin", data));

        await Assert.That(envelope.HeaderValue(WSManNamespace.wsa + "Action")).IsEqualTo(WSManAction.Send);
        await Assert.That(OptionSet(envelope)).IsNull();

        XElement stream = envelope.Body().Element(WSManNamespace.rsp + "Send")!.Element(WSManNamespace.rsp + "Stream")!;
        await Assert.That(stream.Attribute("Name")?.Value).IsEqualTo("stdin");
        await Assert.That(stream.Attribute("End")).IsNull();
        await Assert.That(stream.Attribute("CommandId")).IsNull();
        await Assert.That(Convert.FromBase64String(stream.Value)).IsEquivalentTo(data);
    }

    [Test]
    public async Task Send_WithEndAndCommandId()
    {
        Guid commandId = Guid.NewGuid();

        XElement envelope = TestHelpers.ParseRequest(TestHelpers.NewWinRSClient().Send("pr", new byte[] { 1 },
            commandId: commandId, end: true));
        XElement stream = envelope.Body().Element(WSManNamespace.rsp + "Send")!.Element(WSManNamespace.rsp + "Stream")!;

        await Assert.That(stream.Attribute("Name")?.Value).IsEqualTo("pr");
        await Assert.That(stream.Attribute("End")?.Value).IsEqualTo("True");
        await Assert.That(stream.Attribute("CommandId")?.Value).IsEqualTo(commandId.ToString().ToUpperInvariant());
        await Assert.That(stream.Value).IsEqualTo("AQ==");
    }

    [Test]
    public async Task Send_EmptyData()
    {
        XElement envelope = TestHelpers.ParseRequest(TestHelpers.NewWinRSClient().Send("stdin", Array.Empty<byte>()));
        XElement stream = envelope.Body().Element(WSManNamespace.rsp + "Send")!.Element(WSManNamespace.rsp + "Stream")!;

        await Assert.That(stream.Value).IsEqualTo("");
    }

    [Test]
    [Arguments(SignalCode.CtrlC)]
    [Arguments(SignalCode.CtrlBreak)]
    [Arguments(SignalCode.Terminate)]
    [Arguments(SignalCode.PSCtrlC)]
    public async Task Signal_WithCommandId(string code)
    {
        Guid commandId = Guid.NewGuid();

        XElement envelope = TestHelpers.ParseRequest(TestHelpers.NewWinRSClient().Signal(code, commandId));

        await Assert.That(envelope.HeaderValue(WSManNamespace.wsa + "Action")).IsEqualTo(WSManAction.Signal);

        XElement signal = envelope.Body().Element(WSManNamespace.rsp + "Signal")!;
        await Assert.That(signal.Attribute("CommandId")?.Value).IsEqualTo(commandId.ToString().ToUpperInvariant());
        await Assert.That(signal.Element(WSManNamespace.rsp + "Code")?.Value).IsEqualTo(code);
    }

    [Test]
    public async Task Signal_WithoutCommandId()
    {
        XElement envelope = TestHelpers.ParseRequest(TestHelpers.NewWinRSClient().Signal(SignalCode.Terminate));
        XElement signal = envelope.Body().Element(WSManNamespace.rsp + "Signal")!;

        await Assert.That(signal.Attribute("CommandId")).IsNull();
        await Assert.That(signal.Element(WSManNamespace.rsp + "Code")?.Value).IsEqualTo(SignalCode.Terminate);
    }

    [Test]
    public async Task Delete_HasEmptyBody()
    {
        XElement envelope = TestHelpers.ParseRequest(TestHelpers.NewWinRSClient().Delete());

        await Assert.That(envelope.HeaderValue(WSManNamespace.wsa + "Action")).IsEqualTo(WSManAction.Delete);
        await Assert.That(envelope.Body().HasElements).IsFalse();
        await Assert.That(OptionSet(envelope)).IsNull();
    }

    [Test]
    public async Task ShellRequests_IncludeSelectorsWhenSet()
    {
        Guid shellId = Guid.NewGuid();
        WinRSClient client = TestHelpers.NewWinRSClient(TestHelpers.NewShellSelectors(shellId));
        WSManRequest[] requests =
        {
            client.Command("cmd.exe"),
            client.Receive("stdout"),
            client.Send("stdin", new byte[] { 1 }),
            client.Signal(SignalCode.CtrlC),
            client.Delete(),
        };

        foreach (WSManRequest request in requests)
        {
            XElement envelope = TestHelpers.ParseRequest(request);
            await Assert.That(SelectorValue(envelope, "ShellId")).IsEqualTo(shellId.ToString().ToUpperInvariant());
        }
    }

    [Test]
    public async Task ShellRequests_OmitSelectorsWhenNotSet()
    {
        WinRSClient client = TestHelpers.NewWinRSClient();
        WSManRequest[] requests =
        {
            client.Command("cmd.exe"),
            client.Receive("stdout"),
            client.Send("stdin", new byte[] { 1 }),
            client.Signal(SignalCode.CtrlC),
            client.Delete(),
        };

        foreach (WSManRequest request in requests)
        {
            XElement envelope = TestHelpers.ParseRequest(request);
            await Assert.That(envelope.Header().Element(WSManNamespace.wsman + "SelectorSet")).IsNull();
        }
    }
}
