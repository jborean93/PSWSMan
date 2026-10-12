using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using PSWSMan.Lib;

namespace PSWSMan.Connection.Tests;

public class WSManFaultRetryTests
{
    private const int KeyDeleted = 0x000003FA;
    private const int WrappedKeyDeleted = unchecked((int)0x800703FA);
    private const int AccessDenied = 0x00000005;

    private static readonly WSManClient s_client = new(new Uri("http://server:5985/wsman"), 153600,
        TimeSpan.FromSeconds(20), "en-US");

    [Test]
    [Arguments(KeyDeleted)]
    [Arguments(WrappedKeyDeleted)]
    public async Task Invoke_RetriesMatchingFaultWithNewRequest(int faultCode)
    {
        WSManFaultRetry rule = new("ERROR_KEY_DELETED", 2, TimeSpan.Zero, KeyDeleted, WrappedKeyDeleted);
        List<Guid> messageIds = new();

        string result = WSManFaultRetry.Invoke(
            "Create",
            new[] { rule },
            CreateRequest,
            request =>
            {
                messageIds.Add(request.MessageId);
                return messageIds.Count < 3 ? throw CreateFault(faultCode) : "done";
            },
            null,
            CancellationToken.None);

        await Assert.That(result).IsEqualTo("done");
        await Assert.That(messageIds.Count).IsEqualTo(3);
        await Assert.That(new HashSet<Guid>(messageIds).Count).IsEqualTo(3);
    }

    [Test]
    public async Task Invoke_ThrowsOnceRetriesAreExhausted()
    {
        WSManFaultRetry rule = new("ERROR_KEY_DELETED", 2, TimeSpan.Zero, KeyDeleted);
        int sent = 0;

        WSManFault ex = Assert.Throws<WSManFault>(() => WSManFaultRetry.Invoke<string>(
            "Create",
            new[] { rule },
            CreateRequest,
            _ =>
            {
                sent++;
                throw CreateFault(KeyDeleted);
            },
            null,
            CancellationToken.None));

        await Assert.That(ex.WSManFaultCode).IsEqualTo(KeyDeleted);
        await Assert.That(sent).IsEqualTo(3);
    }

    [Test]
    public async Task Invoke_DoesNotRetryOtherFaults()
    {
        WSManFaultRetry rule = new("ERROR_KEY_DELETED", 2, TimeSpan.Zero, KeyDeleted);
        int sent = 0;

        WSManFault ex = Assert.Throws<WSManFault>(() => WSManFaultRetry.Invoke<string>(
            "Create",
            new[] { rule },
            CreateRequest,
            _ =>
            {
                sent++;
                throw CreateFault(AccessDenied);
            },
            null,
            CancellationToken.None));

        await Assert.That(ex.WSManFaultCode).IsEqualTo(AccessDenied);
        await Assert.That(sent).IsEqualTo(1);
    }

    [Test]
    public async Task Invoke_AlwaysRetriesWithoutLimit()
    {
        WSManFaultRetry rule = new("ERROR_KEY_DELETED", WSManFaultRetry.Always, TimeSpan.Zero, KeyDeleted);
        int sent = 0;

        string result = WSManFaultRetry.Invoke(
            "Receive",
            new[] { rule },
            CreateRequest,
            _ => ++sent < 100 ? throw CreateFault(KeyDeleted) : "done",
            null,
            CancellationToken.None);

        await Assert.That(result).IsEqualTo("done");
        await Assert.That(sent).IsEqualTo(100);
    }

    [Test]
    public async Task Invoke_CountsEachRuleSeparately()
    {
        WSManFaultRetry first = new("first", 1, TimeSpan.Zero, KeyDeleted);
        WSManFaultRetry second = new("second", 1, TimeSpan.Zero, AccessDenied);
        int[] faults = { KeyDeleted, AccessDenied };
        int sent = 0;

        string result = WSManFaultRetry.Invoke(
            "Create",
            new[] { first, second },
            CreateRequest,
            _ => sent < faults.Length ? throw CreateFault(faults[sent++]) : "done",
            null,
            CancellationToken.None);

        await Assert.That(result).IsEqualTo("done");
    }

    [Test]
    public async Task Invoke_ZeroRetriesThrowsImmediately()
    {
        WSManFaultRetry rule = new("ERROR_KEY_DELETED", 0, TimeSpan.Zero, KeyDeleted);
        int sent = 0;

        Assert.Throws<WSManFault>(() => WSManFaultRetry.Invoke<string>(
            "Create",
            new[] { rule },
            CreateRequest,
            _ =>
            {
                sent++;
                throw CreateFault(KeyDeleted);
            },
            null,
            CancellationToken.None));

        await Assert.That(sent).IsEqualTo(1);
    }

    [Test]
    public async Task Invoke_CancelledDuringDelayThrows()
    {
        WSManFaultRetry rule = new("ERROR_KEY_DELETED", 2, TimeSpan.FromMinutes(5), KeyDeleted);
        using CancellationTokenSource cts = new();
        int sent = 0;

        Assert.Throws<OperationCanceledException>(() => WSManFaultRetry.Invoke<string>(
            "Create",
            new[] { rule },
            CreateRequest,
            _ =>
            {
                sent++;
                cts.CancelAfter(TimeSpan.FromMilliseconds(50));
                throw CreateFault(KeyDeleted);
            },
            null,
            cts.Token));

        await Assert.That(sent).IsEqualTo(1);
    }

    [Test]
    public async Task Invoke_RetriedFaultOnceCancelledThrowsCancelled()
    {
        WSManFaultRetry rule = new("ERROR_KEY_DELETED", 2, TimeSpan.Zero, KeyDeleted);
        using CancellationTokenSource cts = new();
        int sent = 0;

        Assert.Throws<OperationCanceledException>(() => WSManFaultRetry.Invoke<string>(
            "Create",
            new[] { rule },
            CreateRequest,
            _ =>
            {
                sent++;
                cts.Cancel();
                throw CreateFault(KeyDeleted);
            },
            null,
            cts.Token));

        await Assert.That(sent).IsEqualTo(1);
    }

    [Test]
    public async Task Invoke_TracesEachRetry()
    {
        WSManFaultRetry rule = new("ERROR_KEY_DELETED", 2, TimeSpan.Zero, KeyDeleted);
        List<Exception?> traced = new();
        int sent = 0;

        WSManFaultRetry.Invoke(
            "Create",
            new[] { rule },
            CreateRequest,
            _ => ++sent < 3 ? throw CreateFault(KeyDeleted) : "done",
            (_, e) => traced.Add(e),
            CancellationToken.None);

        await Assert.That(traced.Count).IsEqualTo(2);
        foreach (Exception? e in traced)
        {
            await Assert.That(e is WSManFault).IsTrue();
        }
    }

    [Test]
    public async Task Constructor_RejectsInvalidRetries()
    {
        ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => new WSManFaultRetry("test", -2, TimeSpan.Zero, KeyDeleted));

        await Assert.That(ex.ParamName).IsEqualTo("retries");
    }

    [Test]
    public async Task Constructor_RejectsNegativeDelay()
    {
        ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => new WSManFaultRetry("test", 1, TimeSpan.FromSeconds(-1), KeyDeleted));

        await Assert.That(ex.ParamName).IsEqualTo("delay");
    }

    private static WSManRequest CreateRequest()
        => s_client.CreateRequest(WSManAction.Create, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd");

    private static WSManFault CreateFault(int code)
    {
        XElement envelope = new(WSManNamespace.s + "Envelope",
            new XElement(WSManNamespace.s + "Header",
                new XElement(WSManNamespace.wsa + "Action", WSManAction.Fault),
                new XElement(WSManNamespace.wsa + "MessageID", $"uuid:{Guid.NewGuid()}")),
            new XElement(WSManNamespace.s + "Body",
                new XElement(WSManNamespace.s + "Fault",
                    new XElement(WSManNamespace.s + "Code",
                        new XElement(WSManNamespace.s + "Value", "s:Receiver")),
                    new XElement(WSManNamespace.s + "Detail",
                        new XElement(WSManNamespace.wsmanfault + "WSManFault",
                            new XAttribute("Code", unchecked((uint)code)))))));
        byte[] data = Encoding.UTF8.GetBytes(envelope.ToString(SaveOptions.DisableFormatting));

        try
        {
            WSManDeleteResponse.Parse(data);
        }
        catch (WSManFault e)
        {
            return e;
        }

        throw new InvalidOperationException("Expected the fault envelope to raise a WSManFault.");
    }
}
