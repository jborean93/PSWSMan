using System;
using System.Threading.Tasks;

namespace PSWSMan.Lib.Tests;

public class WSManExceptionTests
{
    [Test]
    public async Task WSManException_DefaultConstructor()
    {
        WSManException ex = new();

        await Assert.That(ex.Message).IsNotNull();
        await Assert.That(ex.InnerException).IsNull();
    }

    [Test]
    public async Task WSManException_WithMessage()
    {
        WSManException ex = new("failure");

        await Assert.That(ex.Message).IsEqualTo("failure");
        await Assert.That(ex.InnerException).IsNull();
    }

    [Test]
    public async Task WSManException_WithMessageAndInnerException()
    {
        InvalidOperationException inner = new("inner");
        WSManException ex = new("failure", inner);

        await Assert.That(ex.Message).IsEqualTo("failure");
        await Assert.That(ex.InnerException).IsSameReferenceAs(inner);
    }

    [Test]
    public async Task WSManProtocolException_DefaultConstructor()
    {
        WSManProtocolException ex = new();

        await Assert.That(ex).IsAssignableTo<WSManException>();
        await Assert.That(ex.Message).IsNotNull();
        await Assert.That(ex.InnerException).IsNull();
    }

    [Test]
    public async Task WSManProtocolException_WithMessage()
    {
        WSManProtocolException ex = new("failure");

        await Assert.That(ex.Message).IsEqualTo("failure");
        await Assert.That(ex.InnerException).IsNull();
    }

    [Test]
    public async Task WSManProtocolException_WithMessageAndInnerException()
    {
        InvalidOperationException inner = new("inner");
        WSManProtocolException ex = new("failure", inner);

        await Assert.That(ex.Message).IsEqualTo("failure");
        await Assert.That(ex.InnerException).IsSameReferenceAs(inner);
    }
}
