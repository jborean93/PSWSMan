using System;
using System.Threading.Tasks;
using PSWSMan.Lib;

namespace PSWSMan.Connection.Tests;

public class WSManTransportExceptionTests
{
    [Test]
    public async Task DefaultConstructor()
    {
        WSManTransportException ex = new();

        await Assert.That(ex).IsAssignableTo<WSManException>();
        await Assert.That(ex.Message).IsNotNull();
        await Assert.That(ex.InnerException).IsNull();
    }

    [Test]
    public async Task WithMessage()
    {
        WSManTransportException ex = new("failure");

        await Assert.That(ex.Message).IsEqualTo("failure");
        await Assert.That(ex.InnerException).IsNull();
    }

    [Test]
    public async Task WithMessageAndInnerException()
    {
        InvalidOperationException inner = new("inner");
        WSManTransportException ex = new("failure", inner);

        await Assert.That(ex.Message).IsEqualTo("failure");
        await Assert.That(ex.InnerException).IsSameReferenceAs(inner);
    }
}
