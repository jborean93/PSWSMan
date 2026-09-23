using PSWSMan.Authentication;
using System;
using System.Net.Security;
using System.Threading.Tasks;

namespace PSWSMan.Connection.Tests;

public class WSManConnectionOptionsTests
{
    [Test]
    public async Task Validate_EncryptWithBasic_Rejected()
    {
        WSManConnectionOptions options = new(new Uri("http://localhost:5985/wsman"), new BasicCredential("u", "p"))
        {
            Encrypt = true,
        };

        ArgumentException ex = Assert.Throws<ArgumentException>(() => new WSManHttpConnection(options));

        await Assert.That(ex.Message).Contains("does not support message encryption");
    }

    [Test]
    public async Task Validate_EncryptWithCapableCredential_Accepted()
    {
        FakeNegoCredential credential = new(rounds: 1);
        WSManConnectionOptions options = new(new Uri("http://localhost:5985/wsman"), credential)
        {
            Encrypt = true,
        };

        using WSManHttpConnection connection = new(options);

        // The throwaway context used for validation must not leak.
        await Assert.That(credential.Contexts.Count).IsEqualTo(1);
        await Assert.That(credential.Contexts[0].Disposed).IsTrue();
        await Assert.That(connection.IsBroken).IsFalse();
    }

    [Test]
    public async Task Validate_HttpsWithoutTls_Rejected()
    {
        WSManConnectionOptions options = new(new Uri("https://localhost:5986/wsman"), new FakeNegoCredential(rounds: 1));

        ArgumentException ex = Assert.Throws<ArgumentException>(() => new WSManHttpConnection(options));

        await Assert.That(ex.Message).Contains("TlsOptions must be set");
    }

    [Test]
    public async Task Validate_HttpWithTls_Rejected()
    {
        WSManConnectionOptions options = new(new Uri("http://localhost:5985/wsman"), new FakeNegoCredential(rounds: 1))
        {
            TlsOptions = new SslClientAuthenticationOptions(),
        };

        ArgumentException ex = Assert.Throws<ArgumentException>(() => new WSManHttpConnection(options));

        await Assert.That(ex.Message).Contains("only be set for a https");
    }

    [Test]
    public async Task Validate_MaxConnectionsBelowOne_Rejected()
    {
        WSManConnectionOptions options = new(new Uri("http://localhost:5985/wsman"), new FakeNegoCredential(rounds: 1))
        {
            MaxConnections = 0,
        };

        ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => new WSManConnectionPool(options));

        await Assert.That(ex.ParamName).IsEqualTo("MaxConnections");
    }
}
