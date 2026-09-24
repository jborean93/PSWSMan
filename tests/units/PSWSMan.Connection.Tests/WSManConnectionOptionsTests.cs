using PSWSMan.Authentication;
using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Threading;
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

    [Test]
    public async Task Validate_KeepAliveTimeBelowOneSecond_Rejected()
    {
        WSManConnectionOptions options = new(new Uri("http://localhost:5985/wsman"), new FakeNegoCredential(rounds: 1))
        {
            KeepAliveTime = TimeSpan.FromMilliseconds(500),
        };

        ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(() => options.Validate());

        await Assert.That(ex.ParamName).IsEqualTo("KeepAliveTime");
    }

    [Test]
    public async Task Validate_KeepAliveIntervalBelowOneSecond_Rejected()
    {
        WSManConnectionOptions options = new(new Uri("http://localhost:5985/wsman"), new FakeNegoCredential(rounds: 1))
        {
            KeepAliveInterval = TimeSpan.Zero,
        };

        ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(() => options.Validate());

        await Assert.That(ex.ParamName).IsEqualTo("KeepAliveInterval");
    }

    [Test]
    public async Task Validate_KeepAliveRetryCountBelowOne_Rejected()
    {
        WSManConnectionOptions options = new(new Uri("http://localhost:5985/wsman"), new FakeNegoCredential(rounds: 1))
        {
            KeepAliveRetryCount = 0,
        };

        ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(() => options.Validate());

        await Assert.That(ex.ParamName).IsEqualTo("KeepAliveRetryCount");
    }

    [Test]
    public async Task Validate_KeepAliveDisabled_IgnoresOtherKeepAliveSettings()
    {
        WSManConnectionOptions options = new(new Uri("http://localhost:5985/wsman"), new FakeNegoCredential(rounds: 1))
        {
            KeepAliveTime = Timeout.InfiniteTimeSpan,
            KeepAliveInterval = TimeSpan.Zero,
            KeepAliveRetryCount = 0,
        };

        options.Validate();

        await Assert.That(options.KeepAliveTime).IsEqualTo(Timeout.InfiniteTimeSpan);
    }

    [Test]
    public async Task Validate_ClientCertificateWithTlsResume_Rejected()
    {
        using X509Certificate2 cert = CreateSelfSignedCertificate();
        WSManConnectionOptions options = new(new Uri("https://localhost:5986/wsman"), new FakeNegoCredential(rounds: 1))
        {
            TlsOptions = new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                ClientCertificates = new X509CertificateCollection(new X509Certificate[] { cert }),
            },
        };

        ArgumentException ex = Assert.Throws<ArgumentException>(() => options.Validate());

        await Assert.That(ex.Message).Contains("AllowTlsResume must be false");
    }

    [Test]
    public async Task Validate_ClientCertificateWithoutTlsResume_Accepted()
    {
        using X509Certificate2 cert = CreateSelfSignedCertificate();
        WSManConnectionOptions options = new(new Uri("https://localhost:5986/wsman"), new FakeNegoCredential(rounds: 1))
        {
            TlsOptions = new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                ClientCertificates = new X509CertificateCollection(new X509Certificate[] { cert }),
                AllowTlsResume = false,
            },
        };

        options.Validate();

        await Assert.That(options.TlsOptions!.AllowTlsResume).IsFalse();
    }

    private static X509Certificate2 CreateSelfSignedCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new("CN=test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
