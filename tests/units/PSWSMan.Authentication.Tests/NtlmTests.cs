using PSWSMan.Connection;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace PSWSMan.Authentication.Tests;

/// <summary>
/// NTLM through each provider against the pure Python acceptor in pyspnego. The acceptor is forced to pyspnego's own
/// NTLM implementation with use_ntlm so it is the same independent code on every platform.
/// </summary>
public class NtlmTests
{
    private const string Domain = "TESTDOM";
    private const string Username = "testuser";
    private const string Password = "Password01";
    private static readonly AcceptorUser s_user = new(Domain, Username, Password);
    private static readonly string[] s_pureNtlm = ["use_ntlm"];

    // The context borrows the credential's native handle so the credential must outlive it, each test keeps both
    // in scope with the credential disposed last.
    private static WSManCredential CreateCredential(AuthProvider provider, string password = Password)
        => provider.CreateCredential($"{Domain}\\{Username}", password, NegotiateMethod.NTLM,
            new NegotiateOptions { SPNHostName = "acceptor.test" });

    [Test]
    [Arguments(TestProviders.Gssapi)]
    [Arguments(TestProviders.Sspi)]
    [Arguments(TestProviders.Devolutions)]
    public async Task Authenticates(string providerName)
    {
        AuthProvider provider = TestProviders.Require(providerName);
        using Acceptor acceptor = Acceptor.Start(s_user);
        acceptor.Create("ntlm", s_pureNtlm);
        using WSManCredential credential = CreateCredential(provider);
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(null);

        int rounds = AuthExchange.Authenticate(client, acceptor);
        AcceptorContextInfo info = acceptor.Query();

        // NEGOTIATE then AUTHENTICATE.
        await Assert.That(rounds).IsEqualTo(2);
        await Assert.That(client.Complete).IsTrue();
        await Assert.That(client.HttpAuthLabel).IsEqualTo("Negotiate");
        await Assert.That(((IWSManEncryptionContext)client).EncryptionProtocol)
            .IsEqualTo(WSManEncryptionProtocol.SPNEGO);
        await Assert.That(info.Complete).IsTrue();
        await Assert.That(info.NegotiatedProtocol).IsEqualTo("ntlm");
        await Assert.That(info.ClientPrincipal).IsEqualTo($"{Domain}\\{Username}");
    }

    [Test]
    [Arguments(TestProviders.Gssapi)]
    [Arguments(TestProviders.Sspi)]
    [Arguments(TestProviders.Devolutions)]
    public async Task WrongPassword_IsRejected(string providerName)
    {
        AuthProvider provider = TestProviders.Require(providerName);
        using Acceptor acceptor = Acceptor.Start(s_user);
        acceptor.Create("ntlm", s_pureNtlm);
        using WSManCredential credential = CreateCredential(provider, password: "WrongPassword");
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(null);

        // The initiator cannot tell a bad password apart from a good one in NTLM, the acceptor rejects the
        // AUTHENTICATE message instead.
        AcceptorException ex = Assert.Throws<AcceptorException>(() => AuthExchange.Authenticate(client, acceptor));

        await Assert.That(ex.Type).IsEqualTo("InvalidTokenError");
        await Assert.That(acceptor.Query().Complete).IsFalse();
    }

    [Test]
    [Arguments(TestProviders.Gssapi)]
    [Arguments(TestProviders.Sspi)]
    [Arguments(TestProviders.Devolutions)]
    public async Task WinRMEncryption_RoundTripsBothWays(string providerName)
    {
        AuthProvider provider = TestProviders.Require(providerName);
        using Acceptor acceptor = Acceptor.Start(s_user);
        acceptor.Create("ntlm", s_pureNtlm);
        using WSManCredential credential = CreateCredential(provider);
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(null);
        AuthExchange.Authenticate(client, acceptor);
        IWSManEncryptionContext encryption = (IWSManEncryptionContext)client;

        // Several messages in each direction, interleaved, so the sequence numbers on both sides are exercised.
        for (int i = 0; i < 3; i++)
        {
            byte[] request = Encoding.UTF8.GetBytes($"<request n=\"{i}\">{new string('a', 100 * i)}</request>");
            byte[] response = Encoding.UTF8.GetBytes($"<response n=\"{i}\">{new string('b', 50 * i)}</response>");

            byte[] acceptorSaw = AuthExchange.ClientToAcceptorWinRM(encryption, acceptor, request);
            byte[] clientSaw = AuthExchange.AcceptorToClientWinRM(encryption, acceptor, response);

            await Assert.That(acceptorSaw).IsEquivalentTo(request);
            await Assert.That(clientSaw).IsEquivalentTo(response);
        }
    }

    [Test]
    [Arguments(TestProviders.Gssapi)]
    [Arguments(TestProviders.Sspi)]
    [Arguments(TestProviders.Devolutions)]
    public async Task StreamWrap_RoundTripsBothWays(string providerName)
    {
        AuthProvider provider = TestProviders.Require(providerName);
        using Acceptor acceptor = Acceptor.Start(s_user);
        acceptor.Create("ntlm", s_pureNtlm);
        using WSManCredential credential = CreateCredential(provider);
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(null);
        AuthExchange.Authenticate(client, acceptor);

        // The single stream wrap CredSSP uses to protect its TSRequest payloads.
        for (int i = 0; i < 3; i++)
        {
            byte[] request = Encoding.UTF8.GetBytes($"client message {i}");
            byte[] response = Encoding.UTF8.GetBytes($"acceptor message {i}");

            byte[] acceptorSaw = acceptor.Unwrap(client.Wrap(request));
            byte[] clientSaw = client.Unwrap(acceptor.Wrap(response)).ToArray();

            await Assert.That(acceptorSaw).IsEquivalentTo(request);
            await Assert.That(clientSaw).IsEquivalentTo(response);
        }
    }

    [Test]
    [Arguments(TestProviders.Gssapi)]
    [Arguments(TestProviders.Sspi)]
    [Arguments(TestProviders.Devolutions)]
    public async Task ChannelBindings_MatchingCertificate_Authenticates(string providerName)
    {
        AuthProvider provider = TestProviders.Require(providerName);
        using X509Certificate2 certificate = AuthExchange.CreateCertificate();
        using Acceptor acceptor = Acceptor.Start(s_user);
        acceptor.Create("ntlm", s_pureNtlm, channelBindings: AuthExchange.TlsServerEndPoint(certificate));
        using WSManCredential credential = CreateCredential(provider);
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(certificate);

        AuthExchange.Authenticate(client, acceptor);

        await Assert.That(client.Complete).IsTrue();
        await Assert.That(acceptor.Query().Complete).IsTrue();
    }

    [Test]
    [Arguments(TestProviders.Gssapi)]
    [Arguments(TestProviders.Sspi)]
    [Arguments(TestProviders.Devolutions)]
    public async Task ChannelBindings_DifferentCertificate_IsRejected(string providerName)
    {
        AuthProvider provider = TestProviders.Require(providerName);
        using X509Certificate2 clientCert = AuthExchange.CreateCertificate("CN=client-side");
        using X509Certificate2 acceptorCert = AuthExchange.CreateCertificate("CN=acceptor-side");
        using Acceptor acceptor = Acceptor.Start(s_user);
        acceptor.Create("ntlm", s_pureNtlm, channelBindings: AuthExchange.TlsServerEndPoint(acceptorCert));
        using WSManCredential credential = CreateCredential(provider);
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(clientCert);

        AcceptorException ex = Assert.Throws<AcceptorException>(() => AuthExchange.Authenticate(client, acceptor));

        await Assert.That(ex.Type).IsEqualTo("BadBindingsError");
    }
}
