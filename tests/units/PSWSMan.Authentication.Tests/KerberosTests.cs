using PSWSMan.Connection;
using System;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace PSWSMan.Authentication.Tests;

/// <summary>How the client is asked for Kerberos, the module's NegotiateMethod is internal.</summary>
public enum KerberosMethod
{
    /// <summary>The Kerberos mechanism on its own.</summary>
    Kerberos,

    /// <summary>SPNEGO, which negotiates Kerberos with the acceptor.</summary>
    Negotiate,
}

/// <summary>
/// Kerberos, and SPNEGO negotiating Kerberos, through each provider against the pyspnego acceptor with the Obol KDC
/// build.ps1 starts for the run, see <see cref="KerberosRealm"/>. On Linux and macOS the acceptor is the system GSSAPI
/// with the keytab KRB5_KTNAME points to. On Windows it is SSPI, which does not read KRB5_KTNAME, so it logs on with
/// the password of the account the SPN belongs to, and the realm is registered with Windows Kerberos machine wide so
/// that process finds the KDC as well. The SPNEGO acceptor is forced to pyspnego's own implementation with
/// use_negotiate so the module's SPNEGO handling is checked against independent code on every platform.
/// </summary>
public class KerberosTests
{
    private static readonly string[] s_pureNegotiate = ["use_negotiate"];

    /// <summary>
    /// Gets the provider or skips the test. Devolutions.Sspi 2026.10.01 encodes the microseconds of its
    /// PA-ENC-TS-ENC and authenticators as a four byte DER INTEGER, with a leading zero the Obol KDC rejects as it is
    /// not minimal (Windows KDCs accept it). Remove the skip once the package encodes them minimally.
    /// </summary>
    private static AuthProvider RequireProvider(string providerName)
    {
        if (providerName == TestProviders.Devolutions)
        {
            Skip.Test("Devolutions.Sspi 2026.10.01 sends a non-minimal DER INTEGER for pausec that the KDC rejects");
        }

        return TestProviders.Require(providerName);
    }

    private static NegotiateMethod ToNegotiateMethod(KerberosMethod method)
        => method == KerberosMethod.Kerberos ? NegotiateMethod.Kerberos : NegotiateMethod.Negotiate;

    private static Acceptor StartAcceptor(KerberosRealm realm, KerberosMethod method, byte[]? channelBindings = null)
    {
        // The acceptor has no NTLM credentials on purpose, a Negotiate client that falls back to NTLM because it
        // could not get a ticket fails here with an NTLM error rather than quietly authenticating another way.
        Acceptor acceptor = Acceptor.Start();
        try
        {
            (string protocol, string[]? options) = method == KerberosMethod.Kerberos
                ? ("kerberos", null)
                : ("negotiate", s_pureNegotiate);

            // The GSSAPI acceptor reads KRB5_KTNAME, SSPI does not and logs on the service account instead.
            bool sspi = OperatingSystem.IsWindows();
            acceptor.Create(protocol, options, hostname: realm.Hostname, service: realm.Service,
                channelBindings: channelBindings,
                username: sspi ? realm.AcceptorUsername : null,
                password: sspi ? realm.AcceptorPassword : null);
            return acceptor;
        }
        catch
        {
            acceptor.Dispose();
            throw;
        }
    }

    // The context borrows the credential's native handle so the credential must outlive it, each test keeps both
    // in scope with the credential disposed last.
    private static WSManCredential CreateCredential(AuthProvider provider, KerberosRealm realm, KerberosMethod method,
        string? password = null, NegotiateRequestFlags flags = NegotiateRequestFlags.Default)
        => provider.CreateCredential(realm.Username, password ?? realm.Password, ToNegotiateMethod(method),
            new NegotiateOptions
            {
                SPNService = realm.Service,
                SPNHostName = realm.Hostname,
                Flags = flags,
            });

    /// <summary>Checks the acceptor authenticated the client with Kerberos rather than an NTLM fallback.</summary>
    private static async Task AssertKerberos(Acceptor acceptor)
    {
        AcceptorContextInfo info = acceptor.Query();
        await Assert.That(info.Complete).IsTrue();
        await Assert.That(info.NegotiatedProtocol).IsEqualTo("kerberos");
    }

    /// <summary>
    /// The forms the acceptor reports the client in: the principal name from GSSAPI, and REALM\user from SSPI as the
    /// ticket has no PAC with a NetBIOS domain name.
    /// </summary>
    private static string[] ClientPrincipalForms(KerberosRealm realm)
        => [realm.Username, $"{realm.Realm}\\{realm.User}"];

    [Test]
    [Arguments(TestProviders.Gssapi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Gssapi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Negotiate)]
    public async Task Authenticates(string providerName, KerberosMethod method)
    {
        KerberosRealm realm = KerberosRealm.Require();
        AuthProvider provider = RequireProvider(providerName);
        using Acceptor acceptor = StartAcceptor(realm, method);
        using WSManCredential credential = CreateCredential(provider, realm, method);
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(null);

        int tokens = AuthExchange.Authenticate(client, acceptor);
        AcceptorContextInfo info = acceptor.Query();

        (string label, string protocol) = method == KerberosMethod.Kerberos
            ? ("Kerberos", WSManEncryptionProtocol.KERBEROS)
            : ("Negotiate", WSManEncryptionProtocol.SPNEGO);

        // The AP-REQ, answered by the AP-REP that mutual authentication asks for. SPNEGO may follow it with a final
        // token carrying the mechListMIC.
        if (method == KerberosMethod.Kerberos)
        {
            await Assert.That(tokens).IsEqualTo(1);
        }
        else
        {
            await Assert.That(tokens).IsLessThanOrEqualTo(2);
        }
        await Assert.That(client.Complete).IsTrue();
        await Assert.That(client.HttpAuthLabel).IsEqualTo(label);
        await Assert.That(((IWSManEncryptionContext)client).EncryptionProtocol).IsEqualTo(protocol);
        await Assert.That(info.Complete).IsTrue();
        await Assert.That(info.NegotiatedProtocol).IsEqualTo("kerberos");
        await Assert.That(ClientPrincipalForms(realm)).Contains(info.ClientPrincipal!);
    }

    [Test]
    [Arguments(TestProviders.Gssapi)]
    [Arguments(TestProviders.Sspi)]
    [Arguments(TestProviders.Devolutions)]
    public async Task WrongPassword_IsRejected(string providerName)
    {
        KerberosRealm realm = KerberosRealm.Require();
        AuthProvider provider = RequireProvider(providerName);

        // The KDC rejects the pre-authentication so the client never produces a token. GSSAPI gets the TGT when the
        // credential is acquired, SSPI and Devolutions on the first step, so both are inside the assertion. Only
        // Kerberos itself is checked, Negotiate is free to fall back to NTLM and produce a token instead.
        AuthenticationException ex = Assert.Throws<AuthenticationException>(() =>
        {
            using WSManCredential credential = CreateCredential(provider, realm, KerberosMethod.Kerberos,
                password: "WrongPassword");
            using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(null);
            client.Step(null);
        });

        await Assert.That(ex).IsNotNull();
    }

    [Test]
    [Arguments(TestProviders.Gssapi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Gssapi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Negotiate)]
    public async Task WinRMEncryption_RoundTripsBothWays(string providerName, KerberosMethod method)
    {
        KerberosRealm realm = KerberosRealm.Require();
        AuthProvider provider = RequireProvider(providerName);
        using Acceptor acceptor = StartAcceptor(realm, method);
        using WSManCredential credential = CreateCredential(provider, realm, method);
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(null);
        AuthExchange.Authenticate(client, acceptor);
        await AssertKerberos(acceptor);
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
    [Arguments(TestProviders.Gssapi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Gssapi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Negotiate)]
    public async Task StreamWrap_RoundTripsBothWays(string providerName, KerberosMethod method)
    {
        KerberosRealm realm = KerberosRealm.Require();
        AuthProvider provider = RequireProvider(providerName);
        using Acceptor acceptor = StartAcceptor(realm, method);
        using WSManCredential credential = CreateCredential(provider, realm, method);
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(null);
        AuthExchange.Authenticate(client, acceptor);
        await AssertKerberos(acceptor);

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
    [Arguments(TestProviders.Gssapi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Gssapi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Negotiate)]
    public async Task ChannelBindings_MatchingCertificate_Authenticates(string providerName, KerberosMethod method)
    {
        KerberosRealm realm = KerberosRealm.Require();
        AuthProvider provider = RequireProvider(providerName);
        using X509Certificate2 certificate = AuthExchange.CreateCertificate();
        using Acceptor acceptor = StartAcceptor(realm, method, AuthExchange.TlsServerEndPoint(certificate));
        using WSManCredential credential = CreateCredential(provider, realm, method);
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(certificate);

        AuthExchange.Authenticate(client, acceptor);

        await Assert.That(client.Complete).IsTrue();
        await AssertKerberos(acceptor);
    }

    [Test]
    [Arguments(TestProviders.Gssapi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Gssapi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Negotiate)]
    public async Task ChannelBindings_DifferentCertificate_IsRejected(string providerName, KerberosMethod method)
    {
        if (OperatingSystem.IsMacOS())
        {
            // python-gssapi uses Apple's Heimdal there, and that acceptor completes the context without an AP-REP
            // instead of failing it with GSS_S_BAD_BINDINGS when the bindings differ. The client then fails for the
            // missing AP-REP, which says nothing about the bindings, so there is no rejection to observe.
            Skip.Test("The Heimdal acceptor on macOS does not report mismatched channel bindings");
        }

        KerberosRealm realm = KerberosRealm.Require();
        AuthProvider provider = RequireProvider(providerName);
        using X509Certificate2 clientCert = AuthExchange.CreateCertificate("CN=client-side");
        using X509Certificate2 acceptorCert = AuthExchange.CreateCertificate("CN=acceptor-side");
        using Acceptor acceptor = StartAcceptor(realm, method, AuthExchange.TlsServerEndPoint(acceptorCert));
        using WSManCredential credential = CreateCredential(provider, realm, method);
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(clientCert);

        // The bindings are in the authenticator checksum of the AP-REQ, the acceptor rejects it on the first token.
        AcceptorException ex = Assert.Throws<AcceptorException>(() => AuthExchange.Authenticate(client, acceptor));

        await Assert.That(ex.Type).IsEqualTo("BadBindingsError");
    }

    [Test]
    [Arguments(TestProviders.Gssapi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Gssapi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Sspi, KerberosMethod.Negotiate)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Kerberos)]
    [Arguments(TestProviders.Devolutions, KerberosMethod.Negotiate)]
    public async Task Delegate_ForwardsTheTicket(string providerName, KerberosMethod method)
    {
        KerberosRealm realm = KerberosRealm.Require();
        AuthProvider provider = RequireProvider(providerName);
        using Acceptor acceptor = StartAcceptor(realm, method);
        using WSManCredential credential = CreateCredential(provider, realm, method,
            flags: NegotiateRequestFlags.Default | NegotiateRequestFlags.Delegate);
        using NegotiateAuthContext client = (NegotiateAuthContext)credential.CreateAuthContext(null);

        AuthExchange.Authenticate(client, acceptor);
        await AssertKerberos(acceptor);

        // pyspnego's ContextReq.delegate, set once the acceptor holds the forwarded TGT from the AP-REQ. The service
        // principal has the OK-AS-DELEGATE flag Windows requires before it forwards one.
        await Assert.That(acceptor.Query().ContextAttr & 1).IsEqualTo(1);
    }
}
