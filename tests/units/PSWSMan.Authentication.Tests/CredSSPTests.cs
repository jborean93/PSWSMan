using PSWSMan.Connection;
using System;
using System.Buffers.Binary;
using System.Security.Authentication;
using System.Text;
using System.Threading.Tasks;

namespace PSWSMan.Authentication.Tests;

/// <summary>The TLS session the acceptor is pinned to, each has a different WinRM trailer calculation.</summary>
public enum CredSSPTls
{
    /// <summary>TLS 1.3, always AEAD with a fixed trailer.</summary>
    Tls13,

    /// <summary>TLS 1.2 with AES-GCM, AEAD with an explicit nonce in the record.</summary>
    Tls12Aead,

    /// <summary>TLS 1.2 with AES-CBC and an HMAC, the trailer is the MAC plus block padding.</summary>
    Tls12Cbc,
}

/// <summary>
/// CredSSP with NTLM underneath against the pyspnego CredSSP acceptor. The acceptor generates its own TLS certificate
/// and, with use_ntlm, runs pyspnego's pure Python NTLM inside the TLS session, so the module's TLS framing,
/// TSRequest handling, public key binding and credential delegation are all checked against independent code. The
/// exchange runs with each provider as the sub authentication, the TLS variants are only exercised through
/// Devolutions as the sub authentication plays no part in the WinRM encryption.
/// </summary>
public class CredSSPTests
{
    private const string Domain = "TESTDOM";
    private const string Username = "testuser";
    private const string Password = "Password01";
    private static readonly AcceptorUser s_user = new(Domain, Username, Password);
    private static readonly string[] s_pureNtlm = ["use_ntlm"];

    // The CredSSP context creates the NTLM context from the sub credential during the exchange, so the sub credential
    // must outlive the CredSSP context. The CredSSP credential itself owns nothing native.
    private static WSManCredential CreateSubCredential(AuthProvider provider, string password = Password)
        => provider.CreateCredential($"{Domain}\\{Username}", password, NegotiateMethod.NTLM,
            new NegotiateOptions { SPNHostName = "acceptor.test" });

    private static CredSSPCredential CreateCredential(WSManCredential subCredential, string password = Password)
        => new(new TSPasswordCreds(Domain, Username, password), subCredential, sslOptions: null);

    [Test]
    [Arguments(TestProviders.Gssapi)]
    [Arguments(TestProviders.Sspi)]
    [Arguments(TestProviders.Devolutions)]
    public async Task Authenticates_AndDelegatesCredentials(string providerName)
    {
        AuthProvider provider = TestProviders.Require(providerName);
        using Acceptor acceptor = Acceptor.Start(s_user);
        acceptor.Create("credssp", s_pureNtlm);
        using WSManCredential subCredential = CreateSubCredential(provider);
        using CredSSPCredential credential = CreateCredential(subCredential);
        using CredSSPAuthContext client = credential.CreateAuthContext(null);

        AuthExchange.Authenticate(client, acceptor);
        AcceptorContextInfo info = acceptor.Query();

        await Assert.That(client.Complete).IsTrue();
        await Assert.That(client.HttpAuthLabel).IsEqualTo("CredSSP");
        await Assert.That(client.EncryptionProtocol).IsEqualTo(WSManEncryptionProtocol.CREDSSP);
        await Assert.That(client.MaxEncryptionChunkSize).IsEqualTo(16384 - 256);
        await Assert.That(info.Complete).IsTrue();
        await Assert.That(info.NegotiatedProtocol).IsEqualTo("ntlm");
        await Assert.That(info.ClientPrincipal).IsEqualTo($"{Domain}\\{Username}");
        await Assert.That(info.DelegatedCredentials).IsEqualTo(
            new AcceptorDelegatedCredentials(Domain, Username, Password));
    }

    [Test]
    [Arguments(TestProviders.Gssapi)]
    [Arguments(TestProviders.Sspi)]
    [Arguments(TestProviders.Devolutions)]
    public async Task WrongPassword_IsRejected(string providerName)
    {
        AuthProvider provider = TestProviders.Require(providerName);
        using Acceptor acceptor = Acceptor.Start(s_user);
        acceptor.Create("credssp", s_pureNtlm);
        using WSManCredential subCredential = CreateSubCredential(provider, password: "WrongPassword");
        using CredSSPCredential credential = CreateCredential(subCredential, password: "WrongPassword");
        using CredSSPAuthContext client = credential.CreateAuthContext(null);

        // CredSSP v6 reports the NTLM failure in a TSRequest errorCode rather than dropping the connection, so the
        // failure surfaces on the client when it reads that response.
        AuthenticationException ex = Assert.Throws<AuthenticationException>(
            () => AuthExchange.Authenticate(client, acceptor));

        await Assert.That(ex.Message).Contains("Received CredSSP TSRequest error");
        await Assert.That(acceptor.Query().Complete).IsFalse();
        await Assert.That(acceptor.Query().DelegatedCredentials).IsNull();
    }

    [Test]
    [Arguments(TestProviders.Gssapi)]
    [Arguments(TestProviders.Sspi)]
    [Arguments(TestProviders.Devolutions)]
    public async Task WinRMEncryption_RoundTripsBothWays(string providerName)
    {
        AuthProvider provider = TestProviders.Require(providerName);
        using Acceptor acceptor = Acceptor.Start(s_user);
        acceptor.Create("credssp", s_pureNtlm);
        using WSManCredential subCredential = CreateSubCredential(provider);
        using CredSSPCredential credential = CreateCredential(subCredential);
        using CredSSPAuthContext client = credential.CreateAuthContext(null);
        AuthExchange.Authenticate(client, acceptor);

        // Interleaved messages in each direction, ending with the largest chunk the context allows.
        int[] sizes = [5, 1000, client.MaxEncryptionChunkSize];
        foreach (int size in sizes)
        {
            byte[] request = Encoding.ASCII.GetBytes(new string('a', size));
            byte[] response = Encoding.ASCII.GetBytes(new string('b', size));

            byte[] acceptorSaw = AuthExchange.ClientToAcceptorWinRM(client, acceptor, request);
            byte[] clientSaw = AuthExchange.AcceptorToClientWinRM(client, acceptor, response);

            await Assert.That(acceptorSaw).IsEquivalentTo(request);
            await Assert.That(clientSaw).IsEquivalentTo(response);
        }
    }

    [Test]
    [Arguments(CredSSPTls.Tls13)]
    [Arguments(CredSSPTls.Tls12Aead)]
    [Arguments(CredSSPTls.Tls12Cbc)]
    public async Task WinRMEncryption_PerTlsSession(CredSSPTls tls)
    {
        // SslStream on macOS goes through SecureTransport where TLS 1.3 support depends on the .NET version.
        Skip.When(tls == CredSSPTls.Tls13 && OperatingSystem.IsMacOS(), "TLS 1.3 is not reliably available on macOS");

        AuthProvider provider = TestProviders.Require(TestProviders.Devolutions);
        using Acceptor acceptor = Acceptor.Start(s_user);
        acceptor.Create("credssp", s_pureNtlm, tls: tls switch
        {
            CredSSPTls.Tls13 => "tls1.3",
            CredSSPTls.Tls12Aead => "tls1.2-aead",
            CredSSPTls.Tls12Cbc => "tls1.2-cbc",
            _ => throw new ArgumentOutOfRangeException(nameof(tls)),
        });
        using WSManCredential subCredential = CreateSubCredential(provider);
        using CredSSPCredential credential = CreateCredential(subCredential);
        using CredSSPAuthContext client = credential.CreateAuthContext(null);
        AuthExchange.Authenticate(client, acceptor);

        // Confirm the acceptor really negotiated the session under test.
        AcceptorContextInfo info = acceptor.Query();
        await Assert.That(info.TlsProtocol).IsEqualTo(tls == CredSSPTls.Tls13 ? "TLSv1.3" : "TLSv1.2");
        if (tls == CredSSPTls.Tls12Aead)
        {
            await Assert.That(info.TlsCipher).Contains("GCM");
        }
        else if (tls == CredSSPTls.Tls12Cbc)
        {
            await Assert.That(info.TlsCipher).DoesNotContain("GCM");
        }

        // What sits between the 5 byte record header and the data. TLS 1.2 AEAD suites carry an 8 byte explicit
        // nonce and CBC suites a 16 byte IV, TLS 1.3 nothing.
        int recordPrefix = tls switch
        {
            CredSSPTls.Tls12Aead => 8,
            CredSSPTls.Tls12Cbc => 16,
            _ => 0,
        };

        // The CBC padding depends on the plaintext length so a few lengths around the block size are tried. The
        // trailer the module reports as the prefix must match both what the record actually carries and the length
        // pyspnego derives from its own cipher suite table, and the data must round trip in both directions.
        int[] sizes = [5, 10, 16, 17, 31, 32, 1000, client.MaxEncryptionChunkSize];
        foreach (int size in sizes)
        {
            byte[] request = Encoding.ASCII.GetBytes(new string('a', size));
            byte[] response = Encoding.ASCII.GetBytes(new string('b', size));

            ReadOnlyMemory<byte> block = client.WrapWinRM(request, out int paddingLength);
            int prefix = BinaryPrimitives.ReadInt32LittleEndian(block.Span);
            int recordTrailer = block.Length - 4 - 5 - recordPrefix - size;
            AcceptorWinRMWrapResult acceptorWrapped = acceptor.WrapWinRM(request);

            // Spelled out so a failure on another platform reports every number needed to reason about it.
            if (prefix != recordTrailer || prefix != acceptorWrapped.Header.Length)
            {
                throw new InvalidOperationException(
                    $"Trailer mismatch for {size} bytes over {info.TlsProtocol} {info.TlsCipher}: module prefix {prefix}, " +
                    $"record implies {recordTrailer} (block {block.Length} bytes), pyspnego {acceptorWrapped.Header.Length}");
            }

            await Assert.That(paddingLength).IsEqualTo(0);
            await Assert.That(prefix).IsEqualTo(recordTrailer);
            await Assert.That(prefix).IsEqualTo(acceptorWrapped.Header.Length);
            await Assert.That(block.Span[4..].IndexOf(request)).IsEqualTo(-1);

            // Each side decrypts the record it was already sent, in order, so the TLS sequence numbers stay aligned
            // before the next message goes the other way.
            byte[] acceptorSaw = acceptor.UnwrapWinRM(block.Span.Slice(4, prefix).ToArray(),
                block.Span[(4 + prefix)..].ToArray());
            byte[] clientSawRequest = client.UnwrapWinRM(BuildBlock(acceptorWrapped)).ToArray();
            byte[] clientSawResponse = AuthExchange.AcceptorToClientWinRM(client, acceptor, response);
            await Assert.That(acceptorSaw).IsEquivalentTo(request);
            await Assert.That(clientSawRequest).IsEquivalentTo(request);
            await Assert.That(clientSawResponse).IsEquivalentTo(response);
        }
    }

    private static byte[] BuildBlock(AcceptorWinRMWrapResult wrapped)
    {
        byte[] block = new byte[4 + wrapped.Header.Length + wrapped.Data.Length];
        BinaryPrimitives.WriteInt32LittleEndian(block, wrapped.Header.Length);
        wrapped.Header.CopyTo(block, 4);
        wrapped.Data.CopyTo(block, 4 + wrapped.Header.Length);
        return block;
    }
}
