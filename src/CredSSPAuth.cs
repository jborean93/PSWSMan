using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan;

/// <summary>Base class used for CredSSP ASN.1 Structures.</summary>
internal abstract class CredSSPStructure
{
    public virtual void ToBytes(AsnWriter writer) => throw new NotImplementedException();
}

/// <summary>TSRequest Payload</summary>
/// <remarks>
/// <para>
/// This is the TSRequest payload structure used in a CredSSP exchange.
/// </para>
/// <para>
/// The ASN.1 structure is defined as
///     TSRequest ::= SEQUENCE {
///             version    [0] INTEGER,
///             negoTokens [1] NegoData  OPTIONAL,
///             authInfo   [2] OCTET STRING OPTIONAL,
///             pubKeyAuth [3] OCTET STRING OPTIONAL,
///             errorCode  [4] INTEGER OPTIONAL,
///             clientNonce [5] OCTET STRING OPTIONAL
///     }
/// </para>
/// </remarks>
/// <see href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685">2.2.1 TSRequest</see>
internal class TSRequest : CredSSPStructure
{
    internal const int CREDSSP_VERSION = 6;

    /// <summary>The highest CredSSP version supported.</summary>
    public int Version { get; set; }

    /// <summary>Contains the negotiate tokens to exchange.</summary>
    public NegoData[]? Tokens { get; set; }

    /// <summary>The credential information to delegate.</summary>
    public byte[]? AuthInfo { get; set; }

    /// <summary>The public key information used to protect against MitM attacks.</summary>
    public byte[]? PubKeyAuth { get; set; }

    /// <summary>Extra error information returned by a server.</summary>
    public int? ErrorCode { get; set;}

    /// <summary>Unique nonce used for pub key auth hashing on newer CredSSP versions.</summary>
    public byte[]? ClientNonce { get; set; }

    public TSRequest(int version = TSRequest.CREDSSP_VERSION, NegoData[]? tokens = null, byte[]? authInfo = null,
        byte[]? pubKeyAuth = null, int? errorCode = null, byte[]? clientNonce = null)
    {
        Version = version;
        Tokens = tokens;
        AuthInfo = authInfo;
        PubKeyAuth = pubKeyAuth;
        ErrorCode = errorCode;
        ClientNonce = clientNonce;
    }

    public override void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence();

        using (AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        {
            writer.WriteInteger(Version);
        }

        if (Tokens?.Length > 0)
        {
            using AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
            using AsnWriter.Scope _3 = writer.PushSequence();
            foreach (NegoData negoData in Tokens)
            {
                negoData.ToBytes(writer);
            }
        }
        if (AuthInfo?.Length > 0)
        {
            using AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true));
            writer.WriteOctetString(AuthInfo);
        }
        if (PubKeyAuth?.Length > 0)
        {
            using AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, true));
            writer.WriteOctetString(PubKeyAuth);
        }
        if (ErrorCode is not null)
        {
            using AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4, true));
            writer.WriteInteger((int)ErrorCode);
        }
        if (ClientNonce?.Length > 0)
        {
            using AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5, true));
            writer.WriteOctetString(ClientNonce);
        }
    }

    public void CheckSuccess()
    {
        if (ErrorCode is not null && ErrorCode != 0)
        {
            throw new Exception(string.Format("Received TSRequest error 0x{0:X8}", ErrorCode));
        }
    }

    public static TSRequest FromBytes(ReadOnlySpan<byte> data, out int bytesConsumed,
        AsnEncodingRules ruleSet = AsnEncodingRules.DER)
    {
        AsnDecoder.ReadSequence(data, ruleSet, out var contentOffset, out var contentLength, out bytesConsumed);
        data = data.Slice(contentOffset, contentLength);

        int version = 0;
        List<NegoData>? tokens = null;
        byte[]? authInfo = null;
        byte[]? pubKeyAuth = null;
        int? errorCode = null;
        byte[]? clientNonce = null;
        while (data.Length > 0)
        {
            Asn1Tag nextTag = Asn1Tag.Decode(data, out var _);
            int consumed;
            switch (nextTag.TagValue)
            {
                case 0:
                    AsnDecoder.ReadSequence(data, ruleSet, out contentOffset, out contentLength, out consumed,
                        nextTag);
                    version = (int)AsnDecoder.ReadInteger(data.Slice(contentOffset, contentLength), ruleSet, out _);
                    break;
                case 1:
                    AsnDecoder.ReadSequence(data, ruleSet, out contentOffset, out contentLength, out consumed,
                        nextTag);

                    ReadOnlySpan<byte> tokenData = data.Slice(contentOffset, contentLength);
                    AsnDecoder.ReadSequence(tokenData, ruleSet, out contentOffset, out contentLength, out _);
                    tokenData = tokenData.Slice(contentOffset, contentLength);

                    tokens = new();
                    while (tokenData.Length > 0)
                    {
                        NegoData negoData = NegoData.FromBytes(tokenData, out var negoConsumed, ruleSet);
                        tokens.Add(negoData);
                        tokenData = tokenData[negoConsumed..];
                    }

                    break;
                case 2:
                    AsnDecoder.ReadSequence(data, ruleSet, out contentOffset, out contentLength, out consumed,
                        nextTag);

                    authInfo = AsnDecoder.ReadOctetString(data.Slice(contentOffset, contentLength), ruleSet, out _);
                    break;
                case 3:
                    AsnDecoder.ReadSequence(data, ruleSet, out contentOffset, out contentLength, out consumed,
                        nextTag);

                    pubKeyAuth = AsnDecoder.ReadOctetString(data.Slice(contentOffset, contentLength), ruleSet, out _);
                    break;
                case 4:
                    AsnDecoder.ReadSequence(data, ruleSet, out contentOffset, out contentLength, out consumed,
                        nextTag);

                    errorCode = (int)AsnDecoder.ReadInteger(data.Slice(contentOffset, contentLength), ruleSet, out _);
                    break;
                case 5:
                    AsnDecoder.ReadSequence(data, ruleSet, out contentOffset, out contentLength, out consumed,
                        nextTag);

                    clientNonce = AsnDecoder.ReadOctetString(data.Slice(contentOffset, contentLength), ruleSet, out _);
                    break;
                default:
                    AsnDecoder.ReadEncodedValue(data, ruleSet, out contentOffset, out contentLength, out consumed);
                    break;
            }

            data = data[consumed..];
        }

        return new TSRequest(version: version, tokens: tokens?.ToArray(), authInfo: authInfo, pubKeyAuth: pubKeyAuth,
            errorCode: errorCode, clientNonce: clientNonce);
    }
}

/// <summary>NegoData Payload</summary>
/// <remarks>
/// <para>
/// This is the NegoData payload structure used in a CredSSP exchange.
/// </para>
/// <para>
/// The ASN.1 structure is defined as
///     NegoData ::= SEQUENCE OF SEQUENCE {
///             negoToken [0] OCTET STRING
///     }
/// </para>
/// </remarks>
/// <see href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/9664994d-0784-4659-b85b-83b8d54c2336">2.2.1.1 NegoData</see>
internal class NegoData : CredSSPStructure
{
    /// <summary>The authentication token to exchange.</summary>
    public byte[] Token { get; set; }

    public NegoData(byte[] token)
    {
        Token = token;
    }

    public override void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence();

        using AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        writer.WriteOctetString(Token);
    }

    public static NegoData FromBytes(ReadOnlySpan<byte> data, out int bytesConsumed,
        AsnEncodingRules ruleSet = AsnEncodingRules.DER)
    {
        AsnDecoder.ReadSequence(data, ruleSet, out var contentOffset, out var contentLength, out bytesConsumed);
        data = data.Slice(contentOffset, contentLength);

        AsnDecoder.ReadSequence(data, ruleSet, out contentOffset, out contentLength, out var _,
            new Asn1Tag(TagClass.ContextSpecific, 0, true));
        byte[] token = AsnDecoder.ReadOctetString(data.Slice(contentOffset, contentLength), ruleSet, out _);

        return new NegoData(token);
    }
}

/// <summary>TSCredentials Payload</summary>
/// <remarks>
/// <para>
/// This is the TSCredentials payload structure used in a CredSSP exchange. Currently only TSPasswordCredentials is
/// used.
/// </para>
/// <para>
/// The ASN.1 structure is defined as
///     TSCredentials ::= SEQUENCE {
///             credType    [0] INTEGER,
///             credentials [1] OCTET STRING
///     }
/// </para>
/// </remarks>
/// <see href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/94a1ab00-5500-42fd-8d3d-7a84e6c2cf03">2.2.1.2 TSCredentials</see>
internal class TSCredentials : CredSSPStructure
{
    /// <summary>The credential type.</summary>
    public int CredType { get; set; }

    /// <summary>The password credentials to delegate.</summary>
    public byte[] Credentials { get; set; }

    public TSCredentials(int credType, byte[] credentials)
    {
        CredType = credType;
        Credentials = credentials;
    }

    public override void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence();

        using (AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        {
            writer.WriteInteger(CredType);
        }

        using (AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
        {
            writer.WriteOctetString(Credentials);
        }
    }
}

/// <summary>Base class for CredSSP credential buffers.</summary>
internal abstract class TSCredentialBase : CredSSPStructure
{
    public abstract int CredType { get; }
}

/// <summary>TSPassword Credential Payload</summary>
/// <remarks>
/// <para>
/// This is the TSPasswordCreds structurs used in a CredSSP exchange.
/// </para>
/// <para>
/// The ASN.1 structure is defined as
///     TSPasswordCreds ::= SEQUENCE {
///             domainName  [0] OCTET STRING,
///             userName    [1] OCTET STRING,
///             password    [2] OCTET STRING
///     }
/// </para>
/// </remarks>
/// <see href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/17773cc4-21e9-4a75-a0dd-72706b174fe5">2.2.1.2.1 TSPasswordCreds</see>
internal class TSPasswordCreds : TSCredentialBase
{
    public override int CredType => 1;

    /// <summary>The domain name part of the account.</summary>
    public string DomainName { get; set; }

    /// <summary>The username part of the account.</summary>
    public string UserName { get; set; }

    /// <summary>The password for the account.</summary>
    public string Password { get; set; }

    public TSPasswordCreds(string domainName, string userName, string password)
    {
        DomainName = domainName;
        UserName = userName;
        Password = password;
    }

    public override void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence();

        using (AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        {
            writer.WriteOctetString(Encoding.Unicode.GetBytes(DomainName));
        }

        using (AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
        {
            writer.WriteOctetString(Encoding.Unicode.GetBytes(UserName));
        }

        using (AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)))
        {
            writer.WriteOctetString(Encoding.Unicode.GetBytes(Password));
        }
    }
}

internal class TlsBIOStream : Stream
{
    // Max TLS record size is 16KiB + 2KiB extra info.
    private readonly byte[] _incomingBuffer = new byte[18432];
    private readonly byte[] _outgoingBuffer = new byte[18432];
    private readonly BlockingCollection<int> _incoming = new();
    private readonly BlockingCollection<int> _outgoing = new();

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanTimeout => false;

    public override bool CanWrite => true;

    public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

    public override long Length => throw new NotImplementedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotImplementedException();

    public override void SetLength(long value) => throw new NotImplementedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        buffer.AsSpan(offset, count).CopyTo(_outgoingBuffer.AsSpan());
        _outgoing.Add(count);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        // FIXME Deal with smaller count - SslStream has a buffer of 4096
        int dataOffset = _incoming.Take();
        _incomingBuffer.AsSpan(0, dataOffset).CopyTo(buffer.AsSpan(offset, count));
        return dataOffset;
    }

    public override void Flush()
    { }

    public Span<byte> BioRead(CancellationToken? cancelToken = null)
    {
        int dataLength = _outgoing.Take(cancelToken ?? default);
        return _outgoingBuffer.AsSpan(0, dataLength);
    }

    public void BioWrite(ReadOnlySpan<byte> data)
    {
        data.CopyTo(_incomingBuffer.AsSpan());
        _incoming.Add(data.Length);
    }
}

internal enum CredSSPStage
{
    Start,
    TlsHandshake,
    Negotiate,
    KeyAuth,
    Delegate,
    Complete
}

internal class CredSSPAuthProvider : AuthenticationProvider, IWinRMEncryptor
{
    private readonly TSCredentialBase _credential;
    private readonly SecurityContext _secContext;
    private readonly TlsBIOStream _bio;
    private readonly SslStream _ssl;
    private readonly SslClientAuthenticationOptions _sslOptions;
    private IEnumerator<string>? _tokenGenerator;
    private CredSSPStage _stage = CredSSPStage.Start;
    private int? _trailerLength;

    public override bool Complete => _stage == CredSSPStage.Complete;

    public int MaxEncryptionChunkSize => 16384;

    public string EncryptionProtocol => "application/HTTP-CredSSP-session-encrypted";

    public CredSSPAuthProvider(TSCredentialBase credential, SecurityContext subAuthContext,
        SslClientAuthenticationOptions? sslOptions = null)
    {
        _credential = credential;
        _secContext = subAuthContext;

        if (sslOptions == null)
        {
            _sslOptions = new()
            {
                TargetHost = "dummy",
            };
            // Default for CredSSP is to not do any certificate validation.
            _sslOptions.RemoteCertificateValidationCallback = (_1, _2, _3, _4) => true;
        }
        else
        {
            _sslOptions = sslOptions;
        }

        _bio = new();
        _ssl = new(_bio);
    }

    public override bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response)
    {
        if (Complete)
        {
            throw new Exception("Auth provider is already completed");
        }

        AuthenticationHeaderValue? respAuthHeader = response?.Headers.WwwAuthenticate.FirstOrDefault();
        if (respAuthHeader is not null)
        {
            if (respAuthHeader.Scheme != "CredSSP")
            {
                // This typically happens if the client sent a malformed CredSSP packet and the server couldn't process
                // it so the auth resets itself.
                throw new Exception($"Unknown authentication failure at CredSSP stage {_stage}");
            }
            byte[] inputToken = Convert.FromBase64String(respAuthHeader.Parameter ?? "");
            _bio.BioWrite(inputToken);
        }

        _tokenGenerator ??= TokenGenerator().GetEnumerator();
        try
        {
            _tokenGenerator.MoveNext();
        }
        catch (Exception e)
        {
            throw new Exception($"CredSSP Auth exchange failed at {_stage}: {e.Message}", e);
        }

        if (Complete)
        {
            _tokenGenerator.Dispose();
            _tokenGenerator = null;
            return false;
        }
        else
        {
            string authValue = _tokenGenerator.Current;
            request.Headers.Add("Authorization", $"CredSSP {authValue}");
            return true;
        }
    }

    private IEnumerable<string> TokenGenerator()
    {
        // First stage is the TLS Handshake. The handshake operation is done in a background task as .NET doesn't
        // have a non-blocking memory BIO method to perform the handshake. Each of the tokens to exchange are sent
        // to the TlsBIOStream stream we can read and write from. The cancel token is used to let the code waiting
        // on a BIORead to know when no more data is expected and the handshake is done.
        _stage = CredSSPStage.TlsHandshake;
        using (CancellationTokenSource handshakeDone = new())
        {
            Task handshakeTask = Task.Run(() =>
            {
                try
                {
                    _ssl.AuthenticateAsClient(_sslOptions);
                }
                finally
                {
                    handshakeDone.Cancel();
                }
            });

            yield return Convert.ToBase64String(_bio.BioRead(handshakeDone.Token));

            // Keep on exchanging the tokens until the handshake is complete
            while (true)
            {
                ReadOnlySpan<byte> tlsPacket;
                try
                {
                    tlsPacket = _bio.BioRead(handshakeDone.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                yield return Convert.ToBase64String(tlsPacket);
            }

            // Check that no failures occurred when doing the TLS handshake before continuing.
            handshakeTask.GetAwaiter().GetResult();
        }

        int credSSPVersion = 0;
        byte[] pubKeyBytes = _ssl.RemoteCertificate?.GetPublicKey() ?? Array.Empty<byte>();
        AsnWriter asnWriter = new(AsnEncodingRules.DER);
        byte[]? buffer = new byte[16 * 1024];

        // Used to detect if the final msg is the NTLM auth token as that's sent with the pubKeyAuth info.
        // NTLMSSP\x00\x03\x00\x00\x00
        byte[] ntlm3Header = new byte[] { 78, 84, 76, 77, 83, 83, 80, 0, 3, 0, 0, 0 };

        // Second stage is the authentication exchange done over Negotiate, Kerberos, or NTLM. If the auth exchange
        // contains an odd amount (excluding 1) of tokens (NTLM), the final token is sent in step 3 as part of the
        // pubKeyAuth stage.
        _stage = CredSSPStage.Negotiate;
        TSRequest tsRequest;
        int read;
        byte[] outputToken = _secContext.Step();
        do
        {
            NegoData negoData = new(outputToken);
            tsRequest = new(tokens: new[] { negoData });
            tsRequest.ToBytes(asnWriter);
            read = asnWriter.Encode(buffer);

            _ssl.Write(buffer.AsSpan(0, read));
            outputToken = Array.Empty<byte>();
            yield return Convert.ToBase64String(_bio.BioRead());

            read = _ssl.Read(buffer, 0, buffer.Length);
            tsRequest = TSRequest.FromBytes(buffer.AsSpan(0, read), out var _);
            tsRequest.CheckSuccess();
            credSSPVersion = tsRequest.Version;

            byte[]? inputToken = tsRequest.Tokens?[0]?.Token;
            if (inputToken?.Length > 0)
            {
                outputToken = _secContext.Step(inputToken);
            }
            else if (!_secContext.Complete)
            {
                // This shouldn't ever happen but check it to ensure the loop doesn't run forever.
                throw new Exception("FIXME: Expecting input token for CredSSP auth but receive none");
            }

            // Special case for NTLM wrapped in SPNEGO. The context is still expecting 1 more token so won't be
            // complete but the NTLM auth message needs to be sent with the pubKeyAuth. The context is completed
            // later down in that case.
            if (outputToken.AsSpan().IndexOf(ntlm3Header) != -1)
            {
                break;
            }
        }
        while (!_secContext.Complete);

        // Third stage is to exchange the public key information to ensure
        _stage = CredSSPStage.KeyAuth;
        int selectedVersion = Math.Min(credSSPVersion, TSRequest.CREDSSP_VERSION);
        NegoData[]? pubKeyNegoData = null;
        if (outputToken.Length > 0)
        {
            pubKeyNegoData = new NegoData[] { new(outputToken) };
        }

        byte[]? clientNonce = null;
        if (selectedVersion > 4)
        {
            clientNonce = RandomNumberGenerator.GetBytes(32);
        }

        byte[] pubKeyAuth = GetPubKeyAuth(pubKeyBytes, "initiate", clientNonce);
        pubKeyAuth = _secContext.Wrap(pubKeyAuth);

        tsRequest = new(tokens: pubKeyNegoData, pubKeyAuth: pubKeyAuth, clientNonce: clientNonce);

        asnWriter = new(AsnEncodingRules.DER);
        tsRequest.ToBytes(asnWriter);
        read = asnWriter.Encode(buffer);

        _ssl.Write(buffer.AsSpan(0, read));
        outputToken = Array.Empty<byte>();
        yield return Convert.ToBase64String(_bio.BioRead());

        // Fourth stage is to verify the server key auth and send the delegated credentials
        _stage = CredSSPStage.Delegate;
        read = _ssl.Read(buffer, 0, buffer.Length);
        tsRequest = TSRequest.FromBytes(buffer.AsSpan(0, read), out var _);
        tsRequest.CheckSuccess();

        if (tsRequest.Tokens?.Length > 0)
        {
            // NTLM over SPNEGO auth returned the mechListMIC for us to verify.
            _secContext.Step(tsRequest.Tokens?[0]?.Token ?? Array.Empty<byte>());
        }

        if (tsRequest.PubKeyAuth == null)
        {
            throw new Exception("FIXME: Server did not response with pub key auth");
        }
        pubKeyAuth = _secContext.Unwrap(tsRequest.PubKeyAuth);
        byte[] expectedKey = GetPubKeyAuth(pubKeyBytes, "accept", clientNonce);
        if (!pubKeyAuth.SequenceEqual(expectedKey))
        {
            throw new Exception("FIXME: Public key verification failed");
        }

        asnWriter = new(AsnEncodingRules.DER);
        _credential.ToBytes(asnWriter);
        read = asnWriter.Encode(buffer);

        TSCredentials credentials = new(_credential.CredType, buffer.AsSpan(0, read).ToArray());
        asnWriter = new(AsnEncodingRules.DER);
        credentials.ToBytes(asnWriter);
        read = asnWriter.Encode(buffer);
        byte[] encCredentials = _secContext.Wrap(buffer.AsSpan(0, read));

        tsRequest = new(authInfo: encCredentials);
        asnWriter = new(AsnEncodingRules.DER);
        tsRequest.ToBytes(asnWriter);
        read = asnWriter.Encode(buffer);

        _ssl.Write(buffer.AsSpan(0, read));
        yield return Convert.ToBase64String(_bio.BioRead());

        _stage = CredSSPStage.Complete;
    }

    public byte[] Encrypt(Span<byte> data, out int paddingLength)
    {
        paddingLength = 0;

        int trailerLength = _trailerLength ?? GetTlsTrailerLength(data.Length, _ssl.SslProtocol,
            _ssl.NegotiatedCipherSuite, _ssl.HashAlgorithm, _ssl.CipherAlgorithm);
        _trailerLength = trailerLength;

        _ssl.Write(data);
        ReadOnlySpan<byte> wrappedData = _bio.BioRead();

        // Unfortunately the TLS "header" for WinRM is the trailing data, so the data needs to be rearranged in the
        // order that
        // int trailerOffset = wrappedData.Length - trailerLength;
        // byte[] encrypted = new byte[wrappedData.Length];
        // wrappedData.Slice(wrappedData.Length - trailerLength).CopyTo(encrypted.AsSpan());
        // wrappedData.Slice(0, wrappedData.Length - trailerLength).CopyTo(encrypted.AsSpan(trailerLength));

        byte[] encData = new byte[4 + wrappedData.Length];
        BitConverter.TryWriteBytes(encData.AsSpan(0, 4),trailerLength);
        wrappedData.CopyTo(encData.AsSpan(4));

        return encData;
    }

    public Span<byte> Decrypt(Span<byte> data)
    {
        // Ignore the 4 byte header signature.
        _bio.BioWrite(data[4..]);
        int read = _ssl.Read(data);
        return data[..read];
    }

    private static byte[] GetPubKeyAuth(byte[] pubKey, string usage, byte[]? nonce)
    {
        if (nonce?.Length > 0)
        {
            string direction = usage == "initiate" ? "Client-To-Server" : "Server-To-Client";
            using SHA256 sha256 = SHA256.Create();

            byte[] label = Encoding.UTF8.GetBytes($"CredSSP {direction} Binding Hash\u0000");
            sha256.TransformBlock(label, 0, label.Length, label, 0);
            sha256.TransformBlock(nonce, 0, nonce.Length, nonce, 0);
            sha256.TransformFinalBlock(pubKey, 0, pubKey.Length);
            return sha256.Hash ?? Array.Empty<byte>();
        }
        else if (usage == "accept")
        {
            pubKey[0]++;
            return pubKey;
        }
        else
        {
            return pubKey;
        }
    }

    public override void Dispose()
    {
        _ssl?.Dispose();
        _bio?.Dispose();
        _secContext.Dispose();
        _tokenGenerator?.Dispose();
        GC.SuppressFinalize(this);
    }

    private static int GetTlsTrailerLength(int dataLength, SslProtocols protocol, TlsCipherSuite cipherSuite,
        HashAlgorithmType hashAlgorithm, CipherAlgorithmType cipherAlgorithm)
    {
        if (protocol == SslProtocols.Tls13)
        {
            // The 2 cipher suites MS supports (TLS_AES_*_GCM_SHA*) have a fixed length of 17.
            return 17;
        }
        else if (cipherSuite.ToString().Contains("_GCM_"))
        {
            // GCM has a fixed length of 16 bytes
            return 16;
        }

        int hashLength = hashAlgorithm switch
        {
            HashAlgorithmType.Md5 => 16,
            HashAlgorithmType.Sha1 => 20,
            HashAlgorithmType.Sha256 => 32,
            HashAlgorithmType.Sha384 => 48,
            _ => throw new NotImplementedException($"Unknown Cipher Suite {cipherSuite}"),
        };

        int prepadLength = dataLength + hashLength;
        int paddingLength = cipherAlgorithm switch
        {
            CipherAlgorithmType.Rc4 => 0,
            CipherAlgorithmType.Des => 8 - (prepadLength % 8),
            CipherAlgorithmType.TripleDes => 8 - (prepadLength % 8),
            _ => 16 - (prepadLength % 8),
        };

        return (prepadLength + paddingLength) - dataLength;
    }
}
