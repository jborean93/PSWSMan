using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;

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
            throw new AuthenticationException(string.Format("Received CredSSP TSRequest error 0x{0:X8}", ErrorCode));
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

internal enum CredSSPStage
{
    Start,
    TlsHandshake,
    Negotiate,
    GenerateClientKey,
    VerifyServerKey,
    Delegate,
    Complete
}

internal class CredSSPAuthProvider : AuthenticationProvider, IWinRMEncryptor
{
    private readonly TSCredentialBase _credential;
    private readonly SecurityContext _secContext;
    private readonly TlsSecurityContext _tlsContext;
    private IEnumerator<string>? _tokenGenerator;
    private CredSSPStage _stage = CredSSPStage.Start;

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
            sslOptions = new()
            {
                TargetHost = "dummy",
            };
            // Default for CredSSP is to not do any certificate validation.
            sslOptions.RemoteCertificateValidationCallback = (_1, _2, _3, _4) => true;
        }

        _tlsContext = new(sslOptions);
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
            _tlsContext.WriteInputToken(respAuthHeader.Parameter ?? "");
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
        // First stage is the TLS Handshake which needs to be exchanged with the peer.
        _stage = CredSSPStage.TlsHandshake;
        foreach (string token in _tlsContext.DoHandshake())
        {
            yield return token;
        }

        byte[] buffer = new byte[16384];

        // Second stage is the authentication exchange done over Negotiate, Kerberos, or NTLM. If the auth exchange
        // contains an odd amount (excluding 1) of tokens (NTLM), the final token is sent in step 3 as part of the
        // pubKeyAuth stage.
        _stage = CredSSPStage.Negotiate;

        NegoData[]? negoTokens = null;
        byte[]? clientNonce = null;
        foreach ((TSRequest authRequest, bool isEnd) in DoAuthExchange(buffer))
        {
            if (isEnd)
            {
                if (Math.Min(TSRequest.CREDSSP_VERSION, authRequest.Version) > 4)
                {
                    clientNonce = RandomNumberGenerator.GetBytes(32);
                }
                negoTokens = authRequest.Tokens;
            }
            else
            {
                yield return WrapTSRequest(authRequest, buffer);
            }
        }

        // Third stage is to exchange the public key information to ensure
        _stage = CredSSPStage.GenerateClientKey;

        byte[] pubKeyBytes = _tlsContext.GetRemoteCertificate().GetPublicKey();
        byte[] pubKeyAuth = GetPubKeyAuth(pubKeyBytes, "initiate", clientNonce);
        pubKeyAuth = _secContext.Wrap(pubKeyAuth);

        TSRequest tsRequest = new(tokens: negoTokens, pubKeyAuth: pubKeyAuth, clientNonce: clientNonce);
        yield return WrapTSRequest(tsRequest, buffer);

        // Fourth stage is to verify the server key auth and send the delegated credentials
        _stage = CredSSPStage.VerifyServerKey;

        tsRequest = UnwrapTSRequest(buffer);
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

        // Fifth stage is to wrap the credential and send to the peer.
        _stage = CredSSPStage.Delegate;

        int read = WrapCredSSPStructure(_credential, buffer);
        TSCredentials credentials = new(_credential.CredType, buffer.AsSpan(0, read).ToArray());
        read = WrapCredSSPStructure(credentials, buffer);
        byte[] encCredentials = _secContext.Wrap(buffer.AsSpan(0, read));

        tsRequest = new(authInfo: encCredentials);
        yield return WrapTSRequest(tsRequest, buffer);

        _stage = CredSSPStage.Complete;
    }

    public byte[] Encrypt(Span<byte> data, out int paddingLength)
    {
        paddingLength = 0;
        int trailerLength = _tlsContext.GetTlsTrailerLength(data.Length);

        Span<byte> wrappedData = _tlsContext.Encrypt(data);

        byte[] encData = new byte[4 + wrappedData.Length];
        BitConverter.TryWriteBytes(encData.AsSpan(0, 4),trailerLength);
        wrappedData.CopyTo(encData.AsSpan(4));

        return encData;
    }

    public Span<byte> Decrypt(Span<byte> data)
    {
        // Ignore the 4 byte header signature.
        int length = _tlsContext.Decrypt(data[4..]);
        return data.Slice(4, length);
    }

    private string WrapTSRequest(TSRequest request, Span<byte> buffer)
    {
        int read = WrapCredSSPStructure(request, buffer);
        return Convert.ToBase64String(_tlsContext.Encrypt(buffer[..read]));
    }

    private TSRequest UnwrapTSRequest(Span<byte> buffer)
    {
        Span<byte> unwrappedData = _tlsContext.ReadInputToken(buffer);
        TSRequest tsRequest = TSRequest.FromBytes(unwrappedData, out var _);
        tsRequest.CheckSuccess();

        return tsRequest;
    }

    private int WrapCredSSPStructure(CredSSPStructure obj, Span<byte> buffer)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        obj.ToBytes(writer);
        return writer.Encode(buffer);
    }

    private IEnumerable<(TSRequest, bool)> DoAuthExchange(byte[] buffer)
    {
        // Used to detect if the final msg is the NTLM auth token as that's sent with the pubKeyAuth info.
        // NTLMSSP\x00\x03\x00\x00\x00
        byte[] ntlm3Header = new byte[] { 78, 84, 76, 77, 83, 83, 80, 0, 3, 0, 0, 0 };
        int credSSPVersion = 0;

        NegoData[]? negoDatas = new[] { new NegoData(_secContext.Step()) };
        do
        {
            TSRequest tsRequest = new(tokens: negoDatas);
            negoDatas = null; // Set to null for the end check
            yield return (tsRequest, false);

            tsRequest = UnwrapTSRequest(buffer);
            credSSPVersion = tsRequest.Version;

            byte[]? inputToken = tsRequest.Tokens?[0]?.Token;
            if (inputToken?.Length > 0)
            {
                byte[] outputToken = _secContext.Step(inputToken);

                if (outputToken.Length > 0)
                {
                    negoDatas = new[] { new NegoData(outputToken) };
                }

                // Special case for NTLM wrapped in SPNEGO. The context is still expecting 1 more token so won't be
                // complete but the NTLM auth message needs to be sent with the pubKeyAuth. The context is completed
                // later down in that case.
                if (outputToken.AsSpan().IndexOf(ntlm3Header) != -1)
                {
                    break;
                }
            }
            else if (!_secContext.Complete)
            {
                // This shouldn't ever happen but check it to ensure the loop doesn't run forever.
                throw new Exception("FIXME: Expecting input token for CredSSP auth but receive none");
            }
        }
        while (!_secContext.Complete);

        yield return (new TSRequest(version: credSSPVersion, tokens: negoDatas), true);
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
        _secContext.Dispose();
        _tlsContext.Dispose();
        _tokenGenerator?.Dispose();
        GC.SuppressFinalize(this);
    }
}
