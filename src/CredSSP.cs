using System;
using System.Formats.Asn1;
using System.Net.Http;
using System.Net.Security;

namespace PSWSMan;

/// <summary>Base class used for CredSSP ASN.1 Structures.</summary>
internal abstract class CredSSPStructure
{
    public CredSSPStructure()
    { }

    public virtual void ToBytes(AsnWriter writer) => throw new NotImplementedException();
}

/// <summary>TSRequest Payload</summary>
/// <remarks>
/// <para>
/// This is the TSRequest payload structure used in a CredSSP exchange.
/// </para>
/// <para>
/// The ASN.1 structure is defined as
//     TSRequest ::= SEQUENCE {
//             version    [0] INTEGER,
//             negoTokens [1] NegoData  OPTIONAL,
//             authInfo   [2] OCTET STRING OPTIONAL,
//             pubKeyAuth [3] OCTET STRING OPTIONAL,
//             errorCode  [4] INTEGER OPTIONAL,
//             clientNonce [5] OCTET STRING OPTIONAL
//     }
/// </para>
/// </remarks>
/// <see href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685">2.2.1 TSRequest</see>
internal class TSRequest : CredSSPStructure
{
    /// <summary>The highest CredSSP version supported.</summary>
    public int Version { get; set; }

    /// <summary>Contains the negotiate tokens to exchange.</summary>
    public NegoData[]? Tokens { get; set; }

    /// <summary>The credential information to delegate.</summary>
    public TSCredentials? AuthInfo { get; set; }

    /// <summary>The public key information used to protect against MitM attacks.</summary>
    public byte[]? PubKeyAuth { get; set; }

    /// <summary>Extra error information returned by a server.</summary>
    public int? ErrorCode { get; set;}

    /// <summary>Unique nonce used for pub key auth hashing on newer CredSSP versions.</summary>
    public byte[]? ClientNonce { get; set; }

    public TSRequest(int version, NegoData[]? tokens = null, TSCredentials? authInfo = null, byte[]? pubKeyAuth = null,
        int? errorCode = null, byte[]? clientNonce = null)
    {
        Version = version;
        Tokens = tokens;
        AuthInfo = authInfo;
        PubKeyAuth = pubKeyAuth;
        ErrorCode = errorCode;
        ClientNonce = clientNonce;
    }

    public override void ToBytes(AsnWriter writer) => throw new NotImplementedException();

    public static TSRequest FromBytes(ReadOnlySpan<byte> data, out int bytesConsumed,
        AsnEncodingRules ruleSet = AsnEncodingRules.DER)
    {
        throw new NotImplementedException();
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

    public override void ToBytes(AsnWriter writer) => throw new NotImplementedException();

    public static NegoData FromBytes(ReadOnlySpan<byte> data, out int bytesConsumed,
        AsnEncodingRules ruleSet = AsnEncodingRules.DER)
    {
        throw new NotImplementedException();
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
    /// <summary>The password credentials to delegate.</summary>
    public TSCredentialBase Credentials { get; set; }

    public TSCredentials(TSCredentialBase credentials)
    {
        Credentials = credentials;
    }

    public override void ToBytes(AsnWriter writer) => throw new NotImplementedException();

    public static TSCredentials FromBytes(ReadOnlySpan<byte> data, out int bytesConsumed,
        AsnEncodingRules ruleSet = AsnEncodingRules.DER)
    {
        throw new NotImplementedException();
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

    public override void ToBytes(AsnWriter writer) => throw new NotImplementedException();

    public static TSPasswordCreds FromBytes(ReadOnlySpan<byte> data, out int bytesConsumed,
        AsnEncodingRules ruleSet = AsnEncodingRules.DER)
    {
        throw new NotImplementedException();
    }
}

internal class CredSSPAuthProvider : AuthenticationProvider
{
    private readonly bool _encrypt;
    private readonly SecurityContext _secContext;
    private readonly string _domainName;
    private readonly string _username;
    private readonly string _password;
    private bool _complete;
    private SslStream? _ssl;

    public override bool Complete => _complete;

    public override bool WillEncrypt => _encrypt;

    public override string EncryptionProtocol => "application/HTTP-CredSSP-session-encrypted";

    public CredSSPAuthProvider(string username, string password, SecurityContext subAuthContext, bool encrypt,
        SslClientAuthenticationOptions? sslOptions = null)
    {
        _secContext = subAuthContext;
        _encrypt = encrypt;

        _domainName = "";
        _username = username;
        if (_username.Contains('\\'))
        {
            string[] stringSplit = username.Split('\\', 2);
            _domainName = stringSplit[0];
            _username = stringSplit[1];
        }
        _password = password;

        if (sslOptions == null)
        {
            sslOptions = new()
            {
                TargetHost = "dummy",
            };
            // Default for CredSSP is to not do any certificate validation.
            sslOptions.RemoteCertificateValidationCallback = (_1, _2, _3, _4) => true;
        }
    }

    public override bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response)
    {
        if (Complete)
        {
            throw new Exception("Auth provider is already completed");
        }

        throw new NotImplementedException();
    }

    public override (byte[], byte[], int) Wrap(Span<byte> data)
    {
        throw new NotImplementedException();
    }

    public override Span<byte> Unwrap(Span<byte> data, int headerLength)
    {
        throw new NotImplementedException();
    }

    public override void Dispose()
    {
        _ssl?.Dispose();
        _secContext.Dispose();
        GC.SuppressFinalize(this);
    }
}
