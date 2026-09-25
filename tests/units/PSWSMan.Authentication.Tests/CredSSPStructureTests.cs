using System;
using System.Formats.Asn1;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PSWSMan.Authentication.Tests;

/// <summary>
/// Packing and unpacking of the CredSSP ASN.1 structures. TSRequest and NegoData are round tripped through their own
/// parsers, TSCredentials and TSPasswordCreds are only ever sent so their DER is read back with AsnDecoder.
/// </summary>
public class CredSSPStructureTests
{
    private static byte[] Encode(CredSSPStructure structure)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        structure.ToBytes(writer);
        return writer.Encode();
    }

    private static Asn1Tag Context(int value) => new(TagClass.ContextSpecific, value, isConstructed: true);

    private static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", ""));

    [Test]
    public async Task TSRequest_VersionOnly_ExactDer()
    {
        byte[] actual = Encode(new TSRequest());

        // SEQUENCE { [0] { INTEGER 6 } }
        await Assert.That(actual).IsEquivalentTo(Hex("30 05 A0 03 02 01 06"));
    }

    [Test]
    public async Task TSRequest_AllFields_ExactDer()
    {
        TSRequest request = new(
            version: 6,
            tokens: [new NegoData([0x01, 0x02])],
            authInfo: [0x03],
            pubKeyAuth: [0x04, 0x05],
            errorCode: 1,
            clientNonce: [0x06]);

        byte[] actual = Encode(request);

        await Assert.That(actual).IsEquivalentTo(Hex(
            "30 26" +
            "A0 03 02 01 06" +                           // [0] version
            "A1 0A 30 08 30 06 A0 04 04 02 01 02" +      // [1] NegoData
            "A2 03 04 01 03" +                           // [2] authInfo
            "A3 04 04 02 04 05" +                        // [3] pubKeyAuth
            "A4 03 02 01 01" +                           // [4] errorCode
            "A5 03 04 01 06"));                          // [5] clientNonce
    }

    [Test]
    public async Task TSRequest_EmptyOptionalArrays_AreOmitted()
    {
        TSRequest request = new(tokens: [], authInfo: [], pubKeyAuth: [], clientNonce: []);

        byte[] actual = Encode(request);

        await Assert.That(actual).IsEquivalentTo(Encode(new TSRequest()));
    }

    [Test]
    public async Task TSRequest_ErrorCodeZero_IsWritten()
    {
        byte[] actual = Encode(new TSRequest(errorCode: 0));

        await Assert.That(actual).IsEquivalentTo(Hex("30 0A A0 03 02 01 06 A4 03 02 01 00"));
    }

    [Test]
    public async Task TSRequest_NegativeErrorCode_IsTwosComplement()
    {
        int ntStatus = unchecked((int)0xC000006D);

        byte[] actual = Encode(new TSRequest(errorCode: ntStatus));

        await Assert.That(actual).IsEquivalentTo(Hex("30 0D A0 03 02 01 06 A4 06 02 04 C0 00 00 6D"));
    }

    [Test]
    [Arguments(0)]
    [Arguments(2)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(127)]
    [Arguments(128)]
    [Arguments(int.MaxValue)]
    public async Task TSRequest_Version_RoundTrips(int version)
    {
        byte[] data = Encode(new TSRequest(version: version));

        TSRequest actual = TSRequest.FromBytes(data, out int consumed);

        await Assert.That(actual.Version).IsEqualTo(version);
        await Assert.That(consumed).IsEqualTo(data.Length);
        await Assert.That(actual.Tokens).IsNull();
        await Assert.That(actual.AuthInfo).IsNull();
        await Assert.That(actual.PubKeyAuth).IsNull();
        await Assert.That(actual.ErrorCode).IsNull();
        await Assert.That(actual.ClientNonce).IsNull();
    }

    [Test]
    public async Task TSRequest_AllFields_RoundTrip()
    {
        byte[] token1 = Enumerable.Range(0, 300).Select(i => (byte)i).ToArray();
        byte[] token2 = "second"u8.ToArray();
        byte[] authInfo = Enumerable.Repeat((byte)0xAA, 1000).ToArray();
        byte[] pubKeyAuth = Enumerable.Repeat((byte)0xBB, 64).ToArray();
        byte[] nonce = Enumerable.Repeat((byte)0xCC, 32).ToArray();
        TSRequest request = new(
            version: 6,
            tokens: [new NegoData(token1), new NegoData(token2)],
            authInfo: authInfo,
            pubKeyAuth: pubKeyAuth,
            errorCode: unchecked((int)0x80090308),
            clientNonce: nonce);

        byte[] data = Encode(request);
        TSRequest actual = TSRequest.FromBytes(data, out int consumed);

        await Assert.That(consumed).IsEqualTo(data.Length);
        await Assert.That(actual.Version).IsEqualTo(6);
        await Assert.That(actual.Tokens!.Length).IsEqualTo(2);
        await Assert.That(actual.Tokens[0].Token).IsEquivalentTo(token1);
        await Assert.That(actual.Tokens[1].Token).IsEquivalentTo(token2);
        await Assert.That(actual.AuthInfo).IsEquivalentTo(authInfo);
        await Assert.That(actual.PubKeyAuth).IsEquivalentTo(pubKeyAuth);
        await Assert.That(actual.ErrorCode!.Value).IsEqualTo(unchecked((int)0x80090308));
        await Assert.That(actual.ClientNonce).IsEquivalentTo(nonce);
    }

    [Test]
    public async Task TSRequest_FromBytes_ConsumesOnlyTheSequence()
    {
        byte[] data = [.. Encode(new TSRequest(authInfo: [1, 2, 3])), 0xFF, 0xFE];

        TSRequest actual = TSRequest.FromBytes(data, out int consumed);

        await Assert.That(consumed).IsEqualTo(data.Length - 2);
        await Assert.That(actual.AuthInfo).IsEquivalentTo(new byte[] { 1, 2, 3 });
    }

    [Test]
    public async Task TSRequest_FromBytes_FieldsInAnyOrder()
    {
        // [4] errorCode, [2] authInfo, [0] version.
        byte[] data = Hex("30 0F A4 03 02 01 07 A2 03 04 01 09 A0 03 02 01 02");

        TSRequest actual = TSRequest.FromBytes(data, out _);

        await Assert.That(actual.Version).IsEqualTo(2);
        await Assert.That(actual.ErrorCode!.Value).IsEqualTo(7);
        await Assert.That(actual.AuthInfo).IsEquivalentTo(new byte[] { 9 });
    }

    [Test]
    public async Task TSRequest_FromBytes_MissingVersion_IsZero()
    {
        byte[] data = Hex("30 05 A2 03 04 01 09");

        TSRequest actual = TSRequest.FromBytes(data, out _);

        await Assert.That(actual.Version).IsEqualTo(0);
        await Assert.That(actual.AuthInfo).IsEquivalentTo(new byte[] { 9 });
    }

    [Test]
    public async Task TSRequest_FromBytes_EmptySequence()
    {
        TSRequest actual = TSRequest.FromBytes(Hex("30 00"), out int consumed);

        await Assert.That(consumed).IsEqualTo(2);
        await Assert.That(actual.Version).IsEqualTo(0);
        await Assert.That(actual.Tokens).IsNull();
    }

    [Test]
    public async Task TSRequest_FromBytes_UnknownTag_IsSkipped()
    {
        // A [6] element between version and authInfo is ignored, as are its contents.
        byte[] data = Hex("30 11 A0 03 02 01 06 A6 05 04 03 01 02 03 A2 03 04 01 09");

        TSRequest actual = TSRequest.FromBytes(data, out int consumed);

        await Assert.That(consumed).IsEqualTo(data.Length);
        await Assert.That(actual.Version).IsEqualTo(6);
        await Assert.That(actual.AuthInfo).IsEquivalentTo(new byte[] { 9 });
    }

    [Test]
    [Arguments("30 08 02 01 09 A0 03 02 01 06", "universal INTEGER")]
    [Arguments("30 0A 30 03 02 01 09 A0 03 02 01 06", "universal SEQUENCE")]
    [Arguments("30 0A 60 03 02 01 09 A0 03 02 01 06", "application [0]")]
    [Arguments("30 0A E4 03 02 01 09 A0 03 02 01 06", "private [4]")]
    public async Task TSRequest_FromBytes_NonContextTags_AreSkipped(string hex, string reason)
    {
        // Tag numbers 0 to 5 only mean something in the context specific class, so these must not be mistaken for
        // the fields with the same number.
        TSRequest actual = TSRequest.FromBytes(Hex(hex), out int consumed);

        await Assert.That(actual.Version).IsEqualTo(6);
        await Assert.That(actual.ErrorCode).IsNull();
        await Assert.That(consumed).IsEqualTo(Hex(hex).Length);
        await Assert.That(reason).IsNotEmpty();
    }

    [Test]
    public async Task TSRequest_FromBytes_EmptyNegoData_IsEmptyArray()
    {
        // [1] { SEQUENCE OF {} }
        byte[] data = Hex("30 09 A0 03 02 01 06 A1 02 30 00");

        TSRequest actual = TSRequest.FromBytes(data, out _);

        await Assert.That(actual.Tokens).IsNotNull();
        await Assert.That(actual.Tokens!.Length).IsEqualTo(0);
    }

    [Test]
    public async Task TSRequest_FromBytes_EmptyOctetStrings_AreEmptyArrays()
    {
        byte[] data = Hex("30 11 A0 03 02 01 06 A2 02 04 00 A3 02 04 00 A5 02 04 00");

        TSRequest actual = TSRequest.FromBytes(data, out _);

        await Assert.That(actual.AuthInfo!.Length).IsEqualTo(0);
        await Assert.That(actual.PubKeyAuth!.Length).IsEqualTo(0);
        await Assert.That(actual.ClientNonce!.Length).IsEqualTo(0);
    }

    [Test]
    public async Task TSRequest_FromBytes_DuplicateField_LastWins()
    {
        byte[] data = Hex("30 0A A0 03 02 01 02 A0 03 02 01 06");

        TSRequest actual = TSRequest.FromBytes(data, out _);

        await Assert.That(actual.Version).IsEqualTo(6);
    }

    [Test]
    public async Task TSRequest_FromBytes_Ber_IndefiniteLength()
    {
        // The same request as VersionOnly but with indefinite lengths, which only BER allows.
        byte[] data = Hex("30 80 A0 80 02 01 06 00 00 00 00");

        TSRequest actual = TSRequest.FromBytes(data, out int consumed, AsnEncodingRules.BER);

        await Assert.That(actual.Version).IsEqualTo(6);
        await Assert.That(consumed).IsEqualTo(data.Length);
        Assert.Throws<AsnContentException>(() => TSRequest.FromBytes(data, out _));
    }

    [Test]
    public async Task TSRequest_FromBytes_ErrorCodeAboveInt32_Throws()
    {
        // An NTSTATUS written as an unsigned value does not fit the int the structure exposes.
        byte[] data = Hex("30 0E A0 03 02 01 06 A4 07 02 05 00 C0 00 00 6D");

        Assert.Throws<OverflowException>(() => TSRequest.FromBytes(data, out _));

        await Task.CompletedTask;
    }

    [Test]
    [Arguments("", "empty")]
    [Arguments("30", "truncated header")]
    [Arguments("30 07 A0 03 02 01", "truncated content")]
    [Arguments("04 03 01 02 03", "not a sequence")]
    [Arguments("30 05 A0 03 04 01 06", "version is not an integer")]
    [Arguments("30 05 80 03 02 01 06", "version tag is primitive")]
    [Arguments("30 07 A1 05 04 03 01 02 03", "negoTokens is not a sequence")]
    [Arguments("30 05 A2 03 02 01 06", "authInfo is not an octet string")]
    [Arguments("30 05 A4 03 04 01 06", "errorCode is not an integer")]
    [Arguments("30 08 A0 03 02 01 06 A6 05 04", "unknown tag with truncated content")]
    public async Task TSRequest_FromBytes_Malformed_Throws(string hex, string reason)
    {
        Assert.Throws<AsnContentException>(() => TSRequest.FromBytes(Hex(hex), out _));

        await Assert.That(reason).IsNotEmpty();
    }

    [Test]
    public async Task NegoData_ExactDer()
    {
        byte[] actual = Encode(new NegoData("abc"u8.ToArray()));

        // SEQUENCE { [0] { OCTET STRING "abc" } }
        await Assert.That(actual).IsEquivalentTo(Hex("30 07 A0 05 04 03 61 62 63"));
    }

    [Test]
    public async Task NegoData_EmptyToken_RoundTrips()
    {
        byte[] data = Encode(new NegoData([]));

        NegoData actual = NegoData.FromBytes(data, out int consumed);

        await Assert.That(data).IsEquivalentTo(Hex("30 04 A0 02 04 00"));
        await Assert.That(consumed).IsEqualTo(data.Length);
        await Assert.That(actual.Token.Length).IsEqualTo(0);
    }

    [Test]
    [Arguments(1)]
    [Arguments(127)]
    [Arguments(128)]
    [Arguments(255)]
    [Arguments(256)]
    [Arguments(65535)]
    [Arguments(65536)]
    public async Task NegoData_TokenLengths_RoundTrip(int length)
    {
        byte[] token = new byte[length];
        Random.Shared.NextBytes(token);

        byte[] data = Encode(new NegoData(token));
        NegoData actual = NegoData.FromBytes(data, out int consumed);

        await Assert.That(consumed).IsEqualTo(data.Length);
        await Assert.That(actual.Token).IsEquivalentTo(token);
    }

    [Test]
    public async Task NegoData_FromBytes_ConsumesOnlyTheSequence()
    {
        byte[] data = [.. Encode(new NegoData([1])), .. Encode(new NegoData([2]))];

        NegoData first = NegoData.FromBytes(data, out int consumed);
        NegoData second = NegoData.FromBytes(data.AsSpan(consumed), out int consumed2);

        await Assert.That(first.Token).IsEquivalentTo(new byte[] { 1 });
        await Assert.That(second.Token).IsEquivalentTo(new byte[] { 2 });
        await Assert.That(consumed + consumed2).IsEqualTo(data.Length);
    }

    [Test]
    public async Task NegoData_FromBytes_Ber_IndefiniteLength()
    {
        byte[] data = Hex("30 80 A0 80 04 01 41 00 00 00 00");

        NegoData actual = NegoData.FromBytes(data, out int consumed, AsnEncodingRules.BER);

        await Assert.That(actual.Token).IsEquivalentTo("A"u8.ToArray());
        await Assert.That(consumed).IsEqualTo(data.Length);
        Assert.Throws<AsnContentException>(() => NegoData.FromBytes(data, out _));
    }

    [Test]
    [Arguments("", "empty")]
    [Arguments("30 00", "missing negoToken")]
    [Arguments("30 05 A1 03 04 01 41", "wrong context tag")]
    [Arguments("30 05 80 03 04 01 41", "negoToken tag is primitive")]
    [Arguments("30 05 A0 03 02 01 41", "negoToken is not an octet string")]
    [Arguments("30 07 A0 05 04 03 61 62", "truncated token")]
    [Arguments("A0 05 04 03 61 62 63", "outer sequence missing")]
    public async Task NegoData_FromBytes_Malformed_Throws(string hex, string reason)
    {
        Assert.Throws<AsnContentException>(() => NegoData.FromBytes(Hex(hex), out _));

        await Assert.That(reason).IsNotEmpty();
    }

    [Test]
    public async Task TSCredentials_ExactDer()
    {
        byte[] actual = Encode(new TSCredentials(1, [0x01, 0x02]));

        // SEQUENCE { [0] { INTEGER 1 } [1] { OCTET STRING 0102 } }
        await Assert.That(actual).IsEquivalentTo(Hex("30 0B A0 03 02 01 01 A1 04 04 02 01 02"));
    }

    private static (int CredType, byte[] Credentials) DecodeTSCredentials(byte[] data)
    {
        AsnDecoder.ReadSequence(data, AsnEncodingRules.DER, out int offset, out int length, out int consumed);
        if (consumed != data.Length)
        {
            throw new InvalidOperationException("Trailing data after TSCredentials");
        }
        ReadOnlySpan<byte> content = data.AsSpan(offset, length);

        AsnDecoder.ReadSequence(content, AsnEncodingRules.DER, out offset, out length, out consumed, Context(0));
        int credType = (int)AsnDecoder.ReadInteger(content.Slice(offset, length), AsnEncodingRules.DER, out _);
        content = content[consumed..];

        AsnDecoder.ReadSequence(content, AsnEncodingRules.DER, out offset, out length, out consumed, Context(1));
        byte[] credentials = AsnDecoder.ReadOctetString(content.Slice(offset, length), AsnEncodingRules.DER, out _);
        content = content[consumed..];
        if (content.Length != 0)
        {
            throw new InvalidOperationException("Unexpected extra fields in TSCredentials");
        }

        return (credType, credentials);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(6)]
    [Arguments(255)]
    [Arguments(int.MaxValue)]
    public async Task TSCredentials_Decodes(int credType)
    {
        byte[] credentials = Encode(new TSPasswordCreds("D", "U", "P"));
        byte[] data = Encode(new TSCredentials(credType, credentials));

        (int actualType, byte[] actualCredentials) = DecodeTSCredentials(data);

        await Assert.That(actualType).IsEqualTo(credType);
        await Assert.That(actualCredentials).IsEquivalentTo(credentials);
    }

    [Test]
    public async Task TSCredentials_EmptyCredentials_IsWritten()
    {
        byte[] actual = Encode(new TSCredentials(1, []));

        await Assert.That(actual).IsEquivalentTo(Hex("30 09 A0 03 02 01 01 A1 02 04 00"));
    }

    [Test]
    public async Task TSPasswordCreds_CredType_IsPassword()
    {
        TSCredentialBase creds = new TSPasswordCreds("D", "U", "P");

        await Assert.That(creds.CredType).IsEqualTo(1);
    }

    [Test]
    public async Task TSPasswordCreds_ExactDer()
    {
        byte[] actual = Encode(new TSPasswordCreds("D", "U", "P"));

        // Each string is UTF-16LE, "D" is 44 00 and so on.
        await Assert.That(actual).IsEquivalentTo(Hex(
            "30 12" +
            "A0 04 04 02 44 00" +
            "A1 04 04 02 55 00" +
            "A2 04 04 02 50 00"));
    }

    private static (string Domain, string User, string Password) DecodePasswordCreds(byte[] data)
    {
        AsnDecoder.ReadSequence(data, AsnEncodingRules.DER, out int offset, out int length, out int consumed);
        if (consumed != data.Length)
        {
            throw new InvalidOperationException("Trailing data after TSPasswordCreds");
        }
        ReadOnlySpan<byte> content = data.AsSpan(offset, length);

        string[] values = new string[3];
        for (int i = 0; i < 3; i++)
        {
            AsnDecoder.ReadSequence(content, AsnEncodingRules.DER, out offset, out length, out consumed, Context(i));
            byte[] raw = AsnDecoder.ReadOctetString(content.Slice(offset, length), AsnEncodingRules.DER, out _);
            values[i] = Encoding.Unicode.GetString(raw);
            content = content[consumed..];
        }
        if (content.Length != 0)
        {
            throw new InvalidOperationException("Unexpected extra fields in TSPasswordCreds");
        }

        return (values[0], values[1], values[2]);
    }

    [Test]
    [Arguments("DOMAIN", "user", "Password01")]
    [Arguments("", "user", "Password01")]
    [Arguments("", "", "")]
    [Arguments("domain.test", "user@domain.test", "p@ss w0rd!")]
    [Arguments("DOMÄIN", "üser", "pässwörd€")]
    [Arguments("D", "U", "😀🔑")]
    [Arguments("D", "U", "\0inner\0nul\0")]
    public async Task TSPasswordCreds_Decodes(string domain, string user, string password)
    {
        byte[] data = Encode(new TSPasswordCreds(domain, user, password));

        (string actualDomain, string actualUser, string actualPassword) = DecodePasswordCreds(data);

        await Assert.That(actualDomain).IsEqualTo(domain);
        await Assert.That(actualUser).IsEqualTo(user);
        await Assert.That(actualPassword).IsEqualTo(password);
    }

    [Test]
    public async Task TSPasswordCreds_LongPassword_UsesLongFormLengths()
    {
        string password = new('x', 1000);

        byte[] data = Encode(new TSPasswordCreds("D", "U", password));
        (_, _, string actualPassword) = DecodePasswordCreds(data);

        await Assert.That(actualPassword).IsEqualTo(password);
        // 2000 bytes of UTF-16 needs the 2 byte long form length on the octet string.
        await Assert.That(data.Length).IsGreaterThan(2000);
    }

    [Test]
    public async Task TSPasswordCreds_InsideTSCredentials_RoundTrips()
    {
        TSPasswordCreds creds = new("DOMAIN", "user", "Password01");
        byte[] data = Encode(new TSCredentials(creds.CredType, Encode(creds)));

        (int credType, byte[] inner) = DecodeTSCredentials(data);
        (string actualDomain, string actualUser, string actualPassword) = DecodePasswordCreds(inner);

        await Assert.That(credType).IsEqualTo(1);
        await Assert.That(actualDomain).IsEqualTo("DOMAIN");
        await Assert.That(actualUser).IsEqualTo("user");
        await Assert.That(actualPassword).IsEqualTo("Password01");
    }
}
