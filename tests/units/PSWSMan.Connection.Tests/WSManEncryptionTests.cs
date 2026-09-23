using System;
using System.Text;
using System.Threading.Tasks;

namespace PSWSMan.Connection.Tests;

public class WSManEncryptionTests
{
    private const string MimeText =
        "--Encrypted Boundary\r\n" +
        "Content-Type: " + FakeEncryptor.Protocol + "\r\n" +
        "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=3\r\n" +
        "--Encrypted Boundary\r\n" +
        "Content-Type: application/octet-stream\r\n";

    // GSSAPI/SSPI shape: the prefix is the header length and there is no trailer.
    private const string HeaderModeExpected = MimeText + "\u0004\u0000\u0000\u0000HDR!abc--Encrypted Boundary--\r\n";

    // CredSSP shape: the prefix is the trailer length and the trailer follows the data.
    private const string TrailerModeExpected = MimeText + "\u0003\u0000\u0000\u0000HDR!abcTAG--Encrypted Boundary--\r\n";

    private static string Text(WSManEncryptedPayload payload) => Encoding.Latin1.GetString(payload.Payload);

    [Test]
    public async Task Wrap_HeaderMode_MatchesWinRMFraming()
    {
        FakeEncryptor encryptor = new(key: 0x00);
        byte[] message = "abc"u8.ToArray();

        WSManEncryptedPayload payload = WSManEncryption.Wrap(message, encryptor);

        await Assert.That(Text(payload)).IsEqualTo(HeaderModeExpected);
        await Assert.That(payload.ContentType).IsEqualTo(
            $"multipart/encrypted;protocol=\"{FakeEncryptor.Protocol}\";boundary=\"Encrypted Boundary\"");
        await Assert.That(encryptor.Wraps).IsEqualTo(1);
        await Assert.That(message).IsEquivalentTo("abc"u8.ToArray());
    }

    [Test]
    public async Task Wrap_TrailerMode_PrefixIsTrailerLength()
    {
        FakeEncryptor encryptor = new(key: 0x00) { TrailerMode = true };

        WSManEncryptedPayload payload = WSManEncryption.Wrap("abc"u8, encryptor);

        await Assert.That(Text(payload)).IsEqualTo(TrailerModeExpected);
    }

    [Test]
    public async Task Wrap_MultiChunk_UsesMultiEncryptedType()
    {
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: 2);

        WSManEncryptedPayload payload = WSManEncryption.Wrap("abcde"u8, encryptor);

        string text = Text(payload);
        await Assert.That(payload.ContentType).StartsWith("multipart/x-multi-encrypted;");
        // Three chunks, each with a metadata and a data part, and a single terminator at the very end.
        await Assert.That(text.Split("--Encrypted Boundary\r\n").Length - 1).IsEqualTo(6);
        await Assert.That(text.Split("--Encrypted Boundary--\r\n").Length - 1).IsEqualTo(1);
        await Assert.That(text).EndsWith("--Encrypted Boundary--\r\n");
        await Assert.That(text).Contains("Length=2\r\n");
        await Assert.That(text).Contains("Length=1\r\n");
        await Assert.That(encryptor.Wraps).IsEqualTo(3);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Unwrap_RoundTrip(bool trailerMode)
    {
        FakeEncryptor encryptor = new(key: 0x7F, maxChunkSize: 5) { TrailerMode = trailerMode };
        byte[] message = Encoding.UTF8.GetBytes("<Envelope>some payload that spans chunks</Envelope>");

        WSManEncryptedPayload payload = WSManEncryption.Wrap(message, encryptor);
        byte[] buffer = payload.Payload;
        int length = WSManEncryption.Unwrap(buffer, encryptor);

        await Assert.That(length).IsEqualTo(message.Length);
        await Assert.That(buffer.AsSpan(0, length).ToArray()).IsEquivalentTo(message);
    }

    [Test]
    public async Task Unwrap_ExchangeStyleBoundaryWithSpace()
    {
        FakeEncryptor encryptor = new(key: 0x00);
        string payload =
            "-- Encrypted Boundary\r\n" +
            $"Content-Type: {FakeEncryptor.Protocol}\r\n" +
            "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=3\r\n" +
            "-- Encrypted Boundary\r\n" +
            "Content-Type: application/octet-stream\r\n" +
            "\u0004\u0000\u0000\u0000HDR!abc" +
            "-- Encrypted Boundary--\r\n";
        byte[] buffer = Encoding.Latin1.GetBytes(payload);

        int length = WSManEncryption.Unwrap(buffer, encryptor);

        await Assert.That(Encoding.UTF8.GetString(buffer, 0, length)).IsEqualTo("abc");
    }

    [Test]
    public async Task Unwrap_LengthMismatch_Throws()
    {
        FakeEncryptor encryptor = new(key: 0x00);
        string payload =
            "--Encrypted Boundary\r\n" +
            $"Content-Type: {FakeEncryptor.Protocol}\r\n" +
            "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=10\r\n" +
            "--Encrypted Boundary\r\n" +
            "Content-Type: application/octet-stream\r\n" +
            "\u0004\u0000\u0000\u0000HDR!abc" +
            "--Encrypted Boundary--\r\n";

        WSManTransportException ex = Assert.Throws<WSManTransportException>(
            () => WSManEncryption.Unwrap(Encoding.Latin1.GetBytes(payload), encryptor));

        await Assert.That(ex.Message).Contains("Mismatched");
    }

    [Test]
    public async Task Unwrap_Garbage_Throws()
    {
        FakeEncryptor encryptor = new();

        WSManTransportException ex = Assert.Throws<WSManTransportException>(
            () => WSManEncryption.Unwrap("not a mime payload"u8.ToArray(), encryptor));

        await Assert.That(ex.Message).Contains("Invalid WSMan encryption payload");
    }
}
