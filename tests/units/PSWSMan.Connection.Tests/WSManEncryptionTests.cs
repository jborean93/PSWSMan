using System;
using System.IO;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
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

    private static byte[] Bytes(WSManEncryptedContent content)
    {
        // The sync path is what HttpClient.Send uses, the async one must produce the same bytes and both must
        // match the length the content computed for the Content-Length header.
        using MemoryStream sync = new();
        content.CopyTo(sync, null, CancellationToken.None);

        byte[] async = content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        if (!sync.ToArray().AsSpan().SequenceEqual(async))
        {
            throw new InvalidOperationException("Sync and async serialization differ");
        }
        if (content.Headers.ContentLength != async.Length)
        {
            throw new InvalidOperationException(
                $"Content-Length {content.Headers.ContentLength} does not match body length {async.Length}");
        }

        return async;
    }

    private static string Text(WSManEncryptedContent content) => Encoding.Latin1.GetString(Bytes(content));

    private static string ContentType(WSManEncryptedContent content)
    {
        MediaTypeHeaderValue value = content.Headers.ContentType!;
        string protocol = "";
        string boundary = "";
        foreach (NameValueHeaderValue parameter in value.Parameters)
        {
            if (parameter.Name == "protocol")
                protocol = parameter.Value!;
            else if (parameter.Name == "boundary")
                boundary = parameter.Value!;
        }

        return $"{value.MediaType};protocol={protocol};boundary={boundary}";
    }

    [Test]
    public async Task Wrap_HeaderMode_MatchesWinRMFraming()
    {
        FakeEncryptor encryptor = new(key: 0x00);
        byte[] message = "abc"u8.ToArray();

        WSManEncryptedContent payload = WSManEncryption.Wrap(message, encryptor);

        await Assert.That(Text(payload)).IsEqualTo(HeaderModeExpected);
        await Assert.That(ContentType(payload)).IsEqualTo(
            $"multipart/encrypted;protocol=\"{FakeEncryptor.Protocol}\";boundary=\"Encrypted Boundary\"");
        await Assert.That(encryptor.Wraps).IsEqualTo(1);
        await Assert.That(message).IsEquivalentTo("abc"u8.ToArray());
    }

    [Test]
    public async Task Wrap_TrailerMode_PrefixIsTrailerLength()
    {
        FakeEncryptor encryptor = new(key: 0x00) { TrailerMode = true };

        WSManEncryptedContent payload = WSManEncryption.Wrap("abc"u8, encryptor);

        await Assert.That(Text(payload)).IsEqualTo(TrailerModeExpected);
    }

    [Test]
    public async Task Wrap_MultiChunk_UsesMultiEncryptedType()
    {
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: 2);

        WSManEncryptedContent payload = WSManEncryption.Wrap("abcde"u8, encryptor);

        string text = Text(payload);
        await Assert.That(ContentType(payload)).StartsWith("multipart/x-multi-encrypted;");
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

        WSManEncryptedContent payload = WSManEncryption.Wrap(message, encryptor);
        byte[] buffer = Bytes(payload);
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
