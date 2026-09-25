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

    private static string Chunk(string metadata, string block, string boundary = "--Encrypted Boundary") =>
        $"{boundary}\r\n" +
        $"Content-Type: {FakeEncryptor.Protocol}\r\n" +
        $"{metadata}\r\n" +
        $"{boundary}\r\n" +
        "Content-Type: application/octet-stream\r\n" +
        block;

    private const string Terminator = "--Encrypted Boundary--\r\n";
    private const string AbcBlock = "\u0004\u0000\u0000\u0000HDR!abc";
    private const string AbcMetadata = "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=3";

    private static WSManTransportException UnwrapThrows(string payload, FakeEncryptor? encryptor = null) =>
        Assert.Throws<WSManTransportException>(
            () => WSManEncryption.Unwrap(Encoding.Latin1.GetBytes(payload), encryptor ?? new FakeEncryptor(key: 0x00)));

    [Test]
    public async Task Wrap_EmptyMessage_ProducesOneEmptyChunk()
    {
        FakeEncryptor encryptor = new(key: 0x00);

        WSManEncryptedContent payload = WSManEncryption.Wrap(ReadOnlySpan<byte>.Empty, encryptor);

        string text = Text(payload);
        await Assert.That(ContentType(payload)).StartsWith("multipart/encrypted;");
        await Assert.That(text).IsEqualTo(
            "--Encrypted Boundary\r\n" +
            "Content-Type: " + FakeEncryptor.Protocol + "\r\n" +
            "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=0\r\n" +
            "--Encrypted Boundary\r\n" +
            "Content-Type: application/octet-stream\r\n" +
            "\u0004\u0000\u0000\u0000HDR!" +
            Terminator);
        await Assert.That(encryptor.Wraps).IsEqualTo(1);
    }

    [Test]
    [Arguments(0)]
    [Arguments(-1)]
    [Arguments(-100)]
    public async Task Wrap_NoChunkLimit_UsesSingleChunk(int maxChunkSize)
    {
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: maxChunkSize);
        byte[] message = new byte[100_000];
        Random.Shared.NextBytes(message);

        WSManEncryptedContent payload = WSManEncryption.Wrap(message, encryptor);

        await Assert.That(ContentType(payload)).StartsWith("multipart/encrypted;");
        await Assert.That(Text(payload)).Contains("Length=100000\r\n");
        await Assert.That(encryptor.Wraps).IsEqualTo(1);
    }

    [Test]
    [Arguments(0)]
    [Arguments(-1)]
    public async Task Wrap_EmptyMessageWithNoChunkLimit_ProducesOneChunk(int maxChunkSize)
    {
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: maxChunkSize);

        WSManEncryptedContent payload = WSManEncryption.Wrap(ReadOnlySpan<byte>.Empty, encryptor);

        await Assert.That(Text(payload)).Contains("Length=0\r\n");
        await Assert.That(encryptor.Wraps).IsEqualTo(1);
    }

    [Test]
    public async Task Wrap_MessageSmallerThanChunk_IsSingleChunk()
    {
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: 10);

        WSManEncryptedContent payload = WSManEncryption.Wrap("abc"u8, encryptor);

        await Assert.That(Text(payload)).IsEqualTo(HeaderModeExpected);
        await Assert.That(ContentType(payload)).StartsWith("multipart/encrypted;");
        await Assert.That(encryptor.Wraps).IsEqualTo(1);
    }

    [Test]
    public async Task Wrap_MessageEqualToChunk_IsSingleChunk()
    {
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: 3);

        WSManEncryptedContent payload = WSManEncryption.Wrap("abc"u8, encryptor);

        await Assert.That(Text(payload)).IsEqualTo(HeaderModeExpected);
        await Assert.That(ContentType(payload)).StartsWith("multipart/encrypted;");
        await Assert.That(encryptor.Wraps).IsEqualTo(1);
    }

    [Test]
    public async Task Wrap_MessageExactMultipleOfChunk_HasNoPartialChunk()
    {
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: 2);

        WSManEncryptedContent payload = WSManEncryption.Wrap("abcd"u8, encryptor);

        string text = Text(payload);
        await Assert.That(ContentType(payload)).StartsWith("multipart/x-multi-encrypted;");
        await Assert.That(text.Split("Length=2\r\n").Length - 1).IsEqualTo(2);
        await Assert.That(text).DoesNotContain("Length=0\r\n");
        await Assert.That(text).Contains("HDR!ab--Encrypted Boundary\r\n");
        await Assert.That(text).Contains("HDR!cd--Encrypted Boundary--\r\n");
        await Assert.That(encryptor.Wraps).IsEqualTo(2);
    }

    [Test]
    public async Task Wrap_ChunkSizeOne_EmitsOneChunkPerByte()
    {
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: 1);

        WSManEncryptedContent payload = WSManEncryption.Wrap("abc"u8, encryptor);

        string text = Text(payload);
        await Assert.That(text.Split("Length=1\r\n").Length - 1).IsEqualTo(3);
        await Assert.That(encryptor.Wraps).IsEqualTo(3);
    }

    [Test]
    public async Task Wrap_MultiChunk_PreservesChunkOrder()
    {
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: 2);

        string text = Text(WSManEncryption.Wrap("abcde"u8, encryptor));

        int ab = text.IndexOf("HDR!ab--", StringComparison.Ordinal);
        int cd = text.IndexOf("HDR!cd--", StringComparison.Ordinal);
        int e = text.IndexOf("HDR!e--", StringComparison.Ordinal);
        await Assert.That(ab).IsGreaterThanOrEqualTo(0);
        await Assert.That(cd).IsGreaterThan(ab);
        await Assert.That(e).IsGreaterThan(cd);
    }

    [Test]
    public async Task Wrap_PaddingIsCountedInOriginalLengthOnly()
    {
        FakeEncryptor encryptor = new(key: 0x00) { PaddingLength = 5 };

        string text = Text(WSManEncryption.Wrap("abc"u8, encryptor));

        // The MIME length includes the padding but the block only holds the 3 bytes of data.
        await Assert.That(text).Contains("Length=8\r\n");
        await Assert.That(text).Contains("\u0004\u0000\u0000\u0000HDR!abc--Encrypted Boundary--\r\n");
    }

    [Test]
    public async Task Wrap_PaddingIsAppliedPerChunk()
    {
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: 2) { PaddingLength = 1 };

        string text = Text(WSManEncryption.Wrap("abc"u8, encryptor));

        await Assert.That(text.Split("Length=3\r\n").Length - 1).IsEqualTo(1);
        await Assert.That(text.Split("Length=2\r\n").Length - 1).IsEqualTo(1);
    }

    [Test]
    public async Task Wrap_ChunksWithDifferentDigitCounts_SizesHeadersCorrectly()
    {
        // The header buffer is sized from the longest length string, a 2 digit chunk followed by a 1 digit one and
        // then a 3 digit message overall exercises the sizing on both serialization paths.
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: 10);
        byte[] message = Encoding.ASCII.GetBytes(new string('x', 19));

        string text = Text(WSManEncryption.Wrap(message, encryptor));

        await Assert.That(text).Contains("Length=10\r\n--Encrypted Boundary\r\n");
        await Assert.That(text).Contains("Length=9\r\n--Encrypted Boundary\r\n");
        await Assert.That(text.Split("--Encrypted Boundary\r\n").Length - 1).IsEqualTo(4);
    }

    [Test]
    [Arguments(1)]
    [Arguments(9)]
    [Arguments(10)]
    [Arguments(99)]
    [Arguments(100)]
    [Arguments(12345)]
    public async Task Wrap_LengthDigits_MatchContentLength(int messageLength)
    {
        FakeEncryptor encryptor = new(key: 0x00);
        byte[] message = new byte[messageLength];

        WSManEncryptedContent payload = WSManEncryption.Wrap(message, encryptor);

        // Bytes() throws if the computed Content-Length does not match what is written.
        await Assert.That(Text(payload)).Contains($"Length={messageLength}\r\n");
    }

    [Test]
    public async Task Wrap_UsesEncryptorProtocol()
    {
        const string protocol = "application/HTTP-Kerberos-session-encrypted";
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: 2) { EncryptionProtocol = protocol };

        WSManEncryptedContent payload = WSManEncryption.Wrap("abc"u8, encryptor);

        string text = Text(payload);
        await Assert.That(ContentType(payload)).IsEqualTo(
            $"multipart/x-multi-encrypted;protocol=\"{protocol}\";boundary=\"Encrypted Boundary\"");
        await Assert.That(text.Split($"Content-Type: {protocol}\r\n").Length - 1).IsEqualTo(2);
        await Assert.That(text).DoesNotContain(FakeEncryptor.Protocol);
    }

    [Test]
    public async Task Wrap_OversizedEncryptorBuffer_WritesOnlyTheBlock()
    {
        FakeEncryptor encryptor = new(key: 0x00, maxChunkSize: 2) { OversizedBuffer = true };

        string text = Text(WSManEncryption.Wrap("abc"u8, encryptor));

        await Assert.That(text).DoesNotContain("?");
        await Assert.That(text).Contains("HDR!ab--Encrypted Boundary\r\n");
        await Assert.That(text).Contains("HDR!c--Encrypted Boundary--\r\n");
    }

    [Test]
    public async Task Wrap_DoesNotModifyInputMessage()
    {
        FakeEncryptor encryptor = new(key: 0x7F, maxChunkSize: 2);
        byte[] message = "abcde"u8.ToArray();

        Bytes(WSManEncryption.Wrap(message, encryptor));

        await Assert.That(message).IsEquivalentTo("abcde"u8.ToArray());
    }

    [Test]
    public async Task Wrap_SerializesRepeatedly()
    {
        WSManEncryptedContent payload = WSManEncryption.Wrap("abc"u8, new FakeEncryptor(key: 0x00));

        string first = Text(payload);
        string second = Text(payload);

        await Assert.That(second).IsEqualTo(first);
        await Assert.That(second).IsEqualTo(HeaderModeExpected);
    }

    [Test]
    public async Task Wrap_SyncSerialize_Cancelled_Throws()
    {
        WSManEncryptedContent payload = WSManEncryption.Wrap("abc"u8, new FakeEncryptor());
        using MemoryStream stream = new();

        OperationCanceledException ex = Assert.Throws<OperationCanceledException>(
            () => payload.CopyTo(stream, null, new CancellationToken(canceled: true)));

        await Assert.That(stream.Length).IsEqualTo(0L);
    }

    [Test]
    public async Task Wrap_AsyncSerialize_Cancelled_Throws()
    {
        WSManEncryptedContent payload = WSManEncryption.Wrap("abc"u8, new FakeEncryptor());
        using MemoryStream stream = new();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => payload.CopyToAsync(stream, new CancellationToken(canceled: true)));
    }

    [Test]
    public async Task Unwrap_EmptyMessage_RoundTrips()
    {
        FakeEncryptor encryptor = new(key: 0x33);

        byte[] buffer = Bytes(WSManEncryption.Wrap(ReadOnlySpan<byte>.Empty, encryptor));
        int length = WSManEncryption.Unwrap(buffer, encryptor);

        await Assert.That(length).IsEqualTo(0);
    }

    [Test]
    public async Task Unwrap_SingleByteChunks_RoundTrips()
    {
        FakeEncryptor encryptor = new(key: 0x33, maxChunkSize: 1) { TrailerMode = true };
        byte[] message = "hello"u8.ToArray();

        byte[] buffer = Bytes(WSManEncryption.Wrap(message, encryptor));
        int length = WSManEncryption.Unwrap(buffer, encryptor);

        await Assert.That(buffer.AsSpan(0, length).ToArray()).IsEquivalentTo(message);
    }

    [Test]
    public async Task Unwrap_ChunksWithDifferentDigitCounts_RoundTrips()
    {
        FakeEncryptor encryptor = new(key: 0x33, maxChunkSize: 10);
        byte[] message = new byte[25];
        Random.Shared.NextBytes(message);

        byte[] buffer = Bytes(WSManEncryption.Wrap(message, encryptor));
        int length = WSManEncryption.Unwrap(buffer, encryptor);

        await Assert.That(length).IsEqualTo(25);
        await Assert.That(buffer.AsSpan(0, length).ToArray()).IsEquivalentTo(message);
    }

    [Test]
    public async Task Unwrap_LargeMessage_RoundTrips()
    {
        FakeEncryptor encryptor = new(key: 0xA5, maxChunkSize: 16384);
        byte[] message = new byte[100_000];
        Random.Shared.NextBytes(message);

        byte[] buffer = Bytes(WSManEncryption.Wrap(message, encryptor));
        int length = WSManEncryption.Unwrap(buffer, encryptor);

        await Assert.That(length).IsEqualTo(message.Length);
        await Assert.That(buffer.AsSpan(0, length).ToArray()).IsEquivalentTo(message);
    }

    [Test]
    public async Task Unwrap_OnlyTerminator_ReturnsZero()
    {
        int length = WSManEncryption.Unwrap(Encoding.Latin1.GetBytes(Terminator), new FakeEncryptor());

        await Assert.That(length).IsEqualTo(0);
    }

    [Test]
    public async Task Unwrap_LowercaseLengthLabel_IsAccepted()
    {
        string payload = Chunk("originalcontent: type=application/soap+xml;charset=UTF-8;length=3", AbcBlock) + Terminator;
        byte[] buffer = Encoding.Latin1.GetBytes(payload);

        int length = WSManEncryption.Unwrap(buffer, new FakeEncryptor(key: 0x00));

        await Assert.That(Encoding.UTF8.GetString(buffer, 0, length)).IsEqualTo("abc");
    }

    [Test]
    public async Task Unwrap_LengthFollowedByOtherParameters_IsAccepted()
    {
        string payload = Chunk("OriginalContent: Length=3;type=application/soap+xml;charset=UTF-8", AbcBlock) + Terminator;
        byte[] buffer = Encoding.Latin1.GetBytes(payload);

        int length = WSManEncryption.Unwrap(buffer, new FakeEncryptor(key: 0x00));

        await Assert.That(Encoding.UTF8.GetString(buffer, 0, length)).IsEqualTo("abc");
    }

    [Test]
    public async Task Unwrap_MetadataWithExtraHeaders_IsAccepted()
    {
        string payload = Chunk(
            "X-Custom: something\r\nOriginalContent: type=application/soap+xml;charset=UTF-8;Length=3\r\nX-Other: 1",
            AbcBlock) + Terminator;
        byte[] buffer = Encoding.Latin1.GetBytes(payload);

        int length = WSManEncryption.Unwrap(buffer, new FakeEncryptor(key: 0x00));

        await Assert.That(Encoding.UTF8.GetString(buffer, 0, length)).IsEqualTo("abc");
    }

    [Test]
    public async Task Unwrap_ExchangeStyleBoundary_MultiChunk()
    {
        string payload =
            Chunk(AbcMetadata, AbcBlock, "-- Encrypted Boundary") +
            Chunk(AbcMetadata.Replace("Length=3", "Length=2"), "\u0004\u0000\u0000\u0000HDR!de", "-- Encrypted Boundary") +
            "-- Encrypted Boundary--\r\n";
        byte[] buffer = Encoding.Latin1.GetBytes(payload);

        int length = WSManEncryption.Unwrap(buffer, new FakeEncryptor(key: 0x00));

        await Assert.That(Encoding.UTF8.GetString(buffer, 0, length)).IsEqualTo("abcde");
    }

    [Test]
    public async Task Unwrap_EmptyPayload_Throws()
    {
        WSManTransportException ex = UnwrapThrows("");

        await Assert.That(ex.Message).Contains("failed to find MIME boundary");
    }

    [Test]
    public async Task Unwrap_NoNewLine_Throws()
    {
        WSManTransportException ex = UnwrapThrows("--Encrypted Boundary");

        await Assert.That(ex.Message).Contains("failed to find MIME boundary");
    }

    [Test]
    public async Task Unwrap_LineFeedOnly_Throws()
    {
        string payload = (Chunk(AbcMetadata, AbcBlock) + Terminator).Replace("\r\n", "\n");

        WSManTransportException ex = UnwrapThrows(payload);

        await Assert.That(ex.Message).Contains("failed to find MIME boundary");
    }

    [Test]
    public async Task Unwrap_MissingMetadataBoundary_Throws()
    {
        // The metadata part never ends with a boundary so the parser cannot find where the block part starts.
        string payload =
            "--Encrypted Boundary\r\n" +
            $"Content-Type: {FakeEncryptor.Protocol}\r\n" +
            AbcMetadata + "\r\n" +
            "Content-Type: application/octet-stream\r\n" +
            AbcBlock;

        WSManTransportException ex = UnwrapThrows(payload);

        await Assert.That(ex.Message).Contains("missing metadata boundary");
    }

    [Test]
    public async Task Unwrap_MissingOctetStreamHeader_Throws()
    {
        string payload =
            "--Encrypted Boundary\r\n" +
            $"Content-Type: {FakeEncryptor.Protocol}\r\n" +
            AbcMetadata + "\r\n" +
            "--Encrypted Boundary\r\n" +
            "Content-Type: application/octet-stream";

        WSManTransportException ex = UnwrapThrows(payload);

        await Assert.That(ex.Message).Contains("missing octet-stream header");
    }

    [Test]
    public async Task Unwrap_MissingDataBoundary_Throws()
    {
        string payload = Chunk(AbcMetadata, AbcBlock);

        WSManTransportException ex = UnwrapThrows(payload);

        await Assert.That(ex.Message).Contains("missing data boundary");
    }

    [Test]
    [Arguments("")]
    [Arguments("\u0004")]
    [Arguments("\u0004\u0000\u0000")]
    public async Task Unwrap_BlockShorterThanPrefix_Throws(string block)
    {
        string payload = Chunk("OriginalContent: type=application/soap+xml;charset=UTF-8;Length=0", block) + Terminator;

        WSManTransportException ex = UnwrapThrows(payload);

        await Assert.That(ex.Message).Contains("missing data boundary");
    }

    [Test]
    [Arguments("OriginalContent: type=application/soap+xml;charset=UTF-8")]
    [Arguments("OriginalContent: type=application/soap+xml;charset=UTF-8;Length=")]
    [Arguments("OriginalContent: type=application/soap+xml;charset=UTF-8;Length=abc")]
    [Arguments("OriginalContent: type=application/soap+xml;charset=UTF-8;Length=-3")]
    [Arguments("OriginalContent: type=application/soap+xml;charset=UTF-8;Length=99999999999")]
    [Arguments("OriginalContent: type=application/soap+xml;charset=UTF-8;Len=3")]
    [Arguments("")]
    public async Task Unwrap_InvalidOriginalLength_Throws(string metadata)
    {
        string payload = Chunk(metadata, AbcBlock) + Terminator;

        WSManTransportException ex = UnwrapThrows(payload);

        await Assert.That(ex.Message).Contains("failed to find plaintext length");
    }

    [Test]
    public async Task Unwrap_LengthTooSmall_Throws()
    {
        string payload = Chunk(AbcMetadata.Replace("Length=3", "Length=2"), AbcBlock) + Terminator;

        WSManTransportException ex = UnwrapThrows(payload);

        await Assert.That(ex.Message).Contains("Mismatched");
    }

    [Test]
    public async Task Unwrap_MismatchInLaterChunk_Throws()
    {
        string payload =
            Chunk(AbcMetadata, AbcBlock) +
            Chunk(AbcMetadata, "\u0004\u0000\u0000\u0000HDR!de") +
            Terminator;

        WSManTransportException ex = UnwrapThrows(payload);

        await Assert.That(ex.Message).Contains("Mismatched");
    }

    [Test]
    public async Task Unwrap_TrailingDataAfterTerminator_Throws()
    {
        string payload = Chunk(AbcMetadata, AbcBlock) + Terminator + "junk";

        WSManTransportException ex = UnwrapThrows(payload);

        await Assert.That(ex.Message).Contains("missing metadata boundary");
    }

    [Test]
    public async Task Unwrap_MissingTerminator_StillReturnsPlaintext()
    {
        // The parser stops when fewer than 3 bytes remain after the last boundary and never checks for the closing
        // '--', so a body that ends on a plain boundary line is accepted as complete.
        string payload = Chunk(AbcMetadata, AbcBlock) + "--Encrypted Boundary\r\n";
        byte[] buffer = Encoding.Latin1.GetBytes(payload);

        int length = WSManEncryption.Unwrap(buffer, new FakeEncryptor(key: 0x00));

        await Assert.That(Encoding.UTF8.GetString(buffer, 0, length)).IsEqualTo("abc");
    }

    [Test]
    public async Task Unwrap_EncryptorFailure_Propagates()
    {
        // The block prefix says the header is 9 bytes so the fake rejects it before any framing check fails.
        string payload = Chunk(AbcMetadata, "\u0009\u0000\u0000\u0000HDR!abc") + Terminator;

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
            () => WSManEncryption.Unwrap(Encoding.Latin1.GetBytes(payload), new FakeEncryptor(key: 0x00)));

        await Assert.That(ex.Message).Contains("prefix");
    }

    [Test]
    public async Task Unwrap_WrongKey_ReturnsGarbageNotError()
    {
        // The framing has no integrity check of its own, a different key just yields different plaintext.
        byte[] buffer = Bytes(WSManEncryption.Wrap("abc"u8, new FakeEncryptor(key: 0x01)));

        int length = WSManEncryption.Unwrap(buffer, new FakeEncryptor(key: 0x02));

        await Assert.That(length).IsEqualTo(3);
        await Assert.That(buffer.AsSpan(0, length).ToArray()).IsEquivalentTo(new byte[] { (byte)'a' ^ 3, (byte)'b' ^ 3, (byte)'c' ^ 3 });
    }

    [Test]
    public async Task Unwrap_ModeMismatch_Throws()
    {
        byte[] buffer = Bytes(WSManEncryption.Wrap("abc"u8, new FakeEncryptor(key: 0x00) { TrailerMode = true }));

        Assert.Throws<InvalidOperationException>(
            () => WSManEncryption.Unwrap(buffer, new FakeEncryptor(key: 0x00)));

        await Task.CompletedTask;
    }
}
