using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace PSWSMan.Connection.Tests;

public class WinRSFileTransferTests
{
    private static byte[] CreateContent(int length)
    {
        byte[] content = new byte[length];
        new Random(length).NextBytes(content);
        return content;
    }

    private static byte[] Frame(byte[] content)
    {
        byte[] framed = new byte[WinRSFileTransfer.HeaderLength + content.Length + WinRSFileTransfer.HashLength];
        BinaryPrimitives.WriteInt64LittleEndian(framed, content.Length);
        content.CopyTo(framed, WinRSFileTransfer.HeaderLength);
        SHA256.HashData(content).CopyTo(framed, WinRSFileTransfer.HeaderLength + content.Length);
        return framed;
    }

    [Test]
    [Arguments(0, 1)]
    [Arguments(0, 40)]
    [Arguments(0, 1024)]
    [Arguments(1, 7)]
    [Arguments(100, 8)]
    [Arguments(100, 64)]
    [Arguments(100, 140)]
    [Arguments(100, 141)]
    [Arguments(65536, 65536)]
    [Arguments(200000, 65536)]
    public async Task ReadFramedChunks_Frames(int length, int chunkSize)
    {
        byte[] content = CreateContent(length);
        using MemoryStream source = new(content);

        byte[][] chunks = [.. WinRSFileTransfer.ReadFramedChunks(source, length, chunkSize)];

        await Assert.That(chunks.Take(chunks.Length - 1).All(c => c.Length == chunkSize)).IsTrue();
        await Assert.That(chunks[^1].Length).IsBetween(1, chunkSize);
        await Assert.That(Convert.ToHexString([.. chunks.SelectMany(c => c)]))
            .IsEqualTo(Convert.ToHexString(Frame(content)));
    }

    [Test]
    public async Task ReadFramedChunks_StopsAtLength()
    {
        byte[] content = CreateContent(100);
        using MemoryStream source = new(content);

        byte[] framed = [.. WinRSFileTransfer.ReadFramedChunks(source, 60, 1024).SelectMany(c => c)];

        await Assert.That(Convert.ToHexString(framed)).IsEqualTo(Convert.ToHexString(Frame(content[..60])));
    }

    [Test]
    public async Task ReadFramedChunks_SourceTooShort()
    {
        using MemoryStream source = new(CreateContent(10));

        await Assert.That(() => WinRSFileTransfer.ReadFramedChunks(source, 20, 1024).ToArray())
            .Throws<EndOfStreamException>();
    }

    [Test]
    public async Task ReadFramedChunks_InvalidArguments()
    {
        using MemoryStream source = new();

        await Assert.That(() => WinRSFileTransfer.ReadFramedChunks(source, -1, 1024))
            .Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => WinRSFileTransfer.ReadFramedChunks(source, 0, 0))
            .Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    [Arguments(0, 1)]
    [Arguments(0, 1000)]
    [Arguments(1, 3)]
    [Arguments(100, 7)]
    [Arguments(100, 1000)]
    [Arguments(200000, 65536)]
    public async Task Reader_RoundTrip(int length, int chunkSize)
    {
        byte[] content = CreateContent(length);
        byte[] framed = Frame(content);
        using MemoryStream destination = new();
        using WinRSFileTransferReader reader = new(destination);

        await Assert.That(reader.Length).IsNull();
        foreach (byte[] chunk in framed.Chunk(chunkSize))
        {
            reader.Write(chunk);
        }
        reader.Complete();

        await Assert.That(reader.Length).IsEqualTo((long?)length);
        await Assert.That(reader.BytesWritten).IsEqualTo((long)length);
        await Assert.That(Convert.ToHexString(destination.ToArray())).IsEqualTo(Convert.ToHexString(content));
    }

    [Test]
    public async Task Reader_LengthKnownAfterHeader()
    {
        byte[] framed = Frame(CreateContent(50));
        using MemoryStream destination = new();
        using WinRSFileTransferReader reader = new(destination);

        reader.Write(framed.AsSpan(0, 7));
        await Assert.That(reader.Length).IsNull();

        reader.Write(framed.AsSpan(7, 1));
        await Assert.That(reader.Length).IsEqualTo((long?)50);
        await Assert.That(reader.BytesWritten).IsEqualTo(0L);
    }

    [Test]
    [Arguments(0)]
    [Arguments(4)]
    [Arguments(8)]
    [Arguments(30)]
    [Arguments(80)]
    public async Task Reader_Truncated(int keep)
    {
        byte[] framed = Frame(CreateContent(50));
        using MemoryStream destination = new();
        using WinRSFileTransferReader reader = new(destination);

        reader.Write(framed.AsSpan(0, keep));

        await Assert.That(reader.Complete).Throws<InvalidDataException>().WithMessageContaining("ended early");
    }

    [Test]
    public async Task Reader_HashMismatch()
    {
        byte[] framed = Frame(CreateContent(50));
        framed[20] ^= 0xFF;
        using MemoryStream destination = new();
        using WinRSFileTransferReader reader = new(destination);

        reader.Write(framed);

        await Assert.That(reader.Complete).Throws<InvalidDataException>().WithMessageContaining("does not match");
    }

    [Test]
    public async Task Reader_ExtraData()
    {
        byte[] framed = [.. Frame(CreateContent(50)), 0x00];
        using MemoryStream destination = new();
        using WinRSFileTransferReader reader = new(destination);

        reader.Write(framed);

        await Assert.That(reader.Complete).Throws<InvalidDataException>().WithMessageContaining("1 more bytes");
    }

    [Test]
    public async Task Reader_NegativeLength()
    {
        byte[] framed = new byte[40];
        BinaryPrimitives.WriteInt64LittleEndian(framed, -1);
        using MemoryStream destination = new();
        using WinRSFileTransferReader reader = new(destination);

        reader.Write(framed);

        await Assert.That(reader.Length).IsNull();
        await Assert.That(destination.Length).IsEqualTo(0L);
        await Assert.That(reader.Complete).Throws<InvalidDataException>().WithMessageContaining("invalid file length");
    }

    private static byte[] Inflate(byte[] compressed)
    {
        using DeflateStream deflate = new(new MemoryStream(compressed), CompressionMode.Decompress);
        using MemoryStream output = new();
        deflate.CopyTo(output);
        return output.ToArray();
    }

    [Test]
    [Arguments(0, 1)]
    [Arguments(100, 7)]
    [Arguments(200000, 1024)]
    [Arguments(200000, 65536)]
    public async Task Deflate_RoundTrip(int length, int chunkSize)
    {
        byte[] content = CreateContent(length);
        using MemoryStream source = new(content);

        byte[][] chunks = [.. WinRSFileTransfer.Deflate(
            WinRSFileTransfer.ReadFramedChunks(source, length, 4096), chunkSize)];

        await Assert.That(chunks.All(c => c.Length > 0 && c.Length <= chunkSize)).IsTrue();
        await Assert.That(Convert.ToHexString(Inflate([.. chunks.SelectMany(c => c)])))
            .IsEqualTo(Convert.ToHexString(Frame(content)));
    }

    [Test]
    public async Task Deflate_Compresses()
    {
        byte[] content = new byte[200000];
        using MemoryStream source = new(content);

        byte[] compressed = [.. WinRSFileTransfer.Deflate(
            WinRSFileTransfer.ReadFramedChunks(source, content.Length, 65536), 65536).SelectMany(c => c)];

        await Assert.That(compressed.Length).IsLessThan(1000);
    }

    [Test]
    public async Task Deflate_EmptyInput()
    {
        byte[] compressed = [.. WinRSFileTransfer.Deflate([], 1024).SelectMany(c => c)];

        await Assert.That(Inflate(compressed).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Deflate_InvalidChunkSize()
    {
        await Assert.That(() => WinRSFileTransfer.Deflate([], 0)).Throws<ArgumentOutOfRangeException>();
    }
}
