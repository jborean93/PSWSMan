using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PSWSMan.Connection.Tests;

public class ChunkReadStreamTests
{
    private static ChunkReadStream Create(params byte[][] chunks)
    {
        Queue<byte[]> queue = new(chunks);
        return new(() => queue.Count == 0 ? null : queue.Dequeue());
    }

    [Test]
    public async Task Read_ConcatenatesChunks()
    {
        using ChunkReadStream stream = Create([1, 2, 3], [], [4], [5, 6]);
        using MemoryStream output = new();

        stream.CopyTo(output, 2);

        await Assert.That(Convert.ToHexString(output.ToArray())).IsEqualTo("010203040506");
    }

    [Test]
    public async Task Read_ReturnsPartOfAChunk()
    {
        using ChunkReadStream stream = Create([1, 2, 3, 4]);
        byte[] buffer = new byte[3];

        await Assert.That(stream.Read(buffer, 0, 3)).IsEqualTo(3);
        await Assert.That(stream.Read(buffer, 0, 3)).IsEqualTo(1);
        await Assert.That(buffer[0]).IsEqualTo((byte)4);
        await Assert.That(stream.Read(buffer, 0, 3)).IsEqualTo(0);
    }

    [Test]
    public async Task Read_DoesNotPullAfterTheEnd()
    {
        int calls = 0;
        using ChunkReadStream stream = new(() =>
        {
            calls++;
            return null;
        });
        byte[] buffer = new byte[1];

        stream.ReadExactly(buffer, 0, 0);
        await Assert.That(stream.Read(buffer, 0, 1)).IsEqualTo(0);
        await Assert.That(stream.Read(buffer, 0, 1)).IsEqualTo(0);
        await Assert.That(calls).IsEqualTo(1);
    }

    [Test]
    public async Task Stream_IsReadOnlyAndForwardOnly()
    {
        using ChunkReadStream stream = Create();

        await Assert.That(stream.CanRead).IsTrue();
        await Assert.That(stream.CanSeek).IsFalse();
        await Assert.That(stream.CanWrite).IsFalse();
        await Assert.That(() => stream.Length).Throws<NotSupportedException>();
        await Assert.That(() => stream.Position).Throws<NotSupportedException>();
        await Assert.That(() => stream.Write([1], 0, 1)).Throws<NotSupportedException>();
    }
}
