using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace PSWSMan.Connection;

/// <summary>The framing used to copy a file through the stdin or stdout of a WinRS command.</summary>
/// <remarks>
/// A file is sent as its length, a little endian 64-bit integer, then exactly that many bytes of content, then the
/// SHA256 hash of the content. The receiver writes the content somewhere temporary and only keeps it once the length
/// and hash match. The PowerShell scripts that run on the remote host implement the same framing.
/// Compression is a Deflate stream over the whole framed content, it ends where stdin or stdout is closed so it needs
/// no framing of its own, and the length and hash still cover the uncompressed content.
/// </remarks>
internal static class WinRSFileTransfer
{
    /// <summary>The number of bytes in the length prefix.</summary>
    public const int HeaderLength = 8;

    /// <summary>The number of bytes in the trailing SHA256 hash.</summary>
    public const int HashLength = 32;

    /// <summary>Reads a file and splits the framed content into chunks.</summary>
    /// <param name="source">The stream to read the content from.</param>
    /// <param name="length">The number of bytes to read from <paramref name="source"/>.</param>
    /// <param name="chunkSize">The maximum size of each chunk.</param>
    /// <returns>The framed content in order, every chunk is a new array.</returns>
    /// <exception cref="EndOfStreamException"><paramref name="source"/> ended before <paramref name="length"/> bytes.</exception>
    public static IEnumerable<byte[]> ReadFramedChunks(Stream source, long length, int chunkSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        ArgumentOutOfRangeException.ThrowIfLessThan(chunkSize, 1);

        return ReadFramedChunksIterator(source, length, chunkSize);
    }

    /// <summary>Compresses a sequence of chunks as one Deflate stream.</summary>
    /// <param name="chunks">The data to compress.</param>
    /// <param name="chunkSize">The maximum size of each compressed chunk.</param>
    /// <returns>The compressed data in order, no chunk is empty.</returns>
    public static IEnumerable<byte[]> Deflate(IEnumerable<byte[]> chunks, int chunkSize)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(chunkSize, 1);

        return DeflateIterator(chunks, chunkSize);
    }

    private static IEnumerable<byte[]> DeflateIterator(IEnumerable<byte[]> chunks, int chunkSize)
    {
        using MemoryStream compressed = new();
        using (DeflateStream deflate = new(compressed, CompressionLevel.Optimal, leaveOpen: true))
        {
            foreach (byte[] chunk in chunks)
            {
                deflate.Write(chunk);
                if (compressed.Length >= chunkSize)
                {
                    foreach (byte[] output in TakeChunks(compressed, chunkSize, all: false))
                    {
                        yield return output;
                    }
                }
            }
        }

        foreach (byte[] output in TakeChunks(compressed, chunkSize, all: true))
        {
            yield return output;
        }
    }

    /// <summary>Takes whole chunks, or everything when all is set, out of the buffer and keeps the rest.</summary>
    private static List<byte[]> TakeChunks(MemoryStream buffer, int chunkSize, bool all)
    {
        List<byte[]> chunks = [];
        ReadOnlySpan<byte> data = buffer.GetBuffer().AsSpan(0, (int)buffer.Length);
        while (data.Length >= chunkSize || (all && data.Length > 0))
        {
            int length = Math.Min(chunkSize, data.Length);
            chunks.Add(data[..length].ToArray());
            data = data[length..];
        }

        byte[] rest = data.ToArray();
        buffer.SetLength(0);
        buffer.Write(rest);
        return chunks;
    }

    private static IEnumerable<byte[]> ReadFramedChunksIterator(Stream source, long length, int chunkSize)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        byte[] chunk = new byte[chunkSize];
        int filled = 0;
        long remaining = length;
        int headerOffset = 0;
        int trailerOffset = 0;

        while (true)
        {
            if (headerOffset < HeaderLength)
            {
                int count = CopyHeader(length, headerOffset, chunk.AsSpan(filled));
                headerOffset += count;
                filled += count;
            }
            else if (remaining > 0)
            {
                int count = (int)Math.Min(remaining, chunk.Length - filled);
                int read = source.Read(chunk, filled, count);
                if (read == 0)
                {
                    throw new EndOfStreamException(
                        $"The source ended {remaining} bytes before the expected length of {length} bytes.");
                }
                hash.AppendData(chunk, filled, read);
                remaining -= read;
                filled += read;
            }
            else if (trailerOffset < HashLength)
            {
                int count = CopyTrailer(hash, trailerOffset, chunk.AsSpan(filled));
                trailerOffset += count;
                filled += count;
            }
            else
            {
                break;
            }

            if (filled == chunk.Length)
            {
                yield return chunk;
                chunk = new byte[chunkSize];
                filled = 0;
            }
        }

        if (filled > 0)
        {
            yield return chunk.AsSpan(0, filled).ToArray();
        }
    }

    // Iterators cannot hold a span so the fixed size header and trailer are built on the stack in these helpers.
    /// <summary>Copies as much of the length prefix from the offset as fits into the destination.</summary>
    private static int CopyHeader(long length, int offset, Span<byte> destination)
    {
        Span<byte> header = stackalloc byte[HeaderLength];
        BinaryPrimitives.WriteInt64LittleEndian(header, length);

        return CopyPart(header, offset, destination);
    }

    /// <summary>Copies as much of the content hash from the offset as fits into the destination.</summary>
    /// <remarks>The hash is not reset so a trailer split over two chunks gets the same value both times.</remarks>
    private static int CopyTrailer(IncrementalHash hash, int offset, Span<byte> destination)
    {
        Span<byte> trailer = stackalloc byte[HashLength];
        hash.GetCurrentHash(trailer);

        return CopyPart(trailer, offset, destination);
    }

    private static int CopyPart(ReadOnlySpan<byte> source, int offset, Span<byte> destination)
    {
        int count = Math.Min(source.Length - offset, destination.Length);
        source.Slice(offset, count).CopyTo(destination);
        return count;
    }
}

/// <summary>Parses framed file content written by the sender, see <see cref="WinRSFileTransfer"/>.</summary>
/// <remarks>
/// <see cref="Write"/> never throws for bad framing so the caller can keep draining the command's output, the
/// problem is reported by <see cref="Complete"/> instead.
/// </remarks>
internal sealed class WinRSFileTransferReader : IDisposable
{
    private readonly Stream _destination;
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly byte[] _header = new byte[WinRSFileTransfer.HeaderLength];
    private readonly byte[] _expectedHash = new byte[WinRSFileTransfer.HashLength];
    private int _headerFilled;
    private int _hashFilled;
    private long _remaining;
    private string? _error;

    /// <summary>Creates a reader that writes the file content to a stream.</summary>
    /// <param name="destination">The stream that receives the content, it is not disposed by the reader.</param>
    public WinRSFileTransferReader(Stream destination)
    {
        _destination = destination;
    }

    /// <summary>The length of the file, null until the length prefix has been read.</summary>
    public long? Length { get; private set; }

    /// <summary>The number of content bytes written to the destination.</summary>
    public long BytesWritten { get; private set; }

    /// <summary>Processes the next piece of the framed content.</summary>
    /// <param name="data">The data as received.</param>
    public void Write(ReadOnlySpan<byte> data)
    {
        while (data.Length > 0 && _error is null)
        {
            if (_headerFilled < _header.Length)
            {
                int count = Math.Min(_header.Length - _headerFilled, data.Length);
                data[..count].CopyTo(_header.AsSpan(_headerFilled));
                _headerFilled += count;
                data = data[count..];

                if (_headerFilled == _header.Length)
                {
                    long length = BinaryPrimitives.ReadInt64LittleEndian(_header);
                    if (length < 0)
                    {
                        _error = $"The sender reported an invalid file length of {length}.";
                        return;
                    }
                    Length = length;
                    _remaining = length;
                }
            }
            else if (_remaining > 0)
            {
                int count = (int)Math.Min(_remaining, data.Length);
                ReadOnlySpan<byte> content = data[..count];
                _hash.AppendData(content);
                _destination.Write(content);
                _remaining -= count;
                BytesWritten += count;
                data = data[count..];
            }
            else if (_hashFilled < _expectedHash.Length)
            {
                int count = Math.Min(_expectedHash.Length - _hashFilled, data.Length);
                data[..count].CopyTo(_expectedHash.AsSpan(_hashFilled));
                _hashFilled += count;
                data = data[count..];
            }
            else
            {
                _error = $"The sender wrote {data.Length} more bytes after the end of the file.";
            }
        }
    }

    /// <summary>Checks that the whole file was received and that it matches the sender's hash.</summary>
    /// <exception cref="InvalidDataException">The content is incomplete, malformed, or does not match the hash.</exception>
    public void Complete()
    {
        if (_error is not null)
        {
            throw new InvalidDataException(_error);
        }
        if (Length is null || _remaining > 0 || _hashFilled < _expectedHash.Length)
        {
            string received = Length is null ? "before the file length" : $"{BytesWritten} of {Length} bytes";
            throw new InvalidDataException($"The file content ended early, received {received}.");
        }

        Span<byte> actual = stackalloc byte[WinRSFileTransfer.HashLength];
        _hash.GetHashAndReset(actual);
        if (!CryptographicOperations.FixedTimeEquals(actual, _expectedHash))
        {
            throw new InvalidDataException(
                $"The SHA256 hash of the received content {Convert.ToHexString(actual)} does not match the " +
                $"sender's hash {Convert.ToHexString(_expectedHash)}.");
        }
    }

    /// <summary>Releases the hash state.</summary>
    public void Dispose()
    {
        _hash.Dispose();
    }
}
