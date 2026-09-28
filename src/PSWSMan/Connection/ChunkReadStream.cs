using System;
using System.IO;

namespace PSWSMan.Connection;

/// <summary>A forward only stream that reads a sequence of chunks, pulling the next one as it is needed.</summary>
internal sealed class ChunkReadStream : Stream
{
    private readonly Func<byte[]?> _next;
    private byte[] _current = [];
    private int _offset;
    private bool _ended;

    /// <summary>Creates the stream.</summary>
    /// <param name="next">Returns the next chunk, or null when there are no more.</param>
    public ChunkReadStream(Func<byte[]?> next)
    {
        _next = next;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        while (_offset == _current.Length)
        {
            if (_ended || buffer.Length == 0)
            {
                return 0;
            }

            byte[]? next = _next();
            if (next is null)
            {
                _ended = true;
                return 0;
            }
            _current = next;
            _offset = 0;
        }

        int count = Math.Min(buffer.Length, _current.Length - _offset);
        _current.AsSpan(_offset, count).CopyTo(buffer);
        _offset += count;
        return count;
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
