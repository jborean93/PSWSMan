using System;
using System.Buffers;
using System.Buffers.Text;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan.Connection;

/// <summary>One encrypted chunk of a WinRM message.</summary>
/// <param name="Block">The wrapped block including its 4 byte length prefix, as built by the encryption context.</param>
/// <param name="OriginalLength">The plaintext length reported in the MIME header, including any padding.</param>
internal readonly record struct WSManEncryptedChunk(ReadOnlyMemory<byte> Block, int OriginalLength);

/// <summary>The multipart/encrypted HTTP body WinRM uses for message level encryption.</summary>
/// <remarks>
/// The chunks are already wrapped when the content is created. Rather than gathering them into one array the body
/// is written part by part straight to the connection stream, so the only copy of the message after encryption is
/// the one into the socket. The chunk headers are formatted into a stack buffer as they are written. The content
/// length is known up front so the request still carries a <c>Content-Length</c>.
/// </remarks>
internal sealed class WSManEncryptedContent : HttpContent
{
    private static readonly byte[] s_headerStart = Encoding.UTF8.GetBytes(
        $"--{WSManEncryption.Boundary}\r\nContent-Type: ");
    private static readonly byte[] s_headerMiddle = Encoding.UTF8.GetBytes(
        $"\r\nOriginalContent: type={WSManEncryption.ContentType};charset=UTF-8;Length=");
    private static readonly byte[] s_headerEnd = Encoding.UTF8.GetBytes(
        $"\r\n--{WSManEncryption.Boundary}\r\nContent-Type: application/octet-stream\r\n");
    private static readonly byte[] s_terminator = Encoding.UTF8.GetBytes(
        $"--{WSManEncryption.Boundary}--\r\n");

    private readonly string _protocol;
    private readonly WSManEncryptedChunk[] _chunks;
    private readonly int _maxHeaderLength;
    private readonly long _length;

    /// <param name="protocol">The encryption protocol sent in each chunk's Content-Type.</param>
    /// <param name="chunks">The wrapped chunks in message order.</param>
    public WSManEncryptedContent(string protocol, WSManEncryptedChunk[] chunks)
    {
        _protocol = protocol;
        _chunks = chunks;

        // The header only varies by the digits of the original length so the size of each is known now.
        int fixedHeaderLength = s_headerStart.Length + Encoding.UTF8.GetByteCount(protocol) +
            s_headerMiddle.Length + s_headerEnd.Length;
        long length = s_terminator.Length;
        foreach (WSManEncryptedChunk chunk in chunks)
        {
            int headerLength = fixedHeaderLength + DigitCount(chunk.OriginalLength);
            _maxHeaderLength = Math.Max(_maxHeaderLength, headerLength);
            length += headerLength + chunk.Block.Length;
        }
        _length = length;

        string subType = chunks.Length == 1
            ? WSManEncryption.MultipartEncrypted
            : WSManEncryption.MultipartMultiEncrypted;
        Headers.TryAddWithoutValidation("Content-Type",
            $"{subType};protocol=\"{protocol}\";boundary=\"{WSManEncryption.Boundary}\"");
    }

    protected override bool TryComputeLength(out long length)
    {
        length = _length;
        return true;
    }

    protected override void SerializeToStream(Stream stream, TransportContext? context,
        CancellationToken cancellationToken)
    {
        Span<byte> header = stackalloc byte[_maxHeaderLength];
        foreach (WSManEncryptedChunk chunk in _chunks)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int written = WriteChunkHeader(header, chunk.OriginalLength);
            stream.Write(header[..written]);
            stream.Write(chunk.Block.Span);
        }
        stream.Write(s_terminator);
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        => SerializeToStreamAsync(stream, context, CancellationToken.None);

    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context,
        CancellationToken cancellationToken)
    {
        // The stack buffer cannot live across an await so the header is formatted into a rented one instead.
        byte[] header = ArrayPool<byte>.Shared.Rent(_maxHeaderLength);
        try
        {
            foreach (WSManEncryptedChunk chunk in _chunks)
            {
                int written = WriteChunkHeader(header, chunk.OriginalLength);
                await stream.WriteAsync(header.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
                await stream.WriteAsync(chunk.Block, cancellationToken).ConfigureAwait(false);
            }
            await stream.WriteAsync(s_terminator, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(header);
        }
    }

    private int WriteChunkHeader(Span<byte> destination, int originalLength)
    {
        int position = 0;

        s_headerStart.CopyTo(destination);
        position += s_headerStart.Length;

        position += Encoding.UTF8.GetBytes(_protocol, destination[position..]);

        s_headerMiddle.CopyTo(destination[position..]);
        position += s_headerMiddle.Length;

        Utf8Formatter.TryFormat(originalLength, destination[position..], out int digits);
        position += digits;

        s_headerEnd.CopyTo(destination[position..]);
        position += s_headerEnd.Length;

        return position;
    }

    private static int DigitCount(int value)
    {
        int digits = 1;
        while (value >= 10)
        {
            value /= 10;
            digits++;
        }

        return digits;
    }
}
