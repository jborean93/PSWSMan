using System;
using System.Buffers.Text;
using System.Text;

namespace PSWSMan.Connection;

/// <summary>Builds and parses the multipart/encrypted MIME framing WinRM uses for message level encryption.</summary>
/// <remarks>
/// The .NET MultipartContent format is just different enough from what WinRM expects that the payload is built by
/// hand. The format for each chunk is:
/// <code>
/// --Encrypted Boundary\r\n
/// Content-Type: application/HTTP-SPNEGO-session-encrypted\r\n
/// OriginalContent: type=application/soap+xml;charset=UTF-8;Length=123\r\n
/// --Encrypted Boundary\r\n
/// Content-Type: application/octet-stream\r\n
/// [block built by the encryption context]
/// </code>
/// Chunks follow each other directly and the payload ends with a single <c>--Encrypted Boundary--\r\n</c>.
/// The outgoing body is not gathered into one buffer, <see cref="WSManEncryptedContent"/> writes the parts to the
/// connection stream as they are.
/// </remarks>
internal static class WSManEncryption
{
    public const string ContentType = "application/soap+xml";
    public const string Boundary = "Encrypted Boundary";
    public const string MultipartEncrypted = "multipart/encrypted";
    public const string MultipartMultiEncrypted = "multipart/x-multi-encrypted";

    private static readonly byte[] s_newLine = "\r\n"u8.ToArray();
    private static readonly byte[] s_lengthLabel = "Length="u8.ToArray();

    /// <summary>Wraps the message into the encrypted MIME body.</summary>
    /// <param name="message">The plaintext message to encrypt.</param>
    /// <param name="encryptor">The context used to encrypt each chunk.</param>
    /// <returns>The HTTP content that writes the MIME body, with its Content-Type header set.</returns>
    public static WSManEncryptedContent Wrap(ReadOnlySpan<byte> message, IWSManEncryptionContext encryptor)
    {
        int chunkSize = encryptor.MaxEncryptionChunkSize == -1 ? message.Length : encryptor.MaxEncryptionChunkSize;
        if (chunkSize <= 0)
        {
            chunkSize = Math.Max(message.Length, 1);
        }

        // An empty message still produces one chunk.
        int chunkCount = Math.Max(1, (message.Length + chunkSize - 1) / chunkSize);
        WSManEncryptedChunk[] chunks = new WSManEncryptedChunk[chunkCount];

        ReadOnlySpan<byte> remaining = message;
        for (int i = 0; i < chunks.Length; i++)
        {
            int length = Math.Min(remaining.Length, chunkSize);
            ReadOnlyMemory<byte> block = encryptor.WrapWinRM(remaining[..length], out int paddingLength);
            chunks[i] = new(block, length + paddingLength);

            remaining = remaining[length..];
        }

        return new WSManEncryptedContent(encryptor.EncryptionProtocol, chunks);
    }

    /// <summary>Unwraps an encrypted MIME payload in place.</summary>
    /// <remarks>
    /// Each block is decrypted where it sits and the plaintext is compacted to the start of the payload buffer, so
    /// no second buffer is needed.
    /// </remarks>
    /// <param name="payload">The MIME payload, overwritten with the plaintext.</param>
    /// <param name="encryptor">The context used to decrypt each block.</param>
    /// <returns>The number of plaintext bytes now at the start of <paramref name="payload"/>.</returns>
    /// <exception cref="WSManTransportException">The payload is not in the expected format.</exception>
    public static int Unwrap(Span<byte> payload, IWSManEncryptionContext encryptor)
    {
        // While the boundary text should be derived from the HTTP headers to form '--{boundary}\r\n' some endpoints,
        // like Exchange Servers, put a space after the hyphens to become '-- {boundary}\r\n'. Instead of this just
        // scan up to the first newline and use that value.
        int boundaryEnd = payload.IndexOf(s_newLine);
        if (boundaryEnd == -1)
        {
            throw new WSManTransportException("Invalid WSMan encryption payload - failed to find MIME boundary");
        }
        ReadOnlySpan<byte> boundary = payload[..boundaryEnd].ToArray();

        int position = boundaryEnd + 2;
        int written = 0;

        // The last payload in the MIME will have 2 extra bytes which are disregarded here.
        while (payload.Length - position > 2)
        {
            // First MIME part contains the metadata, including the length of the plaintext data.
            int next = payload[position..].IndexOf(boundary);
            if (next == -1)
            {
                throw new WSManTransportException("Invalid WSMan encryption payload - missing metadata boundary");
            }
            int expectedLength = ParseOriginalLength(payload.Slice(position, next));
            position += next + boundary.Length + 2;

            // Second MIME part contains a known header and the block. Ignore the first Content-Type value and go to
            // the next newline where the block starts.
            next = payload[position..].IndexOf(s_newLine);
            if (next == -1)
            {
                throw new WSManTransportException("Invalid WSMan encryption payload - missing octet-stream header");
            }
            position += next + 2;

            next = payload[position..].IndexOf(boundary);
            if (next == -1 || next < 4)
            {
                throw new WSManTransportException("Invalid WSMan encryption payload - missing data boundary");
            }
            Span<byte> block = payload.Slice(position, next);
            position += next + boundary.Length + 2;

            Span<byte> plaintext = encryptor.UnwrapWinRM(block);
            if (plaintext.Length != expectedLength)
            {
                throw new WSManTransportException("Mismatched WSMan encryption payload length");
            }

            // The plaintext always sits at or after the write position so the overlapping copy is safe.
            plaintext.CopyTo(payload.Slice(written, plaintext.Length));
            written += plaintext.Length;
        }

        return written;
    }

    private static int ParseOriginalLength(ReadOnlySpan<byte> metadata)
    {
        // Case insensitive search for 'Length=' as the header is 'OriginalContent: type=...;Length=123'.
        for (int i = 0; i <= metadata.Length - s_lengthLabel.Length; i++)
        {
            ReadOnlySpan<byte> candidate = metadata.Slice(i, s_lengthLabel.Length);
            if (!Ascii.EqualsIgnoreCase(candidate, s_lengthLabel))
            {
                continue;
            }

            ReadOnlySpan<byte> digits = metadata[(i + s_lengthLabel.Length)..];
            if (Utf8Parser.TryParse(digits, out int length, out int _) && length >= 0)
            {
                return length;
            }
            break;
        }

        throw new WSManTransportException("Invalid WSMan encryption payload - failed to find plaintext length");
    }
}
