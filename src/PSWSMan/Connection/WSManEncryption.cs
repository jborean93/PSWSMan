using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Text;

namespace PSWSMan.Connection;

/// <summary>An encrypted HTTP body.</summary>
/// <param name="Payload">The body bytes.</param>
/// <param name="ContentType">The Content-Type header value to send with the payload.</param>
internal readonly record struct WSManEncryptedPayload(byte[] Payload, string ContentType);

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
/// </remarks>
internal static class WSManEncryption
{
    public const string ContentType = "application/soap+xml";
    public const string Boundary = "Encrypted Boundary";
    public const string MultipartEncrypted = "multipart/encrypted";
    public const string MultipartMultiEncrypted = "multipart/x-multi-encrypted";

    private static readonly byte[] s_newLine = "\r\n"u8.ToArray();
    private static readonly byte[] s_lengthLabel = "Length="u8.ToArray();
    private static readonly byte[] s_terminator = Encoding.UTF8.GetBytes($"--{Boundary}--\r\n");

    /// <summary>Wraps the message in the encrypted MIME payload.</summary>
    /// <param name="message">The plaintext message to encrypt.</param>
    /// <param name="encryptor">The context used to encrypt each chunk.</param>
    /// <returns>The MIME payload and its content type.</returns>
    public static WSManEncryptedPayload Wrap(ReadOnlySpan<byte> message, IWSManEncryptionContext encryptor)
    {
        int chunkSize = encryptor.MaxEncryptionChunkSize == -1 ? message.Length : encryptor.MaxEncryptionChunkSize;
        if (chunkSize <= 0)
        {
            chunkSize = Math.Max(message.Length, 1);
        }

        // Each chunk contributes its MIME text and the block the context built, gathered into the body afterwards.
        List<byte[]> parts = new();
        int total = s_terminator.Length;
        int chunkCount = 0;

        ReadOnlySpan<byte> remaining = message;
        do
        {
            int length = Math.Min(remaining.Length, chunkSize);
            byte[] block = encryptor.WrapWinRM(remaining[..length], out int paddingLength);
            byte[] text = ChunkHeader(encryptor.EncryptionProtocol, length + paddingLength);

            parts.Add(text);
            parts.Add(block);
            total += text.Length + block.Length;
            chunkCount++;

            remaining = remaining[length..];
        }
        while (remaining.Length > 0);

        byte[] payload = new byte[total];
        int position = 0;
        foreach (byte[] part in parts)
        {
            part.CopyTo(payload, position);
            position += part.Length;
        }
        s_terminator.CopyTo(payload, position);

        string subType = chunkCount == 1 ? MultipartEncrypted : MultipartMultiEncrypted;
        string contentType = $"{subType};protocol=\"{encryptor.EncryptionProtocol}\";boundary=\"{Boundary}\"";
        return new(payload, contentType);
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

    private static byte[] ChunkHeader(string protocol, int originalLength)
    {
        string text =
            $"--{Boundary}\r\n" +
            $"Content-Type: {protocol}\r\n" +
            $"OriginalContent: type={ContentType};charset=UTF-8;Length={originalLength}\r\n" +
            $"--{Boundary}\r\n" +
            "Content-Type: application/octet-stream\r\n";

        return Encoding.UTF8.GetBytes(text);
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
