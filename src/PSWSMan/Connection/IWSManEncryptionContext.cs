using System;

namespace PSWSMan.Connection;

/// <summary>
/// Implemented by authentication contexts that can wrap and unwrap WSMan messages for HTTP message encryption.
/// </summary>
/// <remarks>
/// <para>
/// A wrapped chunk is a block of <c>[4 byte LE length prefix][header][encrypted data][trailer]</c>. What goes in
/// each part and what the prefix counts differs per mechanism, GSSAPI and SSPI put their signature in the header
/// while TLS based CredSSP has a record header in front and the tag behind, so the context builds the whole block
/// itself and the caller only frames it.
/// </para>
/// <para>
/// Decryption is in place. The complete block including the prefix is handed over as one span and the plaintext
/// is returned as a slice of it.
/// </para>
/// </remarks>
internal interface IWSManEncryptionContext
{
    /// <summary>The WSMan encryption protocol used by this auth context, sent as the MIME Content-Type.</summary>
    string EncryptionProtocol { get; }

    /// <summary>The max size of data that can be encrypted in one call. Use -1 to set no limit.</summary>
    int MaxEncryptionChunkSize { get; }

    /// <summary>Wraps a chunk into a complete WinRM block.</summary>
    /// <param name="data">The plaintext to encrypt.</param>
    /// <param name="paddingLength">
    /// The number of padding bytes the mechanism counts against the plaintext length. They are reported in the MIME
    /// OriginalContent length but are not part of the block, matching the Windows client.
    /// </param>
    /// <returns>
    /// The block including the 4 byte length prefix. It may be a slice of a larger buffer the context allocated, the
    /// caller only reads it.
    /// </returns>
    ReadOnlyMemory<byte> WrapWinRM(ReadOnlySpan<byte> data, out int paddingLength);

    /// <summary>Decrypts a complete block in place.</summary>
    /// <param name="block">The block including the 4 byte length prefix, mutated by the decryption.</param>
    /// <returns>The slice of <paramref name="block"/> holding the plaintext.</returns>
    Span<byte> UnwrapWinRM(Span<byte> block);
}
