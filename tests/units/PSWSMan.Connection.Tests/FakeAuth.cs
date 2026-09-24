using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PSWSMan.Connection.Tests;

/// <summary>Symmetric "encryption" used to exercise the MIME framing without real cryptography.</summary>
/// <remarks>
/// The data is XORed with a key byte. In the default mode the block is the prefix, a 4 byte header and the data
/// like GSSAPI and SSPI. In trailer mode a 3 byte trailer follows the data and the prefix is the trailer length,
/// like CredSSP.
/// </remarks>
internal sealed class FakeEncryptor : IWSManEncryptionContext
{
    public const string Protocol = "application/HTTP-Fake-session-encrypted";
    public static readonly byte[] Header = "HDR!"u8.ToArray();
    public static readonly byte[] Trailer = "TAG"u8.ToArray();

    private readonly byte _key;

    public string EncryptionProtocol => Protocol;

    public int MaxEncryptionChunkSize { get; }

    /// <summary>Whether a trailer follows the data and the length prefix is the trailer length.</summary>
    public bool TrailerMode { get; init; }

    public int Wraps { get; private set; }

    public FakeEncryptor(byte key = 0x5A, int maxChunkSize = -1)
    {
        _key = key;
        MaxEncryptionChunkSize = maxChunkSize;
    }

    private int TrailerLength => TrailerMode ? Trailer.Length : 0;

    public ReadOnlyMemory<byte> WrapWinRM(ReadOnlySpan<byte> data, out int paddingLength)
    {
        Wraps++;
        byte[] block = new byte[4 + Header.Length + data.Length + TrailerLength];
        BinaryPrimitives.WriteInt32LittleEndian(block, TrailerMode ? TrailerLength : Header.Length);
        Header.CopyTo(block, 4);
        for (int i = 0; i < data.Length; i++)
        {
            block[4 + Header.Length + i] = (byte)(data[i] ^ _key);
        }
        if (TrailerMode)
        {
            Trailer.CopyTo(block, block.Length - Trailer.Length);
        }

        paddingLength = 0;
        return block;
    }

    public Span<byte> UnwrapWinRM(Span<byte> block)
    {
        int prefix = BinaryPrimitives.ReadInt32LittleEndian(block);
        if (prefix != (TrailerMode ? TrailerLength : Header.Length))
        {
            throw new InvalidOperationException($"Fake encryption prefix {prefix} mismatch");
        }

        Span<byte> wrapped = block[4..];
        if (!wrapped[..Header.Length].SequenceEqual(Header))
        {
            throw new InvalidOperationException("Fake encryption header mismatch");
        }
        if (TrailerMode && !wrapped[^Trailer.Length..].SequenceEqual(Trailer))
        {
            throw new InvalidOperationException("Fake encryption trailer mismatch");
        }

        Span<byte> data = wrapped.Slice(Header.Length, wrapped.Length - Header.Length - TrailerLength);
        for (int i = 0; i < data.Length; i++)
        {
            data[i] ^= _key;
        }
        return data;
    }
}

/// <summary>A stand-in credential whose contexts support encryption, used where a capable credential is needed.</summary>
internal sealed class FakeNegoCredential : IWSManCredential
{
    public const string Label = "FakeNego";


    /// <summary>How many client tokens are needed before the context is complete.</summary>
    public int Rounds { get; }

    /// <summary>Every context created from this credential, in creation order.</summary>
    public List<FakeNegoContext> Contexts { get; } = new();

    public FakeNegoCredential(int rounds = 2)
    {
        Rounds = rounds;
    }

    public IWSManAuthenticationContext CreateAuthContext(X509Certificate2? serverCertificate)
    {
        FakeNegoContext context = new(Rounds) { ChannelBindingThumbprint = serverCertificate?.Thumbprint };
        lock (Contexts)
        {
            Contexts.Add(context);
        }
        return context;
    }

    public void Dispose()
    { }
}

internal sealed class FakeNegoContext : IWSManAuthenticationContext, IWSManEncryptionContext
{
    private readonly int _rounds;
    private readonly FakeEncryptor _encryptor = new();
    private int _step;

    public bool Complete => _step >= _rounds;

    public bool ExchangesTokens => true;

    public string HttpAuthLabel => FakeNegoCredential.Label;

    public string? AuthenticationStage => $"step {_step}";

    public string EncryptionProtocol => _encryptor.EncryptionProtocol;

    public int MaxEncryptionChunkSize => _encryptor.MaxEncryptionChunkSize;

    /// <summary>The server tokens received by <see cref="Step"/>.</summary>
    public List<string> ReceivedTokens { get; } = new();

    /// <summary>The thumbprint of the server certificate handed over for channel binding.</summary>
    public string? ChannelBindingThumbprint { get; init; }

    public bool Disposed { get; private set; }

    public FakeNegoContext(int rounds)
    {
        _rounds = rounds;
    }

    public byte[]? Step(Span<byte> inToken)
    {
        if (Complete)
        {
            throw new InvalidOperationException("Step called on a completed context");
        }

        if (!inToken.IsEmpty)
        {
            ReceivedTokens.Add(Encoding.ASCII.GetString(inToken));
        }

        _step++;
        return Encoding.ASCII.GetBytes($"C{_step}");
    }

    public ReadOnlyMemory<byte> WrapWinRM(ReadOnlySpan<byte> data, out int paddingLength)
        => _encryptor.WrapWinRM(data, out paddingLength);

    public Span<byte> UnwrapWinRM(Span<byte> block) => _encryptor.UnwrapWinRM(block);

    public void Dispose()
    {
        Disposed = true;
    }
}
