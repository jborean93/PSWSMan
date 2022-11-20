using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan;

/// <summary>Used as an in memory BIO stream for SslStream.</summary>
internal class TlsBIOStream : Stream
{
    // Max TLS record size is 16KiB + 2KiB extra info.
    private readonly byte[] _incomingBuffer = new byte[18432];
    private readonly byte[] _outgoingBuffer = new byte[18432];
    private readonly BlockingCollection<(int, int)> _incoming = new();
    private readonly BlockingCollection<(int, int)> _outgoing = new();

    /// <summary>The buffer used to store incoming data.</summary>
    public byte[] IncomingBuffer => _incomingBuffer;

    /// <summary>The buffer used to store outgoing data.</summary>
    public byte[] OutgoingBuffer => _outgoingBuffer;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanTimeout => false;

    public override bool CanWrite => true;

    public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

    public override long Length => throw new NotImplementedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotImplementedException();

    public override void SetLength(long value) => throw new NotImplementedException();

    /// <summary>Write data from the client to the outgoing buffer.</summary>
    /// <remarks>
    /// This is called by the SslStream that wraps this stream to write TLS encrypted data to send to the server. Use
    /// the <c>ServerRead</c> method to retrieve this data to send.
    /// </remarks>
    /// <param name="buffer">The data to write.</param>
    /// <param name="offset">The offset in buffer to write from.</param>
    /// <param name="count">The number of bytes from offset to write.</param>
    public override void Write(byte[] buffer, int offset, int count)
    {
        buffer.AsSpan(offset, count).CopyTo(_outgoingBuffer.AsSpan());
        _outgoing.Add((0, count));
    }

    /// <summary>Read data from the incoming buffer to be processed.</summary>
    /// <remarks>
    /// This is called by the SslStream that wraps this stream to read incoming TLS encrypted data from the server. Use
    /// the <c>ServerWrite</c> method to load data to be read and processed.
    /// </remarks>
    /// <param name="buffer">The buffer to read into.</param>
    /// <param name="offset">The offset in buffer to read into.</param>
    /// <param name="count">The maximum amount of bytes to read into the buffer.</param>
    /// <returns>The number of bytes read.</returns>
    public override int Read(byte[] buffer, int offset, int count)
    {
        (int dataOffset, int dataLength) = _incoming.Take();
        int writeLength = Math.Min(count, dataLength);

        _incomingBuffer.AsSpan(dataOffset, dataLength).CopyTo(buffer.AsSpan(offset, count));
        if (count < dataLength)
        {
            _incoming.Add((count, dataLength - count));
        }
        return writeLength;
    }

    public override void Flush()
    { }

    /// <summary>Get data from the outgoing buffer to send to the server.</summary>
    /// <remarks>
    /// This will wait until data has been placed by the SslStream client into the outgoing buffer that needs to be
    /// sent to the server. It will block until either data is available in the outgoing buffer or the passed in
    /// cancellation token is set.
    /// </remarks>
    /// <param name="cancelToken">Token used to cancel the read wait.</param>
    /// <returns>The data from the outgoing buffer that should be sent to the server.</returns>
    public Span<byte> ServerRead(CancellationToken? cancelToken = null)
    {
        (int dataoffset, int dataLength) = _outgoing.Take(cancelToken ?? default);
        return _outgoingBuffer.AsSpan(dataoffset, dataLength);
    }

    /// <summary>Write data from the server into the incoming buffer.</summary>
    /// <remarks>
    /// This will place data into the incoming buffer to be processed by the SslStream client.
    /// </remarks>
    /// <param name="data">The data to write into the incoming buffer.</param>
    public void ServerWrite(ReadOnlySpan<byte> data)
    {
        data.CopyTo(_incomingBuffer.AsSpan());
        MarkIncomingWrite(data.Length);
    }

    /// <summary>Mark the number of bytes placed in the incoming buffer.</summary>
    /// <remarks>
    /// This will notify the SslClient client that the incoming buffer now contains the number of bytes specified. This
    /// is used if the caller has placed data into the incoming buffer array directly and not through
    /// <c>ServerWrite</c>.
    /// </remarks>
    /// <param name="length">The number of bytes in the incoming buffer.</param>
    public void MarkIncomingWrite(int length)
    {
        _incoming.Add((0, length));
    }
}

/// <summary>Wraps the TLS specific components used in CredSSP in an easier helper class.</summary>
internal class TlsSecurityContext : IDisposable
{
    private readonly TlsBIOStream _bio;
    private readonly SslStream _ssl;
    private readonly SslClientAuthenticationOptions _sslOptions;

    /// <summary>Creates the TLS security context.</summary>
    /// <param name="sslOptions">The TLS options to authenticate with.</param>
    public TlsSecurityContext(SslClientAuthenticationOptions sslOptions)
    {
        _bio = new();
        _ssl = new(_bio);
        _sslOptions = sslOptions;
    }

    /// <summary>Starts a TLS handshake and yields each TLS record.</summary>
    /// <remarks>
    /// The caller must call <c>WriteInputToken</c> to have the client process each input token received from the
    /// server before starting the next enumerable entry. Not doing so will cause the code to block indefinitely.
    /// </remarks>
    /// <returns>Each TLS record as a base64 string is yielded until the handshake is complete.</returns>
    public IEnumerable<string> DoHandshake()
    {
        // The handshake operation is done in a background task as .NET doesn't have a non-blocking memory BIO method
        // to perform the handshake in steps. Each of the tokens to exchange are sent to the TlsBIOStream stream that
        // the code can read and write. The cancel token is used to let the code waiting on a BioRead to know when the
        // handshake is completed and no more data is expected or a failure has occurred and to exit early.
        using CancellationTokenSource handshakeDone = new();
        Task handshakeTask = Task.Run(() =>
        {
            try
            {
                _ssl.AuthenticateAsClient(_sslOptions);
            }
            finally
            {
                handshakeDone.Cancel();
            }
        });

        Span<byte> token = _bio.ServerRead(handshakeDone.Token);
        yield return Convert.ToBase64String(token);

        // Keep on exchanging the tokens until the handshake is complete
        while (true)
        {
            ReadOnlySpan<byte> tlsPacket;
            try
            {
                tlsPacket = _bio.ServerRead(handshakeDone.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            yield return Convert.ToBase64String(tlsPacket);
        }

        // Check that no failures occurred when doing the TLS handshake before continuing.
        handshakeTask.GetAwaiter().GetResult();
    }

    /// <summary>Get the peer X.509 certificate sent by the server during the handshake process.</summary
    /// <remarks>This can only be called after the handshake is complete.</remarks>
    /// <returns>The X.509 certificate of the server.</returns>
    public X509Certificate GetRemoteCertificate()
    {
        X509Certificate? cert = _ssl.RemoteCertificate;
        if (cert is null)
        {
            throw new InvalidOperationException("Remote certificate has not been exchanged with the TLS context.");
        }

        return cert;
    }

    /// <summary>Write the input TLS token into the SslStream for processing.</summary>
    /// <param name="token">The TLS record as a base64 string.</param>
    public void WriteInputToken(string token)
    {
        Span<byte> serverBuffer = _bio.IncomingBuffer.AsSpan();
        if (!Convert.TryFromBase64String(token, serverBuffer, out var bytesWritten))
        {
            throw new AuthenticationException("Received input token that is too large to process.");
        }
        _bio.MarkIncomingWrite(bytesWritten);
    }

    /// <summary>Get the processed input token from the server.</summary>
    /// <remarks>This will return the decrypted token passed in from <c>WriteInputToken</c>.</remarks>
    /// <param name="buffer">The buffer to write the processed data to.</param>
    /// <returns>The number of bytes written to the input buffer.</returns>
    public int ReadInputToken(Span<byte> buffer)
    {
        return _ssl.Read(buffer);
    }

    /// <summary>Decrypt data received from the server.</summary>
    /// <remarks>The buffer will be mutated in place.</remarks>
    /// <param name="buffer">The data to decrypt.</param>
    /// <returns>The number of bytes that were decrypted and stored in the buffer.</returns>
    public int Decrypt(Span<byte> buffer)
    {
        _bio.ServerWrite(buffer);
        return _ssl.Read(buffer);
    }

    /// <summary>Encrypt data to send to the server.</summary>
    /// <param name="data">The data to encrypt.</param>
    /// <returns>The data that was encrypted.</returns>
    public Span<byte> Encrypt(ReadOnlySpan<byte> data)
    {
        _ssl.Write(data);
        return _bio.ServerRead();
    }

    /// <summary>Get the size of the TLS trailer for the data being encrypted.</summary>
    /// <param name="dataLength">The number of bytes that will be encrypted.</param>
    /// <returns>The number of bytes of the trailer.</returns>
    public int GetTlsTrailerLength(int dataLength)
    {
        if (_ssl.SslProtocol == SslProtocols.Tls13)
        {
            // The 2 cipher suites MS supports (TLS_AES_*_GCM_SHA*) have a fixed length of 17.
            return 17;
        }
        else if (_ssl.NegotiatedCipherSuite.ToString().Contains("_GCM_"))
        {
            // GCM has a fixed length of 16 bytes
            return 16;
        }

        int hashLength = _ssl.HashAlgorithm switch
        {
            HashAlgorithmType.Md5 => 16,
            HashAlgorithmType.Sha1 => 20,
            HashAlgorithmType.Sha256 => 32,
            HashAlgorithmType.Sha384 => 48,
            _ => throw new NotImplementedException($"Unknown Cipher Suite {_ssl.NegotiatedCipherSuite}"),
        };

        int prepadLength = dataLength + hashLength;
        int paddingLength = _ssl.CipherAlgorithm switch
        {
            CipherAlgorithmType.Rc4 => 0,
            CipherAlgorithmType.Des => 8 - (prepadLength % 8),
            CipherAlgorithmType.TripleDes => 8 - (prepadLength % 8),
            _ => 16 - (prepadLength % 8),
        };

        return prepadLength + paddingLength - dataLength;
    }

    public void Dispose()
    {
        _ssl?.Dispose();
        _bio?.Dispose();
        GC.SuppressFinalize(this);
    }
    ~TlsSecurityContext() { Dispose(); }
}
