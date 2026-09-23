using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace PSWSMan.Authentication;

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
        if (count == 0)
        {
            return 0;
        }
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

    /// <summary>Get data from the outgoing buffer without blocking.</summary>
    /// <remarks>
    /// Used to retrieve any data that was written by the SslStream client before it finished its operation.
    /// </remarks>
    /// <param name="data">The data from the outgoing buffer that should be sent to the server.</param>
    /// <returns>Whether there was any data in the outgoing buffer.</returns>
    public bool TryServerRead(out byte[] data)
    {
        if (_outgoing.TryTake(out (int, int) entry))
        {
            data = _outgoingBuffer.AsSpan(entry.Item1, entry.Item2).ToArray();
            return true;
        }

        data = Array.Empty<byte>();
        return false;
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
    private bool? _isAeadSuite;
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
    public IEnumerable<byte[]> DoHandshake()
    {
        // The handshake operation is done in a background task as .NET doesn't have a non-blocking memory BIO method
        // to perform the handshake in steps. Each of the tokens to exchange are sent to the TlsBIOStream stream that
        // the code can read and write. The cancel token is used to let the code waiting on a BioRead to know when the
        // handshake is completed and no more data is expected or a failure has occurred and to exit early.
        using CancellationTokenSource handshakeDone = new();
        Task handshakeTask = Task.Run(() =>
        {
            // This class is only used for CredSSP which does not support TLS resume.
            _sslOptions.AllowTlsResume = false;
            try
            {
                _ssl.AuthenticateAsClient(_sslOptions);
            }
            finally
            {
                handshakeDone.Cancel();
            }
        });

        // Keep on exchanging the tokens until the handshake is complete
        while (true)
        {
            byte[] tlsPacket;
            try
            {
                tlsPacket = _bio.ServerRead(handshakeDone.Token).ToArray();
            }
            catch (OperationCanceledException)
            {
                break;
            }

            // A fatal alert means the client has aborted the handshake, wait for it to finish so the local failure
            // is surfaced rather than sending the alert to the server.
            if (IsFatalAlert(tlsPacket))
            {
                CheckHandshakeResult(handshakeTask);
            }

            yield return tlsPacket;
        }

        // Check that no failures occurred when doing the TLS handshake before continuing.
        CheckHandshakeResult(handshakeTask);

        // The handshake may have written its final record, e.g. the TLS 1.3 client Finished, just before it
        // completed. BlockingCollection.Take will fail on a cancelled token even if there is data available so it
        // needs to be retrieved here.
        while (_bio.TryServerRead(out byte[] remaining))
        {
            yield return remaining;
        }
    }

    private static void CheckHandshakeResult(Task handshakeTask)
    {
        try
        {
            handshakeTask.GetAwaiter().GetResult();
        }
        catch (AuthenticationException e)
        {
            // SslStream's message just points to the inner exception, include the actual failure reason.
            throw new AuthenticationException($"TLS handshake failure: {e.InnerException?.Message ?? e.Message}", e);
        }
    }

    private static bool IsFatalAlert(byte[] record)
    {
        // TLS record header
        //   ContentType (1 byte)
        //   Version (2 bytes)
        //   Length (2 bytes)
        // We check for the Alert ContentType (21) and the fatal Alert Level (2).
        return record.Length >= 7 && record[0] == 21 && record[5] == 2;
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
    public void WriteInputToken(Span<byte> token)
    {
        token.CopyTo(_bio.IncomingBuffer.AsSpan());
        _bio.MarkIncomingWrite(token.Length);
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
    /// <param name="trailerLength">
    /// The number of bytes that follow the encrypted data in the record, which is what WinRM expects as the length
    /// prefix of a CredSSP block. AEAD suites have a constant overhead so it is read straight off the record, TLS
    /// 1.3 has no explicit nonce while the TLS 1.2 AEAD suites SChannel offers carry an 8 byte one after the 5 byte
    /// record header. CBC and RC4 suites carry a MAC and length dependent padding instead.
    /// </param>
    /// <returns>The TLS record to send.</returns>
    public Span<byte> Encrypt(ReadOnlySpan<byte> data, out int trailerLength)
    {
        _ssl.Write(data);
        Span<byte> record = _bio.ServerRead();

        trailerLength = IsAeadSuite
            ? record.Length - data.Length - (_ssl.SslProtocol == SslProtocols.Tls13 ? 5 : 13)
            : GetMacTrailerLength(data.Length);

        return record;
    }

    private int GetMacTrailerLength(int dataLength)
    {
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

        return hashLength + paddingLength;
    }

    private bool IsAeadSuite
    {
        get
        {
            if (_isAeadSuite is bool cached)
            {
                return cached;
            }

            bool isAead = _ssl.SslProtocol == SslProtocols.Tls13;
            if (!isAead)
            {
                string suite = _ssl.NegotiatedCipherSuite.ToString();
                isAead = suite.Contains("_GCM_", StringComparison.Ordinal) ||
                    suite.Contains("_CCM", StringComparison.Ordinal) ||
                    suite.Contains("_CHACHA20_", StringComparison.Ordinal);
            }

            _isAeadSuite = isAead;
            return isAead;
        }
    }

    public void Dispose()
    {
        _ssl?.Dispose();
        _bio?.Dispose();
        GC.SuppressFinalize(this);
    }
    ~TlsSecurityContext() { Dispose(); }
}
