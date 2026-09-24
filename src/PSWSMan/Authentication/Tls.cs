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
    // Each incoming token is queued as its own copy. More than one can be waiting, a TLS 1.3 server sends its
    // session tickets after the client Finished and they sit in front of the first application record until the
    // client next reads, so a single shared buffer would be overwritten.
    private readonly BlockingCollection<byte[]> _incoming = new();
    private byte[]? _incomingCurrent;
    private int _incomingOffset;
    private readonly BlockingCollection<byte[]> _outgoing = new();

    /// <summary>The number of bytes left free at the start of each outgoing record array.</summary>
    /// <remarks>
    /// Lets a caller that needs to put something in front of the record, like WinRM's length prefix, have the
    /// SslStream output land directly in its final buffer.
    /// </remarks>
    public int OutgoingPrefix { get; set; }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanTimeout => false;

    public override bool CanWrite => true;

    public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

    public override long Length => throw new NotImplementedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotImplementedException();

    public override void SetLength(long value) => throw new NotImplementedException();

    /// <summary>Write a record from the client to the outgoing queue.</summary>
    /// <remarks>
    /// This is called by the SslStream that wraps this stream to write TLS encrypted data to send to the server. Each
    /// record is copied into its own array, with <see cref="OutgoingPrefix"/> bytes left free in front, and queued
    /// for <c>ServerRead</c> to hand out.
    /// </remarks>
    /// <param name="buffer">The data to write.</param>
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        byte[] record = new byte[OutgoingPrefix + buffer.Length];
        buffer.CopyTo(record.AsSpan(OutgoingPrefix));
        _outgoing.Add(record);
    }

    public override void Write(byte[] buffer, int offset, int count)
        => Write(buffer.AsSpan(offset, count));

    /// <summary>Read data from the incoming queue to be processed.</summary>
    /// <remarks>
    /// This is called by the SslStream that wraps this stream to read incoming TLS encrypted data from the server. Use
    /// the <c>ServerWrite</c> method to load data to be read and processed. A read never spans two queued tokens,
    /// the SslStream keeps reading until it has a whole record so a token split over several reads is fine. It
    /// blocks when the queue is empty, which only the handshake relies on.
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

        if (_incomingCurrent is null || _incomingOffset >= _incomingCurrent.Length)
        {
            _incomingCurrent = _incoming.Take();
            _incomingOffset = 0;
        }

        int readLength = Math.Min(count, _incomingCurrent.Length - _incomingOffset);
        _incomingCurrent.AsSpan(_incomingOffset, readLength).CopyTo(buffer.AsSpan(offset));
        _incomingOffset += readLength;
        return readLength;
    }

    public override void Flush()
    { }

    /// <summary>Get the next record to send to the server.</summary>
    /// <remarks>
    /// This will wait until a record has been written by the SslStream client. It will block until either a record
    /// is available or the passed in cancellation token is set. The array is owned by the caller and starts with
    /// the <see cref="OutgoingPrefix"/> bytes that were in effect when it was written.
    /// </remarks>
    /// <param name="cancelToken">Token used to cancel the read wait.</param>
    /// <returns>The record that should be sent to the server.</returns>
    public byte[] ServerRead(CancellationToken? cancelToken = null)
        => _outgoing.Take(cancelToken ?? default);

    /// <summary>Get the next record to send to the server without blocking.</summary>
    /// <remarks>
    /// Used to retrieve any record that was written by the SslStream client before it finished its operation.
    /// </remarks>
    /// <param name="data">The record that should be sent to the server.</param>
    /// <returns>Whether there was a record waiting.</returns>
    public bool TryServerRead(out byte[] data)
    {
        if (_outgoing.TryTake(out byte[]? record))
        {
            data = record;
            return true;
        }

        data = Array.Empty<byte>();
        return false;
    }

    /// <summary>Queue data from the server for the SslStream client to process.</summary>
    /// <remarks>
    /// The data is copied so the caller's buffer can be reused, including as the destination of the decrypted
    /// output of the very same record.
    /// </remarks>
    /// <param name="data">The data received from the server.</param>
    public void ServerWrite(ReadOnlySpan<byte> data)
    {
        _incoming.Add(data.ToArray());
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
                tlsPacket = _bio.ServerRead(handshakeDone.Token);
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
        _bio.ServerWrite(token);
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
    /// <remarks>
    /// The data must fit in a single TLS record, at most 16KiB, so that one array holds the whole record.
    /// </remarks>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="prefixLength">The number of bytes to leave free in front of the record for the caller.</param>
    /// <param name="trailerLength">
    /// The number of bytes that follow the encrypted data in the record, which is what WinRM expects as the length
    /// prefix of a CredSSP block. AEAD suites have a constant overhead so it is read straight off the record, TLS
    /// 1.3 has no explicit nonce while the TLS 1.2 AEAD suites SChannel offers carry an 8 byte one after the 5 byte
    /// record header. CBC and RC4 suites carry a MAC and length dependent padding instead.
    /// </param>
    /// <returns>A new array holding <paramref name="prefixLength"/> free bytes followed by the TLS record.</returns>
    public byte[] Encrypt(ReadOnlySpan<byte> data, int prefixLength, out int trailerLength)
    {
        // The WinRM framing needs exactly one record per write. SslStream can break that in two ways, a read that
        // processed a post handshake message may have written a reply that is still queued, and a write beyond the
        // maximum message size of the TLS stack is split over several records. Either silently corrupts the stream
        // so both are checked and reported with the sizes involved.
        if (_bio.TryServerRead(out byte[] stale))
        {
            throw new InvalidOperationException(
                $"TLS output had a {stale.Length} byte record queued before encrypting {data.Length} bytes");
        }

        _bio.OutgoingPrefix = prefixLength;
        try
        {
            _ssl.Write(data);
        }
        finally
        {
            _bio.OutgoingPrefix = 0;
        }
        byte[] block = _bio.ServerRead();

        if (_bio.TryServerRead(out byte[] extra))
        {
            throw new InvalidOperationException(
                $"TLS produced more than one record for {data.Length} bytes, the first was {block.Length - prefixLength} bytes and the next {extra.Length}");
        }

        int recordLength = block.Length - prefixLength;
        trailerLength = IsAeadSuite
            ? recordLength - data.Length - (_ssl.SslProtocol == SslProtocols.Tls13 ? 5 : 13)
            : GetMacTrailerLength(data.Length);

        return block;
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

        // The padding always includes its length byte so a full block is added when the data and MAC already fill
        // one. DES and 3DES have an 8 byte block, AES and anything newer 16.
        int prepadLength = dataLength + hashLength;
        int paddingLength = _ssl.CipherAlgorithm switch
        {
            CipherAlgorithmType.Rc4 => 0,
            CipherAlgorithmType.Des => 8 - (prepadLength % 8),
            CipherAlgorithmType.TripleDes => 8 - (prepadLength % 8),
            _ => 16 - (prepadLength % 16),
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
