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

internal class TlsBIOStream : Stream
{
    // Max TLS record size is 16KiB + 2KiB extra info.
    private readonly byte[] _incomingBuffer = new byte[18432];
    private readonly byte[] _outgoingBuffer = new byte[18432];
    private readonly BlockingCollection<(int, int)> _incoming = new();
    private readonly BlockingCollection<(int, int)> _outgoing = new();

    public byte[] IncomingBuffer => _incomingBuffer;

    public byte[] OutgoingBuffer => _outgoingBuffer;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanTimeout => false;

    public override bool CanWrite => true;

    public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

    public override long Length => throw new NotImplementedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotImplementedException();

    public override void SetLength(long value) => throw new NotImplementedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        buffer.AsSpan(offset, count).CopyTo(_outgoingBuffer.AsSpan());
        _outgoing.Add((0, count));
    }

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

    public Span<byte> ServerRead(CancellationToken? cancelToken = null)
    {
        (int dataoffset, int dataLength) = _outgoing.Take(cancelToken ?? default);
        return _outgoingBuffer.AsSpan(dataoffset, dataLength);
    }

    public void ServerWrite(ReadOnlySpan<byte> data)
    {
        data.CopyTo(_incomingBuffer.AsSpan());
        _incoming.Add((0, data.Length));
    }

    public void MarkIncomingWrite(int length)
    {
        _incoming.Add((0, length));
    }
}

internal class TlsSecurityContext : IDisposable
{
    private readonly TlsBIOStream _bio;
    private readonly SslStream _ssl;
    private readonly SslClientAuthenticationOptions _sslOptions;

    public TlsSecurityContext(SslClientAuthenticationOptions sslOptions)
    {
        _bio = new();
        _ssl = new(_bio);
        _sslOptions = sslOptions;
    }

    public IEnumerable<string> DoHandshake()
    {
        // The handshake operation is done in a background task as .NET doesn't have a non-blocking memory BIO method
        // to perform the handshake in steps. Each of the tokens to exchange are sent to the TlsBIOStream stream that
        // the code can read and write. The cancel token is used to let the code waiting on a BIORead to know when the
        // handshake is completed and no more data is expected.
        using CancellationTokenSource handshakeDone = new();
        Task handshakeTask = Task.Run(() =>
        {
            try
            {
                _ssl.AuthenticateAsClient(_sslOptions);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error {e.Message}");
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

    public X509Certificate GetRemoteCertificate()
    {
        X509Certificate? cert = _ssl.RemoteCertificate;
        if (cert is null)
        {
            throw new InvalidOperationException("Remote certificate has not been exchanged with the TLS context.");
        }

        return cert;
    }

    public void WriteInputToken(string token)
    {
        Span<byte> serverBuffer = _bio.IncomingBuffer.AsSpan();
        if (!Convert.TryFromBase64String(token, serverBuffer, out var bytesWritten))
        {
            throw new AuthenticationException("Received input token that is too large to process.");
        }
        Console.WriteLine($"Input CredSSP token {token}");
        _bio.MarkIncomingWrite(bytesWritten);
    }

    public Span<byte> ReadInputToken(Span<byte> buffer)
    {
        int read = _ssl.Read(buffer);

        return buffer[..read];
    }

    public int Decrypt(Span<byte> buffer)
    {
        _bio.ServerWrite(buffer);
        int read = _ssl.Read(buffer);

        return read;
    }

    public Span<byte> Encrypt(ReadOnlySpan<byte> data)
    {
        _ssl.Write(data);
        return _bio.ServerRead();
    }

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

        return (prepadLength + paddingLength) - dataLength;
    }

    public void Dispose()
    {
        _ssl.Dispose();
        _bio.Dispose();
        GC.SuppressFinalize(this);
    }
    ~TlsSecurityContext() { Dispose(); }
}
