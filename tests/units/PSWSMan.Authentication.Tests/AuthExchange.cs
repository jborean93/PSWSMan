using PSWSMan.Connection;
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PSWSMan.Authentication.Tests;

/// <summary>Helpers that drive a module auth context against the acceptor.</summary>
internal static class AuthExchange
{
    // CredSSP needs the most, a TLS handshake then NTLM then the public key and credential exchanges.
    private const int MaxRounds = 20;

    /// <summary>Runs the token exchange until the client context is complete.</summary>
    /// <returns>The number of tokens the client produced.</returns>
    public static int Authenticate(IWSManAuthenticationContext client, Acceptor acceptor)
    {
        byte[]? inToken = null;
        int rounds = 0;
        while (!client.Complete)
        {
            if (++rounds > MaxRounds)
            {
                throw new InvalidOperationException($"Authentication did not complete after {MaxRounds} rounds");
            }

            byte[]? outToken = client.Step(inToken);
            if (outToken is null || outToken.Length == 0)
            {
                throw new InvalidOperationException(
                    $"Client produced no token on round {rounds} but is not complete ({client.AuthenticationStage})");
            }

            AcceptorStepResult result = acceptor.Step(outToken);
            inToken = result.Token;
        }

        if (inToken is { Length: > 0 })
        {
            throw new InvalidOperationException("Acceptor returned a token after the client completed");
        }

        return rounds;
    }

    /// <summary>Wraps with the client and unwraps with the acceptor, returning what the acceptor recovered.</summary>
    public static byte[] ClientToAcceptorWinRM(IWSManEncryptionContext client, Acceptor acceptor, byte[] plaintext)
    {
        ReadOnlyMemory<byte> block = client.WrapWinRM(plaintext, out int _);

        // The prefix is the header length for NTLM and the trailer length for CredSSP. pyspnego joins the two parts
        // back together for CredSSP so the same split serves both.
        int headerLength = BinaryPrimitives.ReadInt32LittleEndian(block.Span);
        if (headerLength < 0 || headerLength > block.Length - 4)
        {
            throw new InvalidOperationException(
                $"WrapWinRM of {plaintext.Length} bytes produced a {block.Length} byte block with a prefix of {headerLength}");
        }

        byte[] header = block.Span.Slice(4, headerLength).ToArray();
        byte[] data = block.Span[(4 + headerLength)..].ToArray();
        return acceptor.UnwrapWinRM(header, data);
    }

    /// <summary>Wraps with the acceptor and unwraps with the client, returning what the client recovered.</summary>
    public static byte[] AcceptorToClientWinRM(IWSManEncryptionContext client, Acceptor acceptor, byte[] plaintext)
    {
        AcceptorWinRMWrapResult wrapped = acceptor.WrapWinRM(plaintext);

        byte[] block = new byte[4 + wrapped.Header.Length + wrapped.Data.Length];
        BinaryPrimitives.WriteInt32LittleEndian(block, wrapped.Header.Length);
        wrapped.Header.CopyTo(block, 4);
        wrapped.Data.CopyTo(block, 4 + wrapped.Header.Length);

        return client.UnwrapWinRM(block).ToArray();
    }

    /// <summary>Creates a throwaway self signed certificate to derive channel bindings from.</summary>
    public static X509Certificate2 CreateCertificate(string subject = "CN=pswsman-test")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    /// <summary>
    /// The tls-server-end-point binding data for a SHA256 signed certificate, computed here rather than through the
    /// module so the test does not trust the code it is checking.
    /// </summary>
    public static byte[] TlsServerEndPoint(X509Certificate2 certificate)
    {
        byte[] prefix = Encoding.ASCII.GetBytes("tls-server-end-point:");
        byte[] hash = SHA256.HashData(certificate.RawData);
        return [.. prefix, .. hash];
    }
}
