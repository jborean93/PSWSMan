using System;

namespace PSWSMan.Shared.Authentication;

/// <summary>
/// Used by authentication contexts that support WSMan encryption.
/// </summary>
public interface IWSManEncryptionContext
{
    /// <summary>The WSMan encryption protocol used by this auth context.</summary>
    string EncryptionProtocol { get; }

    /// <summary>The max size of data that can be encrypted in one call. Use -1 to set no limit.</summary>
    int MaxEncryptionChunkSize { get; }

    /// <summary>Wraps the data for use with WinRM encryption.</summary>
    /// <remarks>
    /// The input data may be mutated as some providers will encrypt the data in place.
    /// </remarks>
    /// <param name="data">The data to wrap.</param>
    /// <param name="headerLength">The length of the header in the return bytes.</param>
    /// <param name="paddingLength">The number of bytes that was padded to the plaintext during encryption.</param>
    /// <returns>The encrypted bytes including the header.</returns>
    byte[] WrapWinRM(Span<byte> data, out int headerLength, out int paddingLength);

    /// <summary>Unwraps the data from a WinRM exchange.</summary>
    /// <remarks>
    /// The input data will be mutated as the data is decrypted in place.
    /// Use the return value to determine where in input data span the
    /// decrypted data is located.
    /// </remarks>
    /// <param name="data">The data to decrypt, this is the header + data block of data.</param>
    /// <param name="header">The span inside data that is the header.</param>
    /// <param name="encData">The span inside data that is the encrypted data.</param>
    /// <returns>The span pointing to the decrypted data.</returns>
    Span<byte> UnwrapWinRM(Span<byte> data, Span<byte> header, Span<byte> encData);
}

/// <summary>The known WSMan encryption protocol headers.</summary>
public static class WSManEncryptionProtocol
{
    public const string KERBEROS = "application/HTTP-Kerberos-session-encrypted";
    public const string SPNEGO = "application/HTTP-SPNEGO-session-encrypted";
    public const string CREDSSP = "application/HTTP-CredSSP-session-encrypted";
}
