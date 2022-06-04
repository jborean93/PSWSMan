using System;

namespace PSWSMan;

/// <summary>Interface used for WinRM message encryption.</summary>
internal interface IWinRMEncryptor
{
    /// <summary>The encryption protocol type used in the MIME payload.</summary>
    public abstract string EncryptionProtocol { get; }

    /// <summary>The max size of a WinRM encrypted payload, -1 is no limit.</summary>
    public virtual int MaxEncryptionChunkSize => -1;

    /// <summary>Encrypt the data in the format required by WinRM.</summary>
    /// <remarks>
    /// Some platforms may mutate the input data while others won't. Don't rely on the input data to not change and
    /// always use the return value to reference the newly wrapped data.
    /// </remarks>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="paddingLength">The number of bytes that was appended to the plaintext.</param>
    /// <returns>The WinRM encrypted payload.</returns>
    public abstract byte[] Encrypt(Span<byte> data, out int paddingLength);

    /// <summary>Decrypts the data from a WinRM payload.</summary>
    /// <remarks>
    /// The data is decrypted in place, use the return span to determine the location of the decrypted data.
    /// </remarks>
    /// <param name="data">The WinRM payload to decrypt.</param>
    /// <returns>The span pointing to the decrypted data.</returns>
    public abstract Span<byte> Decrypt(Span<byte> data);
}
