using System;

namespace PSWSMan.Authentication.Native;

using unsafe EncryptMessageFn = delegate* unmanaged[Stdcall]<
    Helpers.SecHandle*,     // phContext
    uint,                   // fQOP
    Helpers.SecBufferDesc*, // pMessage
    uint,                   // MessageSeqNo
    int>;

internal sealed unsafe partial class SspiProvider
{
    private readonly EncryptMessageFn _encryptMessage =
        (EncryptMessageFn)GetExport(module, nameof(EncryptMessage));

    /// <summary>Encrypts the input message.</summary>
    /// <remarks>
    /// The message is encrypted in place, use the input message buffers to retrieve the encrypted value.
    /// </remarks>
    /// <param name="context">The SSPI security context to encrypt the message.</param>
    /// <param name="qop">The quality of protection to apply to the message.</param>
    /// <param name="message">The security buffers to encrypt.</param>
    /// <param name="seqNo">The sequence number to apply to the encrypted message.</param>
    /// <exception cref="SspiException">Failure trying to encrypt the message.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--general">EncryptMessage</see>
    public void EncryptMessage(
        SafeSspiContextHandle context,
        uint qop,
        Span<Helpers.SecBuffer> message,
        uint seqNo)
    {
        using SafeHandleRef contextRef = new(context);

        fixed (Helpers.SecBuffer* messagePtr = message)
        {
            Helpers.SecBufferDesc bufferDesc = new()
            {
                ulVersion = 0,
                cBuffers = (uint)message.Length,
                pBuffers = messagePtr,
            };

            int res = _encryptMessage(contextRef.As<Helpers.SecHandle>(), qop, &bufferDesc, seqNo);
            if (res != 0)
                throw new SspiException(res, nameof(EncryptMessage));
        }
    }
}
