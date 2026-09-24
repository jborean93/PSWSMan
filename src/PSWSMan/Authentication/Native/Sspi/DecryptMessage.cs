using System;

namespace PSWSMan.Authentication.Native;

using unsafe DecryptMessageFn = delegate* unmanaged[Stdcall]<
    Helpers.SecHandle*,     // phContext
    Helpers.SecBufferDesc*, // pMessage
    uint,                   // MessageSeqNo
    uint*,                  // pfQOP
    int>;

internal sealed unsafe partial class SspiProvider
{
    private readonly DecryptMessageFn _decryptMessage =
        (DecryptMessageFn)GetExport(module, nameof(DecryptMessage));

    /// <summary>Decrypts the input message.</summary>
    /// <remarks>
    /// The message is decrypted in place, use the input message buffers to retrieve the decrypted value.
    /// </remarks>
    /// <param name="context">The SSPI security context to decrypt the message.</param>
    /// <param name="message">The security buffers to decrypt.</param>
    /// <param name="seqNo">The expected sequence number of the encrypted message.</param>
    /// <param name="qop">Receives the quality of protection applied to the message, or <c>null</c> if not needed.</param>
    /// <exception cref="SspiException">Failure trying to decrypt the message.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general">DecryptMessage</see>
    public void DecryptMessage(
        SafeSspiContextHandle context,
        Span<Helpers.SecBuffer> message,
        uint seqNo,
        uint* qop)
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

            int res = _decryptMessage(contextRef.As<Helpers.SecHandle>(), &bufferDesc, seqNo, qop);
            if (res != 0)
                throw new SspiException(res, nameof(DecryptMessage));
        }
    }
}
