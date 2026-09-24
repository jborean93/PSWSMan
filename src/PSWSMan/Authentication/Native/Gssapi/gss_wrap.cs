using System;

namespace PSWSMan.Authentication.Native;

using unsafe WrapFn = delegate* unmanaged[Cdecl]<
    uint*,                    // minor_status
    void*,                    // context_handle
    int,                      // conf_req_flag
    uint,                     // qop_req
    Helpers.gss_buffer_desc*, // input_message_buffer
    int*,                     // conf_state
    Helpers.gss_buffer_desc*, // output_message_buffer
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly WrapFn _wrap =
        (WrapFn)GetExport(module, "gss_wrap");

    /// <summary>Wraps (signs or encrypts) a message into a new library allocated buffer.</summary>
    /// <param name="context">The context to wrap the message with.</param>
    /// <param name="confReqFlag">Non zero to encrypt the message, 0 to only sign it.</param>
    /// <param name="qopReq">The quality of protection to request, 0 for the default.</param>
    /// <param name="inputMessage">The message to wrap, which only needs to stay valid for the call.</param>
    /// <param name="confState">Receives whether the message was encrypted, or <c>null</c> if not needed.</param>
    /// <param name="outputMessage">Receives the wrapped message, the caller releases it with <c>ReleaseBuffer</c>.</param>
    /// <exception cref="GSSAPIException">Failed to wrap the message.</exception>
    public void Wrap(
        SafeGssapiSecContext context,
        int confReqFlag,
        uint qopReq,
        ReadOnlySpan<byte> inputMessage,
        int* confState,
        Helpers.gss_buffer_desc* outputMessage)
    {
        using SafeHandleRef contextRef = new(context);

        fixed (byte* inputPtr = inputMessage)
        {
            Helpers.gss_buffer_desc inputBuffer = new()
            {
                length = (nuint)inputMessage.Length,
                value = inputPtr,
            };

            uint minorStatus;
            uint majorStatus = _wrap(
                &minorStatus,
                contextRef.Pointer,
                confReqFlag,
                qopReq,
                &inputBuffer,
                confState,
                outputMessage);
            if (majorStatus != GSS_S_COMPLETE)
                throw new GSSAPIException(this, majorStatus, minorStatus, "gss_wrap");
        }
    }
}
