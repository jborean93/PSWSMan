using System;

namespace PSWSMan.Authentication.Native;

using unsafe UnwrapFn = delegate* unmanaged[Cdecl]<
    uint*,                    // minor_status
    void*,                    // context_handle
    Helpers.gss_buffer_desc*, // input_message_buffer
    Helpers.gss_buffer_desc*, // output_message_buffer
    int*,                     // conf_state
    uint*,                    // qop_state
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly UnwrapFn _unwrap =
        (UnwrapFn)GetExport(module, "gss_unwrap");

    /// <summary>Unwraps a message from the peer into a new library allocated buffer.</summary>
    /// <param name="context">The context the message was wrapped with.</param>
    /// <param name="inputMessage">The wrapped message, which only needs to stay valid for the call.</param>
    /// <param name="outputMessage">Receives the plaintext, the caller releases it with <c>ReleaseBuffer</c>.</param>
    /// <param name="confState">Receives whether the message was encrypted, or <c>null</c> if not needed.</param>
    /// <param name="qopState">Receives the quality of protection applied, or <c>null</c> if not needed.</param>
    /// <exception cref="GSSAPIException">Failed to unwrap the message.</exception>
    public void Unwrap(
        SafeGssapiSecContext context,
        ReadOnlySpan<byte> inputMessage,
        Helpers.gss_buffer_desc* outputMessage,
        int* confState,
        uint* qopState)
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
            uint majorStatus = _unwrap(
                &minorStatus,
                contextRef.Pointer,
                &inputBuffer,
                outputMessage,
                confState,
                qopState);
            if (majorStatus != GSS_S_COMPLETE)
                throw new GSSAPIException(this, majorStatus, minorStatus, "gss_unwrap");
        }
    }
}
