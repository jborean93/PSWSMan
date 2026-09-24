using System;

namespace PSWSMan.Authentication.Native;

using unsafe InitSecContextFn = delegate* unmanaged[Cdecl]<
    uint*,                    // minor_status
    void*,                    // initiator_cred_handle
    void**,                   // context_handle
    void*,                    // target_name
    void*,                    // mech_type
    GssapiContextFlags,       // req_flags
    uint,                     // time_req
    void*,                    // input_chan_bindings
    Helpers.gss_buffer_desc*, // input_token
    void**,                   // actual_mech_type
    Helpers.gss_buffer_desc*, // output_token
    GssapiContextFlags*,      // ret_flags
    uint*,                    // time_rec
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly InitSecContextFn _initSecContext =
        (InitSecContextFn)GetExport(module, "gss_init_sec_context");

    /// <summary>Initiates a security context or processes a new token on an existing context.</summary>
    /// <remarks>
    /// The context handle is kept in step with the library on every call, including a failing one where GSSAPI
    /// deletes the context itself. The caller owns <paramref name="outputToken"/> and releases it with
    /// <c>ReleaseBuffer</c> whether the call succeeded or not, an error token can be returned on failure.
    /// </remarks>
    /// <param name="initiatorCred">The credential to use, <c>null</c> for <c>GSS_C_NO_CREDENTIAL</c>.</param>
    /// <param name="context">The context, invalid before the first call and populated by it.</param>
    /// <param name="targetName">The name of the acceptor, for Kerberos this is the SPN.</param>
    /// <param name="mechType">The encoded OID of the mechanism to use, empty for <c>GSS_C_NO_OID</c>.</param>
    /// <param name="reqFlags">The context flags to request.</param>
    /// <param name="timeReq">The requested lifetime of the context in seconds, 0 for the default.</param>
    /// <param name="inputChanBindings">Channel bindings to bind to, <c>null</c> for <c>GSS_C_NO_CHANNEL_BINDINGS</c>.</param>
    /// <param name="inputToken">The token received from the acceptor, empty for the first call.</param>
    /// <param name="actualMechType">
    /// Receives the library owned <c>gss_OID</c> of the mechanism in use, read with <see cref="ReadOid"/>, or
    /// <c>null</c> if not needed.
    /// </param>
    /// <param name="outputToken">Receives the token to send to the acceptor.</param>
    /// <param name="retFlags">Receives the flags the context provides, or <c>null</c> if not needed.</param>
    /// <param name="timeRec">Receives the lifetime of the context in seconds, or <c>null</c> if not needed.</param>
    /// <returns><c>true</c> when the acceptor must send another token, <c>false</c> when the context is established.</returns>
    /// <exception cref="GSSAPIException">Failed to initiate or continue the context.</exception>
    public bool InitSecContext(
        SafeGssapiCred? initiatorCred,
        SafeGssapiSecContext context,
        SafeGssapiName targetName,
        ReadOnlySpan<byte> mechType,
        GssapiContextFlags reqFlags,
        uint timeReq,
        GssChannelBindings* inputChanBindings,
        ReadOnlySpan<byte> inputToken,
        void** actualMechType,
        Helpers.gss_buffer_desc* outputToken,
        GssapiContextFlags* retFlags,
        uint* timeRec)
    {
        using SafeHandleRef credRef = new(initiatorCred);
        using SafeHandleRef contextRef = new(context);
        using SafeHandleRef targetRef = new(targetName);

        byte* oidStorage = stackalloc byte[sizeof(Helpers.gss_OID_desc)];
        byte* bindingsStorage = stackalloc byte[sizeof(Helpers.gss_channel_bindings_struct)];
        fixed (byte* mechPtr = mechType, tokenPtr = inputToken)
        {
            void* mech = WriteOid(oidStorage, mechPtr, (uint)mechType.Length);
            void* bindings = WriteChannelBindings(bindingsStorage, inputChanBindings);
            Helpers.gss_buffer_desc tokenBuffer = new()
            {
                length = (nuint)inputToken.Length,
                value = tokenPtr,
            };

            void* contextHandle = contextRef.Pointer;
            uint minorStatus;
            uint majorStatus = _initSecContext(
                &minorStatus,
                credRef.Pointer,
                &contextHandle,
                targetRef.Pointer,
                mech,
                reqFlags,
                timeReq,
                bindings,
                inputToken.Length > 0 ? &tokenBuffer : null,
                actualMechType,
                outputToken,
                retFlags,
                timeRec);

            context.SetContextHandle((IntPtr)contextHandle);

            if (majorStatus != GSS_S_COMPLETE && majorStatus != GSS_S_CONTINUE_NEEDED)
                throw new GSSAPIException(this, majorStatus, minorStatus, "gss_init_sec_context");

            return majorStatus == GSS_S_CONTINUE_NEEDED;
        }
    }
}
