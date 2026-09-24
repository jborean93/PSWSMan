using System;

namespace PSWSMan.Authentication.Native;

using unsafe InitializeSecurityContextWFn = delegate* unmanaged[Stdcall]<
    Helpers.SecHandle*,           // phCredential
    Helpers.SecHandle*,           // phContext
    char*,                        // pszTargetName
    InitiatorContextRequestFlags, // fContextReq
    uint,                         // Reserved1
    TargetDataRep,                // TargetDataRep
    Helpers.SecBufferDesc*,       // pInput
    uint,                         // Reserved2
    Helpers.SecHandle*,           // phNewContext
    Helpers.SecBufferDesc*,       // pOutput
    InitiatorContextReturnFlags*, // pfContextAttr
    Helpers.SECURITY_INTEGER*,    // ptsExpiry
    int>;

internal sealed unsafe partial class SspiProvider
{
    private readonly InitializeSecurityContextWFn _initializeSecurityContextW =
        (InitializeSecurityContextWFn)GetExport(module, "InitializeSecurityContextW");

    /// <summary>Initiates a security context or processes a new token on an existing context.</summary>
    /// <param name="credential">The credential to use for the security context.</param>
    /// <param name="context">
    /// The context handle for the operation. The first call should be set to <c>null</c> and a new handle is
    /// created, subsequent calls use the context returned from the first call.
    /// </param>
    /// <param name="targetName">The target name of the acceptor, for Kerberos this is the SPN.</param>
    /// <param name="contextReq">Request flags to set.</param>
    /// <param name="dataRep">The data representation on the target.</param>
    /// <param name="input">Optional buffers received from the acceptor, empty for the first call.</param>
    /// <param name="output">The output buffers to fill, empty if no output is expected.</param>
    /// <param name="expiry">Receives the time the context expires, or <c>null</c> if not needed.</param>
    /// <returns>Context information including the handle to the context itself.</returns>
    /// <exception cref="SspiException">Failure initiating/continuing the security context.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--general">InitializeSecurityContext</see>
    public SspiSecContext InitializeSecurityContext(
        SafeSspiCredentialHandle credential,
        SafeSspiContextHandle? context,
        string targetName,
        InitiatorContextRequestFlags contextReq,
        TargetDataRep dataRep,
        ReadOnlySpan<Helpers.SecBuffer> input,
        Span<Helpers.SecBuffer> output,
        Helpers.SECURITY_INTEGER* expiry)
    {
        // The first call has no input context and SSPI populates a fresh handle. Subsequent calls pass the same
        // handle for both the input and new context.
        SafeSspiContextHandle newContext = context ?? new SafeSspiContextHandle(this);
        using SafeHandleRef credRef = new(credential);
        using SafeHandleRef contextRef = new(context);
        using SafeHandleRef newContextRef = new(newContext);

        fixed (char* targetPtr = targetName)
        fixed (Helpers.SecBuffer* inputPtr = input, outputPtr = output)
        {
            Helpers.SecBufferDesc inputDesc = new()
            {
                ulVersion = 0,
                cBuffers = (uint)input.Length,
                pBuffers = inputPtr,
            };
            Helpers.SecBufferDesc outputDesc = new()
            {
                ulVersion = 0,
                cBuffers = (uint)output.Length,
                pBuffers = outputPtr,
            };

            InitiatorContextReturnFlags contextAttr;
            int res = _initializeSecurityContextW(
                credRef.As<Helpers.SecHandle>(),
                contextRef.As<Helpers.SecHandle>(),
                targetPtr,
                contextReq,
                0,
                dataRep,
                input.Length > 0 ? &inputDesc : null,
                0,
                newContextRef.As<Helpers.SecHandle>(),
                output.Length > 0 ? &outputDesc : null,
                &contextAttr,
                expiry);

            if (res != 0 && res != SEC_I_CONTINUE_NEEDED)
            {
                if (context is null)
                    newContext.Dispose();

                throw new SspiException(res, "InitializeSecurityContext");
            }

            newContext.SSPIFree = true;
            return new SspiSecContext(newContext, contextAttr, res == SEC_I_CONTINUE_NEEDED);
        }
    }
}
