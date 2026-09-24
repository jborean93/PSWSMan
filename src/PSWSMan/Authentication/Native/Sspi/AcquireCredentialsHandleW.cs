namespace PSWSMan.Authentication.Native;

using unsafe AcquireCredentialsHandleWFn = delegate* unmanaged[Stdcall]<
    char*,                     // pszPrincipal
    char*,                     // pszPackage
    CredentialUse,             // fCredentialUse
    void*,                     // pvLogonId
    void*,                     // pAuthData
    void*,                     // pGetKeyFn
    void*,                     // pvGetKeyArgument
    Helpers.SecHandle*,        // phCredential
    Helpers.SECURITY_INTEGER*, // ptsExpiry
    int>;

internal sealed unsafe partial class SspiProvider
{
    private readonly AcquireCredentialsHandleWFn _acquireCredentialsHandleW =
        (AcquireCredentialsHandleWFn)GetExport(module, "AcquireCredentialsHandleW");

    /// <summary>Acquire SSPI credential.</summary>
    /// <param name="principal">The name of the principal whose credentials the handle will reference.</param>
    /// <param name="package">The name of the SSPI security package the credentials will be used for.</param>
    /// <param name="usage">How the credentials will be used.</param>
    /// <param name="authData">
    /// Package specific authentication data, for example a pinned <see cref="Helpers.SEC_WINNT_AUTH_IDENTITY_W"/>,
    /// or <c>null</c> to use the current user's credentials. It only needs to stay valid for the call.
    /// </param>
    /// <param name="expiry">Receives the time the credential expires, or <c>null</c> if not needed.</param>
    /// <returns>The handle to the credential.</returns>
    /// <exception cref="SspiException">Error when retrieving the credential.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--general">AcquireCredentialsHandle</see>
    public SafeSspiCredentialHandle AcquireCredentialsHandle(
        string? principal,
        string package,
        CredentialUse usage,
        void* authData,
        Helpers.SECURITY_INTEGER* expiry)
    {
        SafeSspiCredentialHandle cred = new(this);
        using SafeHandleRef credRef = new(cred);

        fixed (char* principalPtr = principal, packagePtr = package)
        {
            int res = _acquireCredentialsHandleW(principalPtr, packagePtr, usage, null, authData, null, null,
                credRef.As<Helpers.SecHandle>(), expiry);
            if (res != 0)
            {
                cred.Dispose();
                throw new SspiException(res, "AcquireCredentialsHandle");
            }

            cred.SSPIFree = true;
            return cred;
        }
    }
}
