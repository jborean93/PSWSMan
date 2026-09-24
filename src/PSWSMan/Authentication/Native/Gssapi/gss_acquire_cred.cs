using System;

namespace PSWSMan.Authentication.Native;

using unsafe AcquireCredFn = delegate* unmanaged[Cdecl]<
    uint*,                      // minor_status
    void*,                      // desired_name
    uint,                       // time_req
    Helpers.gss_OID_set_desc*,  // desired_mechs
    GssapiCredUsage,            // cred_usage
    void**,                     // output_cred_handle
    Helpers.gss_OID_set_desc**, // actual_mechs
    uint*,                      // time_rec
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly AcquireCredFn _acquireCred =
        (AcquireCredFn)GetExport(module, "gss_acquire_cred");

    /// <summary>Acquires a credential handle for an existing principal.</summary>
    /// <param name="desiredName">The principal to get the credential for, <c>null</c> for the default principal.</param>
    /// <param name="timeReq">The requested lifetime of the credential in seconds, 0 for the default.</param>
    /// <param name="desiredMechs">The mechanisms the credential must support, <c>null</c> for the default set.</param>
    /// <param name="credUsage">How the credential will be used.</param>
    /// <param name="actualMechs">
    /// Receives the set of mechanisms the credential supports, or <c>null</c> if not needed. The caller owns the
    /// set and releases it with <c>ReleaseOidSet</c>.
    /// </param>
    /// <param name="timeRec">Receives the lifetime of the credential in seconds, or <c>null</c> if not needed.</param>
    /// <returns>The handle to the credential.</returns>
    /// <exception cref="GSSAPIException">Failed to acquire the credential.</exception>
    public SafeGssapiCred AcquireCred(
        SafeGssapiName? desiredName,
        uint timeReq,
        SafeGssapiOidSet? desiredMechs,
        GssapiCredUsage credUsage,
        Helpers.gss_OID_set_desc** actualMechs,
        uint* timeRec)
    {
        using SafeHandleRef nameRef = new(desiredName);
        using SafeHandleRef mechsRef = new(desiredMechs);

        uint minorStatus;
        void* outputCred;
        uint majorStatus = _acquireCred(
            &minorStatus,
            nameRef.Pointer,
            timeReq,
            mechsRef.As<Helpers.gss_OID_set_desc>(),
            credUsage,
            &outputCred,
            actualMechs,
            timeRec);
        if (majorStatus != GSS_S_COMPLETE)
            throw new GSSAPIException(this, majorStatus, minorStatus, "gss_acquire_cred");

        return new SafeGssapiCred(this, (IntPtr)outputCred);
    }
}
