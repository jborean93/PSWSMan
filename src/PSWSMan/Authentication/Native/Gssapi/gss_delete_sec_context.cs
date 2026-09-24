namespace PSWSMan.Authentication.Native;

using unsafe DeleteSecContextFn = delegate* unmanaged[Cdecl]<
    uint*,                    // minor_status
    void**,                   // context_handle
    Helpers.gss_buffer_desc*, // output_token
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly DeleteSecContextFn _deleteSecContext =
        (DeleteSecContextFn)GetExport(module, "gss_delete_sec_context");

    /// <summary>Deletes a security context.</summary>
    /// <remarks>
    /// This is called from <see cref="SafeGssapiSecContext"/> during release so it reports the status rather than
    /// throwing. The minor status is not reported as nothing acts on it for a release.
    /// </remarks>
    /// <param name="contextHandle">The context to delete, set to <c>GSS_C_NO_CONTEXT</c> on return.</param>
    /// <param name="outputToken">Receives a token to send to the peer, or <c>null</c> for <c>GSS_C_NO_BUFFER</c>.</param>
    /// <returns>The major status, 0 on success.</returns>
    public uint DeleteSecContext(
        void** contextHandle,
        Helpers.gss_buffer_desc* outputToken)
    {
        uint minorStatus;
        return _deleteSecContext(&minorStatus, contextHandle, outputToken);
    }
}
