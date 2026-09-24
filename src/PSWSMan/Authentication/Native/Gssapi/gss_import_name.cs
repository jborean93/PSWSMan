using System;

namespace PSWSMan.Authentication.Native;

using unsafe ImportNameFn = delegate* unmanaged[Cdecl]<
    uint*,                    // minor_status
    Helpers.gss_buffer_desc*, // input_name_buffer
    void*,                    // input_name_type
    void**,                   // output_name
    uint>;

internal sealed unsafe partial class GssapiProvider
{
    private readonly ImportNameFn _importName =
        (ImportNameFn)GetExport(module, "gss_import_name");

    /// <summary>Converts a printable name into a GSSAPI name object.</summary>
    /// <param name="inputName">The name to import, which only needs to stay valid for the call.</param>
    /// <param name="inputNameType">The encoded OID describing the name's form, empty for <c>GSS_C_NO_OID</c>.</param>
    /// <returns>The handle to the name.</returns>
    /// <exception cref="GSSAPIException">Failed to import the name.</exception>
    public SafeGssapiName ImportName(
        ReadOnlySpan<byte> inputName,
        ReadOnlySpan<byte> inputNameType)
    {
        byte* oidStorage = stackalloc byte[sizeof(Helpers.gss_OID_desc)];
        fixed (byte* namePtr = inputName, nameTypePtr = inputNameType)
        {
            Helpers.gss_buffer_desc nameBuffer = new()
            {
                length = (nuint)inputName.Length,
                value = namePtr,
            };
            void* nameType = WriteOid(oidStorage, nameTypePtr, (uint)inputNameType.Length);

            uint minorStatus;
            void* outputName;
            uint majorStatus = _importName(
                &minorStatus,
                &nameBuffer,
                nameType,
                &outputName);
            if (majorStatus != GSS_S_COMPLETE)
                throw new GSSAPIException(this, majorStatus, minorStatus, "gss_import_name");

            return new SafeGssapiName(this, (IntPtr)outputName);
        }
    }
}
