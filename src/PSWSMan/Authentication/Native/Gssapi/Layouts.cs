using System;
using System.Runtime.InteropServices;

namespace PSWSMan.Authentication.Native;

/// <summary>
/// Marshalling between the layout neutral structs callers use and the provider specific native layouts.
/// </summary>
/// <remarks>
/// GSS.framework on x86_64 macOS is compiled with <c>pack(2)</c> so <c>gss_OID_desc</c>, <c>gss_iov_buffer_desc</c>
/// and <c>gss_channel_bindings_struct</c> have different offsets there than everywhere else. Callers hand over the
/// neutral form and the provider writes the right native layout into stack storage the caller supplies, sized with
/// the natural layout which is never smaller than the packed one.
/// https://github.com/apple-oss-distributions/Heimdal/blob/5a776844a50fc09d714ba82ff7a88973c035b42b/lib/gssapi/gssapi/gssapi.h#L64-L67
/// </remarks>
internal sealed unsafe partial class GssapiProvider
{
    /// <summary>Whether the native structs use <c>pack(2)</c>, only GSS.framework on x86_64 does.</summary>
    public bool IsStructPackTwo { get; } = isGssFramework &&
        RuntimeInformation.ProcessArchitecture is Architecture.X86 or Architecture.X64;

    /// <summary>Reads the bytes of a library owned <c>gss_OID</c>.</summary>
    /// <param name="oid">The <c>gss_OID</c> pointer, <c>null</c> yields an empty span.</param>
    public ReadOnlySpan<byte> ReadOid(void* oid)
    {
        if (oid == null)
        {
            return default;
        }

        if (IsStructPackTwo)
        {
            var native = (Helpers.gss_OID_desc_macos*)oid;
            return new ReadOnlySpan<byte>(native->elements, (int)native->length);
        }
        else
        {
            var native = (Helpers.gss_OID_desc*)oid;
            return new ReadOnlySpan<byte>(native->elements, (int)native->length);
        }
    }

    /// <summary>Writes a <c>gss_OID_desc</c> into <paramref name="storage"/> and returns it as a <c>gss_OID</c>.</summary>
    /// <param name="storage">At least <c>sizeof(gss_OID_desc)</c> bytes of caller owned memory.</param>
    /// <param name="elements">The encoded OID bytes, <c>null</c> yields <c>GSS_C_NO_OID</c>.</param>
    /// <param name="length">The number of OID bytes.</param>
    private void* WriteOid(void* storage, byte* elements, uint length)
    {
        if (elements == null)
        {
            return null;
        }

        if (IsStructPackTwo)
        {
            var native = (Helpers.gss_OID_desc_macos*)storage;
            native->length = length;
            native->elements = elements;
        }
        else
        {
            var native = (Helpers.gss_OID_desc*)storage;
            native->length = length;
            native->elements = elements;
        }

        return storage;
    }

    /// <summary>Writes the IOV buffers into <paramref name="storage"/> as a native <c>gss_iov_buffer_desc</c> array.</summary>
    /// <param name="storage">At least <c>sizeof(gss_iov_buffer_desc) * iov.Length</c> bytes of caller owned memory.</param>
    private void WriteIov(void* storage, ReadOnlySpan<IOVBuffer> iov)
    {
        if (IsStructPackTwo)
        {
            var native = (Helpers.gss_iov_buffer_desc_macos*)storage;
            for (int i = 0; i < iov.Length; i++)
            {
                native[i].type = (uint)iov[i].Type | (uint)iov[i].Flags;
                native[i].buffer.length = (nuint)iov[i].Length;
                native[i].buffer.value = iov[i].Data;
            }
        }
        else
        {
            var native = (Helpers.gss_iov_buffer_desc*)storage;
            for (int i = 0; i < iov.Length; i++)
            {
                native[i].type = (uint)iov[i].Type | (uint)iov[i].Flags;
                native[i].buffer.length = (nuint)iov[i].Length;
                native[i].buffer.value = iov[i].Data;
            }
        }
    }

    /// <summary>Reads the native <c>gss_iov_buffer_desc</c> array back into the IOV buffers after a call.</summary>
    private void ReadIov(void* storage, Span<IOVBuffer> iov)
    {
        if (IsStructPackTwo)
        {
            var native = (Helpers.gss_iov_buffer_desc_macos*)storage;
            for (int i = 0; i < iov.Length; i++)
            {
                iov[i].Flags = (IOVBufferFlags)(native[i].type & 0xFFFF0000);
                iov[i].Type = (IOVBufferType)(native[i].type & 0x0000FFFF);
                iov[i].Data = (byte*)native[i].buffer.value;
                iov[i].Length = (int)native[i].buffer.length;
            }
        }
        else
        {
            var native = (Helpers.gss_iov_buffer_desc*)storage;
            for (int i = 0; i < iov.Length; i++)
            {
                iov[i].Flags = (IOVBufferFlags)(native[i].type & 0xFFFF0000);
                iov[i].Type = (IOVBufferType)(native[i].type & 0x0000FFFF);
                iov[i].Data = (byte*)native[i].buffer.value;
                iov[i].Length = (int)native[i].buffer.length;
            }
        }
    }

    /// <summary>Writes the channel bindings into <paramref name="storage"/> and returns it as a <c>gss_channel_bindings_t</c>.</summary>
    /// <param name="storage">At least <c>sizeof(gss_channel_bindings_struct)</c> bytes of caller owned memory.</param>
    /// <param name="bindings">The bindings, <c>null</c> yields <c>GSS_C_NO_CHANNEL_BINDINGS</c>.</param>
    private void* WriteChannelBindings(void* storage, GssChannelBindings* bindings)
    {
        if (bindings == null)
        {
            return null;
        }

        if (IsStructPackTwo)
        {
            var native = (Helpers.gss_channel_bindings_struct_macos*)storage;
            native->initiator_addrtype = bindings->InitiatorAddrType;
            native->initiator_address.length = (nuint)bindings->InitiatorLength;
            native->initiator_address.value = bindings->InitiatorAddr;
            native->acceptor_addrtype = bindings->AcceptorAddrType;
            native->acceptor_address.length = (nuint)bindings->AcceptorLength;
            native->acceptor_address.value = bindings->AcceptorAddr;
            native->application_data.length = (nuint)bindings->ApplicationLength;
            native->application_data.value = bindings->ApplicationData;
        }
        else
        {
            var native = (Helpers.gss_channel_bindings_struct*)storage;
            native->initiator_addrtype = bindings->InitiatorAddrType;
            native->initiator_address.length = (nuint)bindings->InitiatorLength;
            native->initiator_address.value = bindings->InitiatorAddr;
            native->acceptor_addrtype = bindings->AcceptorAddrType;
            native->acceptor_address.length = (nuint)bindings->AcceptorLength;
            native->acceptor_address.value = bindings->AcceptorAddr;
            native->application_data.length = (nuint)bindings->ApplicationLength;
            native->application_data.value = bindings->ApplicationData;
        }

        return storage;
    }
}
