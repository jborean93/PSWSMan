using System.Runtime.InteropServices;

namespace PSWSMan.Authentication.Native;

internal static partial class Helpers
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct gss_buffer_desc
    {
        public nuint length;
        public void* value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct gss_OID_desc
    {
        public uint length;
        public void* elements;
    }

    // See GssapiProvider.Layouts for why GSS.framework on x86_64 needs pack(2) copies of some structs.
    [StructLayout(LayoutKind.Sequential, Pack = 2)]
    public unsafe struct gss_OID_desc_macos
    {
        public uint length;
        public void* elements;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct gss_OID_set_desc
    {
        public nuint count;
        public void* elements;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct gss_iov_buffer_desc
    {
        public uint type;
        public gss_buffer_desc buffer;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 2)]
    public struct gss_iov_buffer_desc_macos
    {
        public uint type;
        public gss_buffer_desc buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct gss_channel_bindings_struct
    {
        public uint initiator_addrtype;
        public gss_buffer_desc initiator_address;
        public uint acceptor_addrtype;
        public gss_buffer_desc acceptor_address;
        public gss_buffer_desc application_data;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 2)]
    public struct gss_channel_bindings_struct_macos
    {
        public uint initiator_addrtype;
        public gss_buffer_desc initiator_address;
        public uint acceptor_addrtype;
        public gss_buffer_desc acceptor_address;
        public gss_buffer_desc application_data;
    }
}

/// <summary>Channel bindings in a layout neutral form, the provider marshals them to its native struct.</summary>
/// <remarks>The pointers must stay valid for the duration of the call they are passed to.</remarks>
internal unsafe struct GssChannelBindings
{
    public uint InitiatorAddrType;
    public byte* InitiatorAddr;
    public int InitiatorLength;
    public uint AcceptorAddrType;
    public byte* AcceptorAddr;
    public int AcceptorLength;
    public byte* ApplicationData;
    public int ApplicationLength;
}

/// <summary>One IOV buffer in a layout neutral form, the provider marshals it to its native struct.</summary>
/// <remarks>
/// After a call the fields reflect what the library set, including pointers to buffers it allocated for entries
/// flagged <c>GSS_IOV_BUFFER_FLAG_ALLOCATE</c>, which must be handed back to <c>ReleaseIovBuffer</c>.
/// </remarks>
internal unsafe struct IOVBuffer
{
    public IOVBufferFlags Flags;
    public IOVBufferType Type;
    public byte* Data;
    public int Length;
}
