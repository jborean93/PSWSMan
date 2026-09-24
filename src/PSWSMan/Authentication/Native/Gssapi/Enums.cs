using System;

namespace PSWSMan.Authentication.Native;

[Flags]
internal enum GssapiContextFlags : uint
{
    GSS_C_DELEG_FLAG = 1,
    GSS_C_MUTUAL_FLAG = 2,
    GSS_C_REPLAY_FLAG = 4,
    GSS_C_SEQUENCE_FLAG = 8,
    GSS_C_CONF_FLAG = 16,
    GSS_C_INTEG_FLAG = 32,
    GSS_C_ANON_FLAG = 64,
    GSS_C_PROT_READY_FLAG = 128,
    GSS_C_TRANS_FLAG = 256,
    GSS_C_DELEG_POLICY_FLAG = 32768,
}

internal enum GssapiCredUsage
{
    GSS_C_BOTH = 0,
    GSS_C_INITIATE = 1,
    GSS_C_ACCEPT = 2,
}

internal enum GssapiStatusType
{
    GSS_C_GSS_CODE = 1,
    GSS_C_MECH_CODE = 2,
}

internal enum IOVBufferType : uint
{
    GSS_IOV_BUFFER_TYPE_EMPTY = 0,
    GSS_IOV_BUFFER_TYPE_DATA = 1,
    GSS_IOV_BUFFER_TYPE_HEADER = 2,
    GSS_IOV_BUFFER_TYPE_MECH_PARAMS = 3,
    GSS_IOV_BUFFER_TYPE_TRAILER = 7,
    GSS_IOV_BUFFER_TYPE_PADDING = 9,
    GSS_IOV_BUFFER_TYPE_STREAM = 10,
    GSS_IOV_BUFFER_TYPE_SIGN_ONLY = 11,
    GSS_IOV_BUFFER_TYPE_MIC_TOKEN = 12,
}

[Flags]
internal enum IOVBufferFlags : uint
{
    NONE = 0x00000000,
    GSS_IOV_BUFFER_FLAG_ALLOCATE = 0x00010000,
    GSS_IOV_BUFFER_FLAG_ALLOCATED = 0x00020000,
}
