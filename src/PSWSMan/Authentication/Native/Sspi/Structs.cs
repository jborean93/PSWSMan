using System;
using System.Runtime.InteropServices;

namespace PSWSMan.Authentication.Native;

internal static partial class Helpers
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SEC_CHANNEL_BINDINGS
    {
        public UInt32 dwInitiatorAddrType;
        public UInt32 cbInitiatorLength;
        public UInt32 dwInitiatorOffset;
        public UInt32 dwAcceptorAddrType;
        public UInt32 cbAcceptorLength;
        public UInt32 dwAcceptorOffset;
        public UInt32 cbApplicationDataLength;
        public UInt32 dwApplicationDataOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct SEC_WINNT_AUTH_IDENTITY_W
    {
        public char* User;
        public UInt32 UserLength;
        public char* Domain;
        public UInt32 DomainLength;
        public char* Password;
        public UInt32 PasswordLength;
        public WinNTAuthIdentityFlags Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_INTEGER
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct SecBufferDesc
    {
        public UInt32 ulVersion;
        public UInt32 cBuffers;
        public SecBuffer* pBuffers;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct SecBuffer
    {
        public UInt32 cbBuffer;
        public UInt32 BufferType;
        public byte* pvBuffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecHandle
    {
        public UIntPtr dwLower;
        public UIntPtr dwUpper;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_Sizes
    {
        public UInt32 cbMaxToken;
        public UInt32 cbMaxSignature;
        public UInt32 cbBlockSize;
        public UInt32 cbSecurityTrailer;
    }
}
