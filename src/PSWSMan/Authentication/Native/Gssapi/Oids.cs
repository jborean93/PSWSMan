namespace PSWSMan.Authentication.Native;

/// <summary>Well known GSSAPI OIDs in their DER encoded form.</summary>
internal static class GssapiOid
{
    // Name Types
    public static readonly byte[] GSS_C_NT_HOSTBASED_SERVICE = new byte[] {
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x01, 0x04
    }; // 1.2.840.113554.1.2.1.4

    public static readonly byte[] GSS_C_NT_USER_NAME = new byte[] {
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x01, 0x01
    }; // 1.2.840.113554.1.2.1.1

    // Mechanisms
    public static readonly byte[] KERBEROS = new byte[] {
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02
    }; // 1.2.840.113554.1.2.2

    public static readonly byte[] NTLM = new byte[] {
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A
    }; // 1.3.6.1.4.1.311.2.2.10

    public static readonly byte[] SPNEGO = new byte[] {
        0x2B, 0x06, 0x01, 0x05, 0x05, 0x02
    }; // 1.3.6.1.5.5.2
}
