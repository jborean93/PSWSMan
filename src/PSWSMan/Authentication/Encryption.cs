using System;

namespace PSWSMan.Authentication;

/// <summary>The known WSMan encryption protocol headers.</summary>
internal static class WSManEncryptionProtocol
{
    public const string KERBEROS = "application/HTTP-Kerberos-session-encrypted";
    public const string SPNEGO = "application/HTTP-SPNEGO-session-encrypted";
    public const string CREDSSP = "application/HTTP-CredSSP-session-encrypted";
}
