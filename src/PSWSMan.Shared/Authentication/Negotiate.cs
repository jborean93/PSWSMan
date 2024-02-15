using PSWSMan.Shared.Authentication.Native;
using System;
using System.Runtime.InteropServices;

namespace PSWSMan.Shared.Authentication;

/// <summary>
/// Options to request during the negotiate authentication stepping. The values
/// are based on GSSAPI but are mapped internally to the SSPI equivalents on
/// Windows.
/// </summary>
[Flags]
public enum NegotiateRequestFlags
{
    None = 0x00000000,
    Delegate = 0x00000001,
    MutualAuth = 0x00000002,
    ReplayDetect = 0x00000004,
    SequenceDetect = 0x00000008,
    Confidentiality = 0x00000010,
    Integrity = 0x00000020,
    Anonymous = 0x00000040,
    Identify = 0x00002000,
    DelegatePolicy = 0x00008000,

    Default = NegotiateRequestFlags.MutualAuth | NegotiateRequestFlags.ReplayDetect |
        NegotiateRequestFlags.SequenceDetect | NegotiateRequestFlags.Confidentiality |
        NegotiateRequestFlags.Integrity,
}

/// <summary>
/// Specifies the authentication method used by the Negotiate context.
/// </summary>
public enum NegotiateMethod
{
    NTLM,
    Kerberos,
    Negotiate,
}

/// <summary>
/// Channel bindings that can be supplied to a INegotiateContext to bind the
/// authentication context to the transport layer.
/// </summary>
/// <remarks>
/// WSMan will only set the ApplicationData byte value to the one expected by
/// Windows. The other properties are just set for completeness.
/// </remarks>
public sealed class ChannelBindings
{
    public int InitiatorAddrType { get; set; }
    public byte[]? InitiatorAddr { get; set; }
    public int AcceptorAddrType { get; set; }
    public byte[]? AcceptorAddr { get; set; }
    public byte[]? ApplicationData { get; set; }
}

/// <summary>
/// Extra options specific to Negotiate authentication to set on the authentication context.
/// </summary>
public sealed class NegotiateOptions
{
    public NegotiateRequestFlags Flags { get; set; } = NegotiateRequestFlags.Default;
    public string? SPNService { get; set; }
    public string? SPNHostName { get; set; }
}

/// <summary>
/// Interface that extends an AuthenticationContext to provide features
/// specific to the Negotiate protocol. This includes channel binding support
/// and wrapping and unwrapping support.
/// </summary>
public abstract class NegotiateAuthContext : AuthenticationContext
{
    /// <summary>Wraps the data as a single stream.</summary>
    /// <remarks>
    /// Some platforms may mutate the input data while others won't.
    /// Don't rely on the input data to not change and always use the return
    /// value to reference the newly wrapped data. This is used by CredSSP
    /// to wrap the authentication tokens it sends post authentication.
    /// </remarks>
    /// <param name="data">The data to wrap.</param>
    /// <returns>The wrapped data.</returns>
    protected internal abstract byte[] Wrap(Span<byte> data);

    /// <summary>Unwraps the data as a single stream.</summary>
    /// <remarks>
    /// Some platforms may mutate the input data while others won't.
    /// Don't rely on the input data to not change and always use the return
    /// value to reference the newly unwrapped data. This is used by CredSSP
    /// to unwrap the authentication tokesn it receives post authentication.
    /// </remarks>
    /// <param name="data">The data to unwrap.</param>
    /// <returns>The unwrapped data.</returns>
    protected internal abstract byte[] Unwrap(Span<byte> data);

    /// <summary>
    /// Creates a credential that uses negotiate authentication for the current platform.
    /// It will use SSPI on Windows and GSSAPI on Linux.
    /// </summary>
    /// <param name="username">The username to authenticate with.</param>
    /// <param name="password">The password to authenticate with.</param>
    /// <param name="method">The specific negotiate protocol to use.</param>
    /// <returns>The Negotiate context for the platform.</returns>
    public static WSManCredential CreateCredential(string? username, string? password, NegotiateMethod method)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            SspiProvider provider = new(NativeLibrary.Load("Secur32.dll"));
            return new SspiCredential(provider, username, password, method);
        }
        else
        {
            GssapiProvider provider = GetGssapiProvider();
            return new GssapiCredential(provider, username, password, method);
        }
    }

    internal static GssapiProvider GetGssapiProvider()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return new(NativeLibrary.Load("/System/Library/Frameworks/GSS.framework/GSS"));
        }

        foreach (string krb5Path in new[] {
                "libgssapi_krb5.so.2", // MIT krb5
                "libgssapi.so.3", "libgssapi.so", // Heimdal
            })
        {
            if (NativeLibrary.TryLoad(krb5Path, out var krb5Handle))
            {
                return new(krb5Handle);
            }
        }

        throw new PlatformNotSupportedException("Cannot find GSSAPI on current system platform.");
    }
}
