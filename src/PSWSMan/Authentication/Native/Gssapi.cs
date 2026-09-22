using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;

namespace PSWSMan.Authentication.Native;

internal static partial class Helpers
{
    [StructLayout(LayoutKind.Sequential)]
    public struct gss_channel_bindings_struct
    {
        public int initiator_addrtype;
        public gss_buffer_desc initiator_address;
        public int acceptor_addrtype;
        public gss_buffer_desc acceptor_address;
        public gss_buffer_desc application_data;
    }

    // GSS.framework on x86_64 macOS is defined with pack(2) which complicates things a bit more. It needs special
    // runtime handling when creating the struct. Note this does not apply to the arm64 macOS, the define only applies
    // to PowerPC (no longer relevant) and x86_64.
    // https://github.com/apple-oss-distributions/Heimdal/blob/5a776844a50fc09d714ba82ff7a88973c035b42b/lib/gssapi/gssapi/gssapi.h#L64-L67
    [StructLayout(LayoutKind.Sequential, Pack = 2)]
    public struct gss_channel_bindings_struct_macos
    {
        public int initiator_addrtype;
        public gss_buffer_desc initiator_address;
        public int acceptor_addrtype;
        public gss_buffer_desc acceptor_address;
        public gss_buffer_desc application_data;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct gss_iov_buffer_desc
    {
        public int type;
        public gss_buffer_desc buffer;
    }

    // Same as above, needs a special macos def for GSS.framework packing
    [StructLayout(LayoutKind.Sequential, Pack = 2)]
    public struct gss_iov_buffer_desc_macos
    {
        public int type;
        public gss_buffer_desc buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct gss_OID_desc
    {
        public UInt32 length;
        public IntPtr elements;
    }

    // See above for why macOS needs this pack value.
    [StructLayout(LayoutKind.Sequential, Pack = 2)]
    public struct gss_OID_desc_macos
    {
        public UInt32 length;
        public IntPtr elements;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct gss_OID_set_desc
    {
        public IntPtr count;
        public IntPtr elements;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct gss_buffer_desc
    {
        public IntPtr length;
        public IntPtr value;
    }
}

/// <summary>Result of <c>AcquireCred</c> or <c>AcquireCredWithPassword</c>.</summary>
internal class GssapiCredential
{
    /// <summary>The handle to the GSSAPI credential.</summary>
    public SafeGssapiCred Creds { get; }

    /// <summary>The number of seconds until the credential expires.</summary>
    public UInt32 TimeToLive { get; }

    /// <summary>The GSSAPI mechanisms that the credential supports.</summary>
    public List<byte[]> Mechanisms { get; }

    public GssapiCredential(GssapiProvider provider, SafeGssapiCred creds, UInt32 ttl, SafeHandle mechanisms)
    {
        Creds = creds;
        TimeToLive = ttl;

        using (mechanisms)
        {
            unsafe
            {
                Helpers.gss_OID_set_desc* set = (Helpers.gss_OID_set_desc*)mechanisms.DangerousGetHandle();
                Mechanisms = new List<byte[]>((int)set->count);

                if (provider.IsStructPackTwo)
                {
                    Span<Helpers.gss_OID_desc_macos> oids = new(set->elements.ToPointer(), (int)set->count);
                    foreach (Helpers.gss_OID_desc_macos memers in oids)
                    {
                        byte[] oid = new Span<byte>(memers.elements.ToPointer(), (int)memers.length).ToArray();
                        Mechanisms.Add(oid);
                    }
                }
                else
                {
                    Span<Helpers.gss_OID_desc> oids = new(set->elements.ToPointer(), (int)set->count);
                    foreach (Helpers.gss_OID_desc memers in oids)
                    {
                        byte[] oid = new Span<byte>(memers.elements.ToPointer(), (int)memers.length).ToArray();
                        Mechanisms.Add(oid);
                    }
                }
            }
        }
    }
}

/// <summary>Result of <c>InitSecContext</c>.</summary>
internal class GssapiSecContext
{
    /// <summary>The handle to the GSSAPI security context.</summary>
    public SafeGssapiSecContext Context { get; }

    /// <summary>The GSSAPI mech the context used.</summary>
    public byte[] MechType { get; }

    /// <summary>The return buffer from the GSSAPI call.</summary>
    public byte[]? OutputToken { get; }

    /// <summary>The attributes used to describe the functionality available on the context.</summary>
    public GssapiContextFlags Flags { get; }

    /// <summary>The number of seconds until the context expires.</summary>
    public Int32 TimeToLive { get; }

    /// <summary>Whether more data is neded from the acceptor to complete the context.</summary>
    public bool MoreNeeded { get; }

    public GssapiSecContext(SafeGssapiSecContext context, byte[] mechType, byte[]? outputToken,
        GssapiContextFlags flags, int ttl, bool moreNeeded)
    {
        Context = context;
        MechType = mechType;
        OutputToken = outputToken;
        Flags = flags;
        TimeToLive = ttl;
        MoreNeeded = moreNeeded;
    }
}

/// <summary>Result of <c>WrapIOV</c> and <c>UnwrapIOV</c>.</summary>
/// <remarks>This should be disposed when the results are no longer needed to cleanup unmanaged memory.</remarks>
internal class IOVResult : IDisposable
{
    private readonly GssapiProvider _provider;
    private readonly SafeHandle _raw;

    /// <summary>The confidentiality state of the IOV wrapping operation.</summary>
    public int ConfState { get; }

    public IOVResult(GssapiProvider provider, SafeHandle raw, int confState)
    {
        _provider = provider;
        _raw = raw;
        ConfState = confState;
    }

    public void Dispose()
    {
        _provider.gss_release_iov_buffer(out var _, _raw, 0);
        _raw?.Dispose();
        GC.SuppressFinalize(this);
    }
    ~IOVResult() => Dispose();
}

/// <summary>Provides extern entrypoints for GSSAPI functions</summary>
internal class GssapiProvider : IDisposable
{
    private bool? _isHeimdal = null;
    private IntPtr _module;
    private Dictionary<string, IntPtr> _moduleExports = new();

    public GssapiProvider(IntPtr module) => _module = module;

    public unsafe delegate int gss_add_oid_set_member_func(
            out int min_stat,
            SafeHandle member,
            ref Helpers.gss_OID_set_desc* target_set);

    public gss_add_oid_set_member_func gss_add_oid_set_member
        => GetDelegateForFunctionPtr<gss_add_oid_set_member_func>(nameof(gss_add_oid_set_member));

    public unsafe delegate int gss_acquire_cred_func(
        out int min_stat,
        SafeHandle desired_name,
        UInt32 ttl,
        Helpers.gss_OID_set_desc* mechs,
        GssapiCredUsage cred_usage,
        out IntPtr output_creds,
        out IntPtr actual_mechs,
        out UInt32 actual_ttl);

    public gss_acquire_cred_func gss_acquire_cred
        => GetDelegateForFunctionPtr<gss_acquire_cred_func>(nameof(gss_acquire_cred));

    public unsafe delegate int gss_acquire_cred_with_password_func(
        out int min_stat,
        SafeHandle desired_name,
        ref Helpers.gss_buffer_desc password,
        UInt32 ttl,
        Helpers.gss_OID_set_desc* desired_mechs,
        GssapiCredUsage cred_usage,
        out IntPtr output_creds,
        out IntPtr actual_mechs,
        out UInt32 actual_ttl);

    public gss_acquire_cred_with_password_func gss_acquire_cred_with_password
        => GetDelegateForFunctionPtr<gss_acquire_cred_with_password_func>(nameof(gss_acquire_cred_with_password));

    public unsafe delegate int gss_create_empty_oid_set_func(
        out int min_stat,
        out Helpers.gss_OID_set_desc* target_set);

    public gss_create_empty_oid_set_func gss_create_empty_oid_set
        => GetDelegateForFunctionPtr<gss_create_empty_oid_set_func>(nameof(gss_create_empty_oid_set));

    public delegate int gss_delete_sec_context_func(
        out int min_stat,
        ref IntPtr context,
        IntPtr output_token);

    public gss_delete_sec_context_func gss_delete_sec_context
        => GetDelegateForFunctionPtr<gss_delete_sec_context_func>(nameof(gss_delete_sec_context));

    public delegate int gss_display_status_func(
        out int min_status,
        int status_value,
        int status_type,
        SafeHandle mech_type,
        ref int message_context,
        ref Helpers.gss_buffer_desc status_string);

    public gss_display_status_func gss_display_status
        => GetDelegateForFunctionPtr<gss_display_status_func>(nameof(gss_display_status));

    public delegate int gss_import_name_func(
        out int min_stat,
        ref Helpers.gss_buffer_desc input_buffer,
        SafeHandle name_type,
        out IntPtr output_name);

    public gss_import_name_func gss_import_name
        => GetDelegateForFunctionPtr<gss_import_name_func>(nameof(gss_import_name));

    public unsafe delegate int gss_init_sec_context_func(
        out int minor_status,
        SafeGssapiCred? cred_handle,
        ref IntPtr context_handle,
        SafeHandle target_name,
        SafeHandle mech_type,
        GssapiContextFlags req_flags,
        int time_req,
        SafeHandle input_chan_bindings,
        Helpers.gss_buffer_desc* input_token,
        ref IntPtr actual_mech_type,
        ref Helpers.gss_buffer_desc output_token,
        out GssapiContextFlags ret_flags,
        out int time_rec);

    public gss_init_sec_context_func gss_init_sec_context
        => GetDelegateForFunctionPtr<gss_init_sec_context_func>(nameof(gss_init_sec_context));

    public delegate int gss_release_buffer_func(
        out int min_stat,
        ref Helpers.gss_buffer_desc buffer);

    public gss_release_buffer_func gss_release_buffer
        => GetDelegateForFunctionPtr<gss_release_buffer_func>(nameof(gss_release_buffer));

    public delegate int gss_release_cred_func(
        out int min_stat,
        ref IntPtr creds);

    public gss_release_cred_func gss_release_cred
        => GetDelegateForFunctionPtr<gss_release_cred_func>(nameof(gss_release_cred));

    public delegate int gss_release_name_func(
        out int min_stat,
        ref IntPtr name);

    public gss_release_name_func gss_release_name
        => GetDelegateForFunctionPtr<gss_release_name_func>(nameof(gss_release_name));

    public unsafe delegate int gss_release_oid_set_func(
        out int min_stat,
        ref Helpers.gss_OID_set_desc* target_set);

    public gss_release_oid_set_func gss_release_oid_set
        => GetDelegateForFunctionPtr<gss_release_oid_set_func>(nameof(gss_release_oid_set));

    public delegate int gss_unwrap_func(
        out int minor_status,
        SafeGssapiSecContext context_handle,
        ref Helpers.gss_buffer_desc input_message,
        ref Helpers.gss_buffer_desc output_message,
        out int conf_state,
        out int qop_state);

    public gss_unwrap_func gss_unwrap
        => GetDelegateForFunctionPtr<gss_unwrap_func>(nameof(gss_unwrap));

    public delegate int gss_wrap_func(
        out int minor_status,
        SafeGssapiSecContext context_handle,
        int conf_req,
        int qop_req,
        ref Helpers.gss_buffer_desc input_message,
        out int conf_state,
        ref Helpers.gss_buffer_desc output_message);

    public gss_wrap_func gss_wrap
        => GetDelegateForFunctionPtr<gss_wrap_func>(nameof(gss_wrap));

    public delegate int gss_unwrap_iov_func(
        out int minor_status,
        SafeGssapiSecContext context_handle,
        out int conf_state,
        out int qop_state,
        SafeHandle iov,
        int iov_count);

    public virtual gss_unwrap_iov_func gss_unwrap_iov
        => GetDelegateForFunctionPtr<gss_unwrap_iov_func>(nameof(gss_unwrap_iov));

    public delegate int gss_wrap_iov_func(
        out int minor_status,
        SafeGssapiSecContext context_handle,
        int conf_eq,
        int qop_req,
        out int conf_state,
        SafeHandle iov,
        int iov_count);

    public virtual gss_wrap_iov_func gss_wrap_iov
        => GetDelegateForFunctionPtr<gss_wrap_iov_func>(nameof(gss_wrap_iov));

    public delegate int gss_release_iov_buffer_func(
        out int minor_status,
        SafeHandle iov,
        int iov_count);

    public virtual gss_release_iov_buffer_func gss_release_iov_buffer
        => GetDelegateForFunctionPtr<gss_release_iov_buffer_func>(nameof(gss_release_iov_buffer));

    public virtual bool IsStructPackTwo => false;

    public virtual bool IsHeimdal
    {
        get
        {
            if (_isHeimdal == null)
            {
                _isHeimdal = NativeLibrary.TryGetExport(_module, "krb5_xfree", out var _);
            }

            return (bool)_isHeimdal;
        }
    }

    protected T GetDelegateForFunctionPtr<T>(string name)
    {
        if (!_moduleExports.TryGetValue(name, out var funcPtr))
        {
            funcPtr = NativeLibrary.GetExport(_module, name);
            _moduleExports[name] = funcPtr;
        }
        return Marshal.GetDelegateForFunctionPointer<T>(funcPtr);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            NativeLibrary.Free(_module);
            _module = IntPtr.Zero;
        }
    }
    ~GssapiProvider() => Dispose(false);
}

internal class GSSFrameworkProvider : GssapiProvider
{
    public GSSFrameworkProvider(IntPtr module) : base(module)
    { }

    // These 3 functions are not publicly exported but can still be accessed using these symbols
    public override gss_unwrap_iov_func gss_unwrap_iov
            => GetDelegateForFunctionPtr<gss_unwrap_iov_func>($"__ApplePrivate_{nameof(gss_unwrap_iov)}");

    public override gss_wrap_iov_func gss_wrap_iov
            => GetDelegateForFunctionPtr<gss_wrap_iov_func>($"__ApplePrivate_{nameof(gss_wrap_iov)}");

    public override gss_release_iov_buffer_func gss_release_iov_buffer
            => GetDelegateForFunctionPtr<gss_release_iov_buffer_func>($"__ApplePrivate_{nameof(gss_release_iov_buffer)}");

    // macOS on x86_64 need to use a specially packed structure when using GSS.Framework.
    public override bool IsStructPackTwo
        => RuntimeInformation.ProcessArchitecture == Architecture.X86 ||
            RuntimeInformation.ProcessArchitecture == Architecture.X64;
}

internal static class Gssapi
{
    // Name Types
    public static readonly byte[] GSS_C_NT_HOSTBASED_SERVICE = new byte[] {
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x01, 0x04
    }; // 1.2.840.113554.1.2.1.4

    public static readonly byte[] GSS_C_NT_USER_NAME = new byte[] {
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x01, 0x01
    }; // 1.2.840.113554.1.2.1.1

    // Mechanism OIDs
    public static readonly byte[] KERBEROS = new byte[] {
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02
    }; // 1.2.840.113554.1.2.2

    public static readonly byte[] NTLM = new byte[] {
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A
    }; // 1.3.6.1.4.1.311.2.2.10

    public static readonly byte[] SPNEGO = new byte[] {
        0x2B, 0x06, 0x01, 0x05, 0x05, 0x02
    }; // 1.3.6.1.5.5.2

    /// <summary>Acquire GSSAPI credential.</summary>
    /// <param name="provider">The GSSAPI provider to use.</param>
    /// <param name="name">The principal to get the cred for, if null the default principal is used.</param>
    /// <param name="ttl">The lifetime of the credential retrieved.</param>
    /// <param name="desiredMechs">A list of mechanisms the credential should work for.</param>
    /// <param name="usage">The usage type of the credential.</param>
    /// <returns>A handle to the retrieved GSSAPI credential.</returns>
    /// <exception cref="GSSAPIException">Failed to find the credential.</exception>
    public static GssapiCredential AcquireCred(GssapiProvider provider, SafeGssapiName? name, UInt32 ttl,
        IList<byte[]>? desiredMechs, GssapiCredUsage usage)
    {
        if (name == null)
            name = new SafeGssapiName(provider, IntPtr.Zero);

        unsafe
        {
            Helpers.gss_OID_set_desc* oidSet = CreateOIDSet(provider, desiredMechs);
            try
            {
                int majorStatus = provider.gss_acquire_cred(out var minorStatus, name, ttl, oidSet, usage,
                    out var outputCredsPtr, out var actualMechsPtr, out var actualTtls);
                if (majorStatus != 0)
                    throw new GSSAPIException(provider, majorStatus, minorStatus, "gss_acquire_cred");

                SafeGssapiCred outputCreds = new(provider, outputCredsPtr);
                SafeGssapiOidSet actualMechs = new(provider, actualMechsPtr);
                return new GssapiCredential(provider, outputCreds, actualTtls, actualMechs);
            }
            finally
            {
                provider.gss_release_oid_set(out var _, ref oidSet);
            }
        }
    }

    /// <summary>Get a new GSSAPI credential with the password specified.</summary>
    /// <param name="provider">The GSSAPI provider to use.</param>
    /// <param name="name">The principal to get the cred for, if null the default principal is used.</param>
    /// <param name="password">The password used to generate the new credential.</param>
    /// <param name="ttl">The lifetime of the credential retrieved.</param>
    /// <param name="desiredMechs">A list of mechanisms the credential should work for.</param>
    /// <param name="usage">The usage type of the credential.</param>
    /// <returns>A handle to the retrieved GSSAPI credential.</returns>
    /// <exception cref="GSSAPIException">Failed to get a new credential with the creds specified.</exception>
    public static GssapiCredential AcquireCredWithPassword(GssapiProvider provider, SafeHandle name, string password,
        UInt32 ttl, IList<byte[]> desiredMechs, GssapiCredUsage usage)
    {
        byte[] passBytes = Encoding.UTF8.GetBytes(password);
        unsafe
        {
            Helpers.gss_OID_set_desc* oidSet = CreateOIDSet(provider, desiredMechs);
            try
            {
                fixed (byte* passPtr = passBytes)
                {
                    Helpers.gss_buffer_desc passBuffer = new()
                    {
                        length = new IntPtr(passBytes.Length),
                        value = (IntPtr)passPtr,
                    };

                    int majorStatus = provider.gss_acquire_cred_with_password(out var minorStatus, name,
                        ref passBuffer, ttl, oidSet, usage, out var outputCredsPtr, out var actualMechsPtr,
                        out var actualTtls);
                    if (majorStatus != 0)
                        throw new GSSAPIException(provider, majorStatus, minorStatus, "gss_acquire_cred_with_password");

                    SafeGssapiCred outputCreds = new(provider, outputCredsPtr);
                    SafeGssapiOidSet actualMechs = new(provider, actualMechsPtr);
                    return new GssapiCredential(provider, outputCreds, actualTtls, actualMechs);
                }
            }
            finally
            {
                provider.gss_release_oid_set(out var _, ref oidSet);
            }
        }
    }

    /// <summary>Get the GSSAPI error message for the error code.</summary>
    /// <param name="provider">The GSSAPI provider to use.</param>
    /// <param name="errorCode">The error code to get the status for.</param>
    /// <param name="isMajorCode">The error code is a major error code and not minor.</param>
    /// <param name="mech">Optional mech the error code is associated with.</param>
    /// <returns>The error message for the code specified.</returns>
    public static string DisplayStatus(GssapiProvider provider, int errorCode, bool isMajorCode, byte[]? mech)
    {
        Helpers.gss_buffer_desc msgBuffer = new();
        int statusType = isMajorCode ? 1 : 2; // GSS_C_GSS_CODE : GSS_C_MECH_CODE
        int messageContext = 0;

        unsafe
        {
            fixed (byte* mechPtr = mech)
            {
                SafeHandle mechBuffer = CreateOIDBuffer(provider, mechPtr, mech?.Length ?? 0);

                List<string> lines = new();
                while (true)
                {
                    int contextValue = messageContext;
                    messageContext++;

                    int majorStatus = provider.gss_display_status(out var _, errorCode, statusType, mechBuffer,
                        ref contextValue, ref msgBuffer);

                    // Cannot raise exception as it will result in a recursive operation.
                    if (majorStatus != 0)
                        break;

                    string? status = Marshal.PtrToStringUTF8(msgBuffer.value, (int)msgBuffer.length);
                    if (!String.IsNullOrEmpty(status))
                        lines.Add(status);

                    if (contextValue == 0)
                        break;
                }

                return String.Join(". ", lines);
            }
        }
    }

    /// <summary>Create a GSSAPI name object.</summary>
    /// <param name="provider">The GSSAPI provider to use.</param>
    /// <param name="name">The name to create the name object for.</param>
    /// <param nameType="The type of name to create."></param>
    /// <returns>The GSSAPI name buffer handle.</returns>
    /// <exception cref="GSSAPIException">Failed to create name object.</exception>
    public static SafeGssapiName ImportName(GssapiProvider provider, string name, ReadOnlySpan<byte> nameType)
    {
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);

        unsafe
        {
            fixed (byte* nameTypePtr = nameType, namePtr = nameBytes)
            {
                Helpers.gss_buffer_desc nameBuffer = new()
                {
                    length = new IntPtr(nameBytes.Length),
                    value = (IntPtr)namePtr,
                };

                using SafeHandle nameTypeBuffer = CreateOIDBuffer(provider, nameTypePtr, nameType.Length);
                int majorStatus = provider.gss_import_name(out var minorStatus, ref nameBuffer, nameTypeBuffer,
                    out var outputNamePtr);
                if (majorStatus != 0)
                    throw new GSSAPIException(provider, majorStatus, minorStatus, "gss_import_name");

                return new(provider, outputNamePtr);
            }
        }
    }

    /// <summary>Initiates a security context or processes a new token on an existing context.</summary>
    /// <param name="provider">The GSSAPI provider to use.</param>
    /// <param name="cred">
    /// The credential handle to be used with the context. Set to null to use <c>GSS_C_NO_CREDENTIAL</c>.
    /// </param>
    /// <param name="context">
    /// The context handle for the operation. The first call should be set to <c>null</c> while subsequence calls
    /// use the context returned from the first call.
    /// </param>
    /// <param name="targetName">The target name of the acceptor, for Kerberos this is the SPN.</param>
    /// <param name="mechType">The desired security mechanism OID or null for <c>GSS_C_NO_OID</c>.</param>
    /// <param name="reqFlags">Request flags to set.</param>
    /// <param name="ttl">The lifetime of the context retrieved.</param>
    /// <param name="chanBindings">Optional channel bindings to bind to the context.</param>
    /// <param name="inputToken">Optional token received from the acceptor or null for <c>GSS_C_NO_BUFFER</c>.</param>
    /// <returns>A handle to the retrieved GSSAPI security context.</returns>
    /// <exception cref="GSSAPIException">Failed to initiate/step the security context.</exception>
    public static GssapiSecContext InitSecContext(GssapiProvider provider, SafeGssapiCred? cred,
        SafeGssapiSecContext? context, SafeGssapiName targetName, byte[]? mechType, GssapiContextFlags reqFlags,
        int ttl, ChannelBindings? chanBindings, Span<byte> inputToken)
    {
        cred ??= new SafeGssapiCred(provider, IntPtr.Zero);
        context ??= new SafeGssapiSecContext(provider, IntPtr.Zero);
        Helpers.gss_buffer_desc outputTokenBuffer = new();
        IntPtr actualMechBuffer = IntPtr.Zero;

        GssapiContextFlags actualFlags;
        int actualTTL;
        bool continueNeeded;
        unsafe
        {
            fixed (byte* mechTypePtr = mechType)
            fixed (byte* initiatorAddr = chanBindings?.InitiatorAddr)
            fixed (byte* acceptorAddr = chanBindings?.AcceptorAddr)
            fixed (byte* appData = chanBindings?.ApplicationData)
            fixed (byte* inputTokenPtr = inputToken)
            {
                SafeHandle mechBuffer = CreateOIDBuffer(provider, mechTypePtr, mechType?.Length ?? 0);
                SafeHandle chanBindingBuffer = CreateChanBindingBuffer(provider, chanBindings, initiatorAddr,
                    acceptorAddr, appData);

                Helpers.gss_buffer_desc* inputStruct = null;
                if (inputToken.Length > 0)
                {
                    Helpers.gss_buffer_desc inputBuffer = new()
                    {
                        length = new IntPtr(inputToken.Length),
                        value = (IntPtr)inputTokenPtr,
                    };
                    inputStruct = &inputBuffer;
                }

                IntPtr contextPtr = context.DangerousGetHandle();
                int majorStatus = provider.gss_init_sec_context(out var minorStatus, cred, ref contextPtr, targetName,
                    mechBuffer, reqFlags, ttl, chanBindingBuffer, inputStruct, ref actualMechBuffer,
                    ref outputTokenBuffer, out actualFlags, out actualTTL);

                if (majorStatus != 0 && majorStatus != 1)
                    throw new GSSAPIException(provider, majorStatus, minorStatus, "gss_init_sec_context");

                context.SetContextHandle(contextPtr);

                continueNeeded = majorStatus == 1;
            }
        }

        try
        {
            byte[] actualMechType;
            if (actualMechBuffer == IntPtr.Zero)
            {
                actualMechType = Array.Empty<byte>();
            }
            else
            {
                unsafe
                {
                    if (provider.IsStructPackTwo)
                    {
                        var actualMech = (Helpers.gss_OID_desc_macos*)actualMechBuffer.ToPointer();
                        actualMechType = new byte[actualMech->length];
                        Marshal.Copy(actualMech->elements, actualMechType, 0, actualMechType.Length);
                    }
                    else
                    {
                        var actualMech = (Helpers.gss_OID_desc*)actualMechBuffer.ToPointer();
                        actualMechType = new byte[actualMech->length];
                        Marshal.Copy(actualMech->elements, actualMechType, 0, actualMechType.Length);
                    }
                }
            }

            byte[]? outputToken = null;
            if ((int)outputTokenBuffer.length > 0)
            {
                outputToken = new byte[(int)outputTokenBuffer.length];
                Marshal.Copy(outputTokenBuffer.value, outputToken, 0, outputToken.Length);
            }

            return new GssapiSecContext(context, actualMechType, outputToken, actualFlags, actualTTL,
                continueNeeded);
        }
        finally
        {
            provider.gss_release_buffer(out var minStatus2, ref outputTokenBuffer);
        }
    }

    /// <summary>Unwraps a wrapped message from the peer.</summary>
    /// <param name="provider">The GSSAPI provider to use.</param>
    /// <param name="context">The context handle that was used to wrap the message.</param>
    /// <param name="inputMessage">The wrapped message to unwrap.</param>
    /// <returns>
    /// A tuple that contains:
    ///   The unwrapped message.
    ///   Whether the input message was encrypted.
    ///   The QOP applied to the input message.
    /// </returns>
    /// <exception cref="GSSAPIException">Failed to initiate/step the security context.</exception>
    public static (byte[], bool, int) Unwrap(GssapiProvider provider, SafeGssapiSecContext context,
        ReadOnlySpan<byte> inputMessage)
    {
        Helpers.gss_buffer_desc outputBuffer = new();
        int confState;
        int qopState;

        unsafe
        {
            fixed (byte* p = inputMessage)
            {
                Helpers.gss_buffer_desc inputBuffer = new()
                {
                    length = (IntPtr)inputMessage.Length,
                    value = (IntPtr)p,
                };
                int majorStatus = provider.gss_unwrap(out var minorStatus, context, ref inputBuffer, ref outputBuffer,
                    out confState, out qopState);
                if (majorStatus != 0)
                    throw new GSSAPIException(provider, majorStatus, minorStatus, "gss_unwrap");
            }
        }

        try
        {
            byte[] output = new byte[(int)outputBuffer.length];
            Marshal.Copy(outputBuffer.value, output, 0, output.Length);

            return (output, confState == 1, qopState);
        }
        finally
        {
            provider.gss_release_buffer(out var _, ref outputBuffer);
        }
    }

    /// <summary>Unwraps an IOV buffer from the peer.</summary>
    /// <remarks>The IOV unwrapping will mutate the input buffer data in place.</remarks>
    /// <param name="provider">The GSSAPI provider to use.</param>
    /// <param name="context">The context handle that was used to wrap the message.</param>
    /// <param name="buffer">The IOV buffers to unwrap.</param>
    /// <returns>The IOV result containing the unmanaged memory handle</returns>
    /// <exception cref="GSSAPIException">Failed to initiate/step the security context.</exception>
    public static IOVResult UnwrapIOV(GssapiProvider provider, SafeGssapiSecContext context, Span<IOVBuffer> buffer)
    {
        SafeHandle iovBuffers = CreateIOVSet(provider, buffer);
        int majorStatus = provider.gss_unwrap_iov(out var minorStatus, context, out var confState, out var _,
            iovBuffers, buffer.Length);

        if (majorStatus != 0)
            throw new GSSAPIException(provider, majorStatus, minorStatus, "gss_wrap_iov");

        ProcessIOVResult(provider, buffer, iovBuffers);
        return new IOVResult(provider, iovBuffers, confState);
    }

    /// <summary>Wraps (signs or encrypts) a message to send to the peer.</summary>
    /// <param name="provider">The GSSAPI provider to use.</param>
    /// <param name="context">The context handle that is used to wrap the message.</param>
    /// <param name="confReq">Whether to encrypt the message or just sign it.</param>
    /// <param name="qopReq">The QOP requested for the message.</param>
    /// <param name="inputMessage">The message to encrypt.</param>
    /// <returns>
    /// A tuple the contains:
    ///   The wrapped message.
    ///   Whether the input message was encrypted (true) or just signed (false).
    /// </returns>
    /// <exception cref="GSSAPIException">Failed to initiate/step the security context.</exception>
    public static (byte[], bool) Wrap(GssapiProvider provider, SafeGssapiSecContext context, bool confReq, int qopReq,
        ReadOnlySpan<byte> inputMessage)
    {
        Helpers.gss_buffer_desc outputBuffer = new();
        int confState;

        unsafe
        {
            fixed (byte* p = inputMessage)
            {
                Helpers.gss_buffer_desc inputBuffer = new()
                {
                    length = (IntPtr)inputMessage.Length,
                    value = (IntPtr)p,
                };
                int majorStatus = provider.gss_wrap(out var minorStatus, context, confReq ? 1 : 0, qopReq,
                    ref inputBuffer, out confState, ref outputBuffer);
                if (majorStatus != 0)
                    throw new GSSAPIException(provider, majorStatus, minorStatus, "gss_unwrap");
            }
        }

        try
        {
            byte[] output = new byte[(int)outputBuffer.length];
            Marshal.Copy(outputBuffer.value, output, 0, output.Length);

            return (output, confState == 1);
        }
        finally
        {
            provider.gss_release_buffer(out var _, ref outputBuffer);
        }
    }

    /// <summary>Wraps an IOV buffer to send to the peer.</summary>
    /// <remarks>The IOV wrapping will mutate the input buffer data in place.</remarks>
    /// <param name="provider">The GSSAPI provider to use.</param>
    /// <param name="context">The context handle that was used to wrap the message.</param>
    /// <param name="confReq">Whether to encrypt the message or just sign it.</param>
    /// <param name="qopReq">The QOP requested for the message.</param>
    /// <param name="buffer">The IOV buffers to unwrap.</param>
    /// <returns>The IOV result containing the unmanaged memory handle</returns>
    /// <exception cref="GSSAPIException">Failed to initiate/step the security context.</exception>
    public static IOVResult WrapIOV(GssapiProvider provider, SafeGssapiSecContext context, bool confReq, int qopReq,
        Span<IOVBuffer> buffer)
    {
        SafeHandle iovBuffers = CreateIOVSet(provider, buffer);
        int majorStatus = provider.gss_wrap_iov(out var minorStatus, context, confReq ? 1 : 0, qopReq,
            out var confState, iovBuffers, buffer.Length);

        if (majorStatus != 0)
            throw new GSSAPIException(provider, majorStatus, minorStatus, "gss_wrap_iov");

        ProcessIOVResult(provider, buffer, iovBuffers);
        return new IOVResult(provider, iovBuffers, confState);
    }

    private static unsafe SafeHandle CreateChanBindingBuffer(GssapiProvider provider, ChannelBindings? bindings,
        byte* initiatorAddr, byte* acceptorAddr, byte* applicationData)
    {
        if (bindings == null)
            return new SafeMemoryBuffer();

        if (provider.IsStructPackTwo)
        {
            // Need the pack 2 structure to properly set this up.
            SafeMemoryBuffer buffer = new(Marshal.SizeOf<Helpers.gss_channel_bindings_struct_macos>());

            var cb = (Helpers.gss_channel_bindings_struct_macos*)buffer.DangerousGetHandle().ToPointer();
            cb->initiator_addrtype = bindings.InitiatorAddrType;
            cb->initiator_address.length = new IntPtr(bindings.InitiatorAddr?.Length ?? 0);
            cb->initiator_address.value = (IntPtr)initiatorAddr;
            cb->acceptor_addrtype = bindings.AcceptorAddrType;
            cb->acceptor_address.length = new IntPtr(bindings.AcceptorAddr?.Length ?? 0);
            cb->acceptor_address.value = (IntPtr)acceptorAddr;
            cb->application_data.length = new IntPtr(bindings.ApplicationData?.Length ?? 0);
            cb->application_data.value = (IntPtr)applicationData;

            return buffer;
        }
        else
        {
            SafeMemoryBuffer buffer = new(Marshal.SizeOf<Helpers.gss_channel_bindings_struct>());

            var cb = (Helpers.gss_channel_bindings_struct*)buffer.DangerousGetHandle().ToPointer();
            cb->initiator_addrtype = bindings.InitiatorAddrType;
            cb->initiator_address.length = new IntPtr(bindings.InitiatorAddr?.Length ?? 0);
            cb->initiator_address.value = (IntPtr)initiatorAddr;
            cb->acceptor_addrtype = bindings.AcceptorAddrType;
            cb->acceptor_address.length = new IntPtr(bindings.AcceptorAddr?.Length ?? 0);
            cb->acceptor_address.value = (IntPtr)acceptorAddr;
            cb->application_data.length = new IntPtr(bindings.ApplicationData?.Length ?? 0);
            cb->application_data.value = (IntPtr)applicationData;

            return buffer;
        }
    }

    private static unsafe SafeHandle CreateOIDBuffer(GssapiProvider provider, byte* oid, int length)
    {
        if (oid == null)
            return new SafeMemoryBuffer();

        if (provider.IsStructPackTwo)
        {
            // Need the pack 2 structure to properly set this up.
            SafeMemoryBuffer buffer = new(Marshal.SizeOf<Helpers.gss_OID_desc_macos>());
            var oidBuffer = (Helpers.gss_OID_desc_macos*)buffer.DangerousGetHandle().ToPointer();
            oidBuffer->length = (uint)length;
            oidBuffer->elements = (IntPtr)oid;

            return buffer;
        }
        else
        {
            SafeMemoryBuffer buffer = new(Marshal.SizeOf<Helpers.gss_OID_desc>());
            var oidBuffer = (Helpers.gss_OID_desc*)buffer.DangerousGetHandle().ToPointer();
            oidBuffer->length = (uint)length;
            oidBuffer->elements = (IntPtr)oid;

            return buffer;
        }
    }

    private static SafeHandle CreateIOVSet(GssapiProvider provider, Span<IOVBuffer> buffers)
    {
        unsafe
        {
            if (provider.IsStructPackTwo)
            {
                SafeMemoryBuffer buffer = new(Marshal.SizeOf<Helpers.gss_iov_buffer_desc_macos>() * buffers.Length);
                Span<Helpers.gss_iov_buffer_desc_macos> iovBuffers = new(buffer.DangerousGetHandle().ToPointer(),
                    buffers.Length);

                for (int i = 0; i < buffers.Length; i++)
                {
                    iovBuffers[i].type = (int)buffers[i].Type | (int)buffers[i].Flags;
                    iovBuffers[i].buffer.length = (IntPtr)buffers[i].Length;
                    iovBuffers[i].buffer.value = buffers[i].Data;
                }

                return buffer;
            }
            else
            {
                SafeMemoryBuffer buffer = new(Marshal.SizeOf<Helpers.gss_iov_buffer_desc>() * buffers.Length);
                Span<Helpers.gss_iov_buffer_desc> iovBuffers = new(buffer.DangerousGetHandle().ToPointer(),
                    buffers.Length);

                for (int i = 0; i < buffers.Length; i++)
                {
                    iovBuffers[i].type = (int)buffers[i].Type | (int)buffers[i].Flags;
                    iovBuffers[i].buffer.length = (IntPtr)buffers[i].Length;
                    iovBuffers[i].buffer.value = buffers[i].Data;
                }

                return buffer;
            }
        }
    }

    private static void ProcessIOVResult(GssapiProvider provider, Span<IOVBuffer> buffers, SafeHandle raw)
    {
        unsafe
        {
            if (provider.IsStructPackTwo)
            {
                Span<Helpers.gss_iov_buffer_desc_macos> iovSet = new(raw.DangerousGetHandle().ToPointer(),
                    buffers.Length);

                for (int i = 0; i < iovSet.Length; i++)
                {
                    buffers[i].Flags = (IOVBufferFlags)(iovSet[i].type & unchecked((int)0xFFFF0000));
                    buffers[i].Type = (IOVBufferType)(iovSet[i].type & 0x0000FFFF);
                    buffers[i].Data = iovSet[i].buffer.value;
                    buffers[i].Length = iovSet[i].buffer.length.ToInt32();
                }
            }
            else
            {
                Span<Helpers.gss_iov_buffer_desc> iovSet = new(raw.DangerousGetHandle().ToPointer(),
                    buffers.Length);

                for (int i = 0; i < iovSet.Length; i++)
                {
                    buffers[i].Flags = (IOVBufferFlags)(iovSet[i].type & unchecked((int)0xFFFF0000));
                    buffers[i].Type = (IOVBufferType)(iovSet[i].type & 0x0000FFFF);
                    buffers[i].Data = iovSet[i].buffer.value;
                    buffers[i].Length = iovSet[i].buffer.length.ToInt32();
                }
            }
        }
    }

    private static unsafe Helpers.gss_OID_set_desc* CreateOIDSet(GssapiProvider provider, IList<byte[]>? oids)
    {
        if (oids == null)
            return null;

        int majorStatus = provider.gss_create_empty_oid_set(out var minorStatus, out var setBuffer);
        if (majorStatus != 0)
            throw new GSSAPIException(provider, majorStatus, minorStatus, "gss_create_empty_oid_set");

        try
        {
            foreach (byte[] oid in oids)
            {
                fixed (byte* oidPtr = oid)
                {
                    SafeHandle oidBuffer = CreateOIDBuffer(provider, oidPtr, oid.Length);
                    majorStatus = provider.gss_add_oid_set_member(out minorStatus, oidBuffer, ref setBuffer);
                    if (majorStatus != 0)
                        throw new GSSAPIException(provider, majorStatus, minorStatus, "gss_add_oid_set_member");
                }
            }
        }
        catch
        {
            provider.gss_release_oid_set(out var _, ref setBuffer);
            throw;
        }

        return setBuffer;
    }
}

public class GSSAPIException : AuthenticationException
{
    public int MajorStatus { get; } = -1;

    public int MinorStatus { get; } = -1;

    public GSSAPIException() { }

    public GSSAPIException(string message) : base(message) { }

    public GSSAPIException(string message, Exception innerException) :
        base(message, innerException)
    { }

    internal GSSAPIException(GssapiProvider provider, int majorStatus, int minorStatus, string method)
        : base(GetExceptionMessage(provider, majorStatus, minorStatus, method))
    {
        MajorStatus = majorStatus;
        MinorStatus = minorStatus;
    }

    private static string GetExceptionMessage(GssapiProvider provider, int majorStatus, int minorStatus,
        string? method)
    {
        method = String.IsNullOrWhiteSpace(method) ? "GSSAPI Call" : method;
        string majString = Gssapi.DisplayStatus(provider, majorStatus, true, null);
        string minString = Gssapi.DisplayStatus(provider, minorStatus, false, null);

        return String.Format("{0} failed (Major Status {1} - {2}) (Minor Status {3} - {4})",
            method, majorStatus, majString, minorStatus, minString);
    }
}

[Flags]
internal enum GssapiContextFlags
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

internal enum IOVBufferType
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
internal enum IOVBufferFlags
{
    NONE = 0x00000000,
    GSS_IOV_BUFFER_FLAG_ALLOCATE = 0x00010000,
    GSS_IOV_BUFFER_FLAG_ALLOCATED = 0x00020000,
}

internal class SafeGssapiCred : SafeHandle
{
    private readonly GssapiProvider _provider;

    internal SafeGssapiCred(GssapiProvider provider, IntPtr handle) : base(handle, true)
    {
        _provider = provider;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        return _provider.gss_release_cred(out var _, ref handle) == 0;
    }
}

internal class SafeGssapiName : SafeHandle
{
    private readonly GssapiProvider _provider;

    internal SafeGssapiName(GssapiProvider provider, IntPtr handle) : base(handle, true)
    {
        _provider = provider;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        return _provider.gss_release_name(out var _, ref handle) == 0;
    }
}

internal class SafeGssapiOidSet : SafeHandle
{
    private readonly GssapiProvider _provider;

    internal SafeGssapiOidSet(GssapiProvider provider, IntPtr handle) : base(handle, true)
    {
        _provider = provider;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        unsafe
        {
            Helpers.gss_OID_set_desc* oidSet = (Helpers.gss_OID_set_desc*)handle;

            return _provider.gss_release_oid_set(out var _, ref oidSet) == 0;
        }
    }
}

internal class SafeGssapiSecContext : SafeHandle
{
    private readonly GssapiProvider _provider;

    internal SafeGssapiSecContext(GssapiProvider provider, IntPtr handle) : base(handle, true)
    {
        _provider = provider;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    internal void SetContextHandle(IntPtr credHandle) => SetHandle(credHandle);

    protected override bool ReleaseHandle()
    {
        return _provider.gss_delete_sec_context(out var _, ref handle, IntPtr.Zero) == 0;
    }
}

internal class SafeMemoryBuffer : SafeHandle
{
    public int Length { get; } = 0;

    internal SafeMemoryBuffer() : base(IntPtr.Zero, true) { }

    internal SafeMemoryBuffer(int size) : base(Marshal.AllocHGlobal(size), true) => Length = size;

    internal SafeMemoryBuffer(string value) : base(IntPtr.Zero, true)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);
        Length = data.Length;

        handle = Marshal.AllocHGlobal(Length);
        Marshal.Copy(data, 0, handle, Length);
    }

    internal SafeMemoryBuffer(IntPtr buffer, bool ownsHandle) : base(buffer, ownsHandle) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        Marshal.FreeHGlobal(handle);
        return true;
    }
}

internal struct IOVBuffer
{
    public IOVBufferFlags Flags;
    public IOVBufferType Type;
    public IntPtr Data;
    public int Length;
}
