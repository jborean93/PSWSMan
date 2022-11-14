using PSWSMan.Native;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace PSWSMan;

internal enum GssapiProvider
{
    /// <summary>No GSSAPI provider is available, no Negotiate, NTLM, Kerberos, or CredSSP auth is available.</summary>
    None,

    /// <summary>Uses the MIT krb5 GSSAPI implementation.</summary>
    MIT,

    /// <summary>Uses the Heimdal GSSAPI implementation.</summary>
    Heimdal,

    /// <summary>Uses the macOS GSS.Framework (based on Heimdal) implementation.</summary>
    GSSFramework,

    /// <summary>Uses the Windows only SSPI implementation.</summary>
    SSPI,
}

internal class ChannelBindings
{
    public int InitiatorAddrType { get; set; }
    public byte[]? InitiatorAddr { get; set; }
    public int AcceptorAddrType { get; set; }
    public byte[]? AcceptorAddr { get; set; }
    public byte[]? ApplicationData { get; set; }
}

/// <summary>Abstract class that exposes a platform agnostic GSSAPI/SSPI implementation.</summary>
internal abstract class SecurityContext : IDisposable
{
    /// <summary>States whether the auth context is authenticated and ready for wrapping/unwrapping.</summary>
    public bool Complete { get; internal set; }

    /// <summary>Process the optional incoming auth token and generate an output token.</summary>
    /// <param name="inputToken">The input token from the peer to process, or null for the first call.</summary>
    /// <returns>The auth token to send to the peer, may be an empty array if no more tokens need to be sent.</returns>
    public abstract byte[] Step(byte[]? inputToken = null);

    /// <summary>Wraps the data as a single stream.</summary>
    /// <remarks>
    /// Some platforms may mutate the input data while others won't. Don't rely on the input data to not change and
    /// always use the return value to reference the newly wrapped data.
    /// </remarks>
    /// <param name="data">The data to wrap.</summary>
    /// <returns>The wrapped data.</returns>
    public abstract byte[] Wrap(Span<byte> data);

    /// <summary>Wraps the data for use with WinRM.</summary>
    /// <remarks>
    /// The input data will be mutated as the data is encrypted in place. Use the encryptedLength out parameter to
    /// determine the length of the newly encrypted data in the span passed in.
    /// </remarks>
    /// <param name="data">The data to wrap.</summary>
    /// <param name="encryptedLength">The number of bytes in data that has been encrypted.</summary>
    /// <param name="paddingLength">The number of bytes that was padded to the plaintext during encryption.</summary>
    /// <returns>The encryption header bytes.</returns>
    public abstract byte[] WrapWinRM(Span<byte> data, out int encryptedLength, out int paddingLength);

    /// <summary>Unwraps the data as a single stream.</summary>
    /// <remarks>
    /// Some platforms may mutate the input data while others won't. Don't rely on the input data to not change and
    /// always use the return value to reference the newly unwrapped data.
    /// </remarks>
    /// <param name="data">The data to unwrap.</summary>
    /// <returns>The unwrapped data.</returns>
    public abstract byte[] Unwrap(Span<byte> data);

    /// <summary>Unwraps the data from a WinRM exchange.</summary>
    /// <remarks>
    /// The input data will be mutated as the data is decrypted in place. Use the return value to determine where in
    /// input data span the decrypted data is located.
    /// </remarks>
    /// <param name="data">The data to decrypt, this should contain the header and 4 byte signature marker.</summary>
    /// <returns>The span pointing to the decrypted data.</returns>
    public abstract Span<byte> UnwrapWinRM(Span<byte> data);

    /// <summary>Sets the channel bindings to use for authentication.</summary>
    /// <param name="bindings">The channel bindings to set on the security context.</summary>
    public virtual void SetChannelBindings(ChannelBindings? bindings)
    { }

    public abstract void Dispose();
    ~SecurityContext() => Dispose();

    /// <summary>Gets the relevant security provider for the platform at runtime.</summary>
    /// <param name="username">The username to authenticate with or null for the current user context.</param>
    /// <param name="password">The password to authenticate with or null to rely on a cached credential.</param>
    /// <param name="method">The Negotiate authentication method to use.</param>
    /// <param name="service">The SPN service part, e.g. host, cifs, ldap.</param>
    /// <param name="target">The SPN principal part, i.e. the hostname.</param>
    /// <param name="requestDelegate">Request a delegatable ticket, used with Kerberos auth only.</param>
    /// <returns>The SecurityContext that can be used for Negotiate authentication.</returns>
    public static SecurityContext GetPlatformSecurityContext(string? username, string? password,
        AuthenticationMethod method, string service, string target, bool requestDelegate)
    {
        if (GlobalState.GssapiProvider == GssapiProvider.SSPI)
        {
            return new SspiContext(
                username,
                password,
                method,
                $"{service}/{target}",
                requestDelegate);
        }
        else
        {
            return new GssapiContext(
                username,
                password,
                method,
                $"{service}@{target}",
                requestDelegate);
        }
    }
}

internal class GssapiContext : SecurityContext
{
    private readonly SafeGssapiCred? _credential;
    private readonly SafeGssapiName _targetSpn;
    private readonly byte[]? _mech;
    private readonly GssapiContextFlags _flags = GssapiContextFlags.GSS_C_MUTUAL_FLAG |
        GssapiContextFlags.GSS_C_SEQUENCE_FLAG | GssapiContextFlags.GSS_C_INTEG_FLAG |
        GssapiContextFlags.GSS_C_CONF_FLAG;
    private SafeGssapiSecContext? _context;
    private byte[]? _negotiatedMech;
    private ChannelBindings? _bindingData;

    public GssapiContext(string? username, string? password, AuthenticationMethod method, string target,
        bool requestDelegate)
    {
        _mech = method switch
        {
            AuthenticationMethod.NTLM => GSSAPI.NTLM,
            AuthenticationMethod.Kerberos => GSSAPI.KERBEROS,
            _ => GSSAPI.SPNEGO,
        };
        _targetSpn = GSSAPI.ImportName(target, GSSAPI.GSS_C_NT_HOSTBASED_SERVICE);

        bool isHeimdal = GlobalState.GssapiProvider != GssapiProvider.MIT;
        List<byte[]> mechList = new() { _mech };
        if (isHeimdal && method == AuthenticationMethod.Negotiate)
        {
            mechList.AddRange(new[] { GSSAPI.KERBEROS, GSSAPI.NTLM });
        }

        if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
        {
            using SafeGssapiName name = GSSAPI.ImportName(username, GSSAPI.GSS_C_NT_USER_NAME);
            _credential = GSSAPI.AcquireCredWithPassword(name, password, 0, mechList,
                GssapiCredUsage.GSS_C_INITIATE).Creds;

            if (GlobalState.GssapiProvider != GssapiProvider.MIT)
            {
                _mech = null;
            }
        }
        else
        {
            SafeGssapiName? name = null;
            if (!string.IsNullOrEmpty(username))
                name = GSSAPI.ImportName(username, GSSAPI.GSS_C_NT_USER_NAME);

            using (name)
                _credential = GSSAPI.AcquireCred(name, 0, mechList, GssapiCredUsage.GSS_C_INITIATE).Creds;
        }

        if (requestDelegate)
        {
            _flags |= GssapiContextFlags.GSS_C_DELEG_FLAG;
        }
    }

    public override byte[] Step(byte[]? inputToken = null)
    {
        var res = GSSAPI.InitSecContext(_credential, _context, _targetSpn, _mech, _flags, 0, _bindingData,
            inputToken);
        _context = res.Context;

        if (!res.MoreNeeded)
        {
            Complete = true;
            _negotiatedMech = res.MechType;
        }

        return res.OutputToken ?? Array.Empty<byte>();
    }

    public override byte[] Wrap(Span<byte> data)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        (byte[] wrappedData, bool _) = GSSAPI.Wrap(_context, true, 0, data);
        return wrappedData;
    }

    public override byte[] WrapWinRM(Span<byte> data, out int encryptedLength, out int paddingLength)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        if (_negotiatedMech?.SequenceEqual(GSSAPI.NTLM) == true)
        {
            // NTLM doesn't support gss_wrap_iov but luckily the header is always 16 bytes and there is no padding so
            // gss_wrap can be used instead. Because gss_wrap doesn't wrap in place we still need to copy the wrapped
            // data to the input span.
            byte[] wrappedData = Wrap(data);
            byte[] header = wrappedData.AsSpan(0, 16).ToArray();
            wrappedData.AsSpan(16).CopyTo(data);

            encryptedLength = wrappedData.Length - 16;
            paddingLength = 0;

            return header;
        }
        else
        {
            unsafe
            {
                fixed (byte* dataPtr = data)
                {
                    Span<IOVBuffer> iov = stackalloc IOVBuffer[3];
                    iov[0].Flags = IOVBufferFlags.GSS_IOV_BUFFER_FLAG_ALLOCATE;
                    iov[0].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_HEADER;
                    iov[0].Data = IntPtr.Zero;
                    iov[0].Length = 0;

                    iov[1].Flags = IOVBufferFlags.NONE;
                    iov[1].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_DATA;
                    iov[1].Data = (IntPtr)dataPtr;
                    iov[1].Length = data.Length;

                    iov[2].Flags = IOVBufferFlags.GSS_IOV_BUFFER_FLAG_ALLOCATE;
                    iov[2].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_PADDING;
                    iov[2].Data = IntPtr.Zero;
                    iov[2].Length = 0;

                    using IOVResult res = GSSAPI.WrapIOV(_context, true, 0, iov);

                    byte[] header = new Span<byte>(iov[0].Data.ToPointer(), iov[0].Length).ToArray();
                    encryptedLength = iov[1].Length;
                    paddingLength = iov[2].Length;

                    return header;
                }
            }
        }
    }

    public override byte[] Unwrap(Span<byte> data)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot unwrap without a completed context");

        (byte[] unwrappedData, bool _1, int _2) = GSSAPI.Unwrap(_context, data);
        return unwrappedData;
    }

    public override Span<byte> UnwrapWinRM(Span<byte> data)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot unwrap without a completed context");

        /*
            Using Unwrap is required for NTLM as it does not support IOV buffers and by chance it also works for
            Kerberos when using AES encryption. Kerberos RC4 encryption requires the use of UnwrapIOV due to the
            padding that is used on the algorithm. UnwrapIOV also works with Kerberos AES but there is a bug on Heimdal
            that breaks UnwrapIOV with how WinRM payloads are encrypted. Until Heimdal has been updated to v8+ this
            code will continue to use Unwrap for NTLM and Kerb on Heimdal and will use UnwrapIOV for Kerb on MIT. This
            ensures that AES is supported on all main platforms and RC4 works on at least MIT based systems. If
            affected by this, just don't use RC4 encryption!
            https://github.com/heimdal/heimdal/issues/739
        */

        int headerLength = BitConverter.ToInt32(data[..4]);

        if (_negotiatedMech?.SequenceEqual(GSSAPI.NTLM) == true || GlobalState.GssapiProvider != GssapiProvider.MIT)
        {
            // gss_unwrap doesn't decrypt in place which the caller is expecting. The output array needs to be copied
            // back into the input span.
            byte[] unwrappedData = Unwrap(data[4..]);

            Span<byte> decData = data.Slice(4 + headerLength, unwrappedData.Length);
            unwrappedData.CopyTo(decData);

            return decData;
        }
        else
        {
            Span<byte> header = data.Slice(4, headerLength);
            Span<byte> encData = data[(4 + headerLength)..];

            unsafe
            {
                fixed (byte* headerPtr = header, encDataPtr = encData)
                {
                    Span<IOVBuffer> iov = stackalloc IOVBuffer[3];
                    iov[0].Flags = IOVBufferFlags.NONE;
                    iov[0].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_HEADER;
                    iov[0].Data = (IntPtr)headerPtr;
                    iov[0].Length = headerLength;

                    iov[1].Flags = IOVBufferFlags.NONE;
                    iov[1].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_DATA;
                    iov[1].Data = (IntPtr)encDataPtr;
                    iov[1].Length = encData.Length;

                    // Stores the padding info, we don't need to return this but it is necessary to have it in the IOV
                    // buffer.
                    iov[2].Flags = IOVBufferFlags.GSS_IOV_BUFFER_FLAG_ALLOCATE;
                    iov[2].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_DATA;
                    iov[2].Data = IntPtr.Zero;
                    iov[2].Length = 0;

                    using IOVResult res = GSSAPI.UnwrapIOV(_context, iov);

                    // IOV will decrypt the data in place, no need for a copy, just return a span that tells the caller
                    // the location of the decrypted payload.
                    return encData[..iov[1].Length];
                }
            }
        }
    }

    public override void SetChannelBindings(ChannelBindings? bindings)
    {
        _bindingData = bindings;
    }

    public override void Dispose()
    {
        _credential?.Dispose();
        _context?.Dispose();
        _targetSpn?.Dispose();
    }
}

internal class SspiContext : SecurityContext
{
    private readonly SafeSspiCredentialHandle _credential;
    private readonly string _targetSpn;
    private readonly InitiatorContextRequestFlags _flags = InitiatorContextRequestFlags.ISC_REQ_MUTUAL_AUTH |
        InitiatorContextRequestFlags.ISC_REQ_INTEGRITY | InitiatorContextRequestFlags.ISC_REQ_SEQUENCE_DETECT |
        InitiatorContextRequestFlags.ISC_REQ_CONFIDENTIALITY;
    private SafeSspiContextHandle? _context;
    private byte[]? _bindingData;
    private UInt32 _blockSize = 0;
    private UInt32 _trailerSize = 0;
    private UInt32 _seqNo = 0;

    public SspiContext(string? username, string? password, AuthenticationMethod method, string target,
        bool requestDelegate)
    {
        _targetSpn = target;

        string package = method == AuthenticationMethod.Kerberos ? "Kerberos" : "Negotiate";
        WinNTAuthIdentity? identity = null;
        if (!string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password))
        {
            string? domain = null;
            if (username?.Contains('\\') == true)
            {
                string[] stringSplit = username.Split('\\', 2);
                domain = stringSplit[0];
                username = stringSplit[1];
            }

            identity = new WinNTAuthIdentity(username, domain, password);
        }
        _credential = SSPI.AcquireCredentialsHandle(null, package, CredentialUse.SECPKG_CRED_OUTBOUND,
            identity).Creds;

        if (requestDelegate)
        {
            _flags |= InitiatorContextRequestFlags.ISC_REQ_DELEGATE;
        }
    }

    public override byte[] Step(byte[]? inputToken = null)
    {
        int bufferCount = 0;
        if (inputToken != null)
            bufferCount++;

        if (_bindingData != null)
            bufferCount++;

        unsafe
        {
            fixed (byte* input = inputToken, cbBuffer = _bindingData)
            {
                Span<Helpers.SecBuffer> inputBuffers = stackalloc Helpers.SecBuffer[bufferCount];
                int idx = 0;

                if (inputToken != null)
                {
                    inputBuffers[idx].cbBuffer = (UInt32)inputToken.Length;
                    inputBuffers[idx].BufferType = (UInt32)SecBufferType.SECBUFFER_TOKEN;
                    inputBuffers[idx].pvBuffer = input;
                    idx++;
                }

                if (_bindingData != null)
                {
                    inputBuffers[idx].cbBuffer = (UInt32)_bindingData.Length;
                    inputBuffers[idx].BufferType = (UInt32)SecBufferType.SECBUFFER_CHANNEL_BINDINGS;
                    inputBuffers[idx].pvBuffer = cbBuffer;
                }

                SspiSecContext context = SSPI.InitializeSecurityContext(_credential, _context, _targetSpn, _flags,
                    TargetDataRep.SECURITY_NATIVE_DREP, inputBuffers, new[] { SecBufferType.SECBUFFER_TOKEN, });
                _context = context.Context;

                if (!context.MoreNeeded)
                {
                    Complete = true;

                    Span<Helpers.SecPkgContext_Sizes> sizes = stackalloc Helpers.SecPkgContext_Sizes[1];
                    fixed (Helpers.SecPkgContext_Sizes* sizesPtr = sizes)
                    {
                        SSPI.QueryContextAttributes(_context, SecPkgAttribute.SECPKG_ATTR_SIZES,
                            (IntPtr)sizesPtr);

                        _trailerSize = sizes[0].cbSecurityTrailer;
                        _blockSize = sizes[0].cbBlockSize;
                    }
                }

                return context.OutputBuffers.Length > 0 ? context.OutputBuffers[0] : Array.Empty<byte>();
            }
        }
    }

    public override byte[] Wrap(Span<byte> data)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        unsafe
        {
            ArrayPool<byte> shared = ArrayPool<byte>.Shared;
            byte[] token = shared.Rent((int)_trailerSize);
            byte[] padding = shared.Rent((int)_blockSize);

            try
            {
                fixed (byte* tokenPtr = token, dataPtr = data, paddingPtr = padding)
                {
                    Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[3];
                    buffers[0].BufferType = (UInt32)SecBufferType.SECBUFFER_TOKEN;
                    buffers[0].cbBuffer = _trailerSize;
                    buffers[0].pvBuffer = tokenPtr;

                    buffers[1].BufferType = (UInt32)SecBufferType.SECBUFFER_DATA;
                    buffers[1].cbBuffer = (UInt32)data.Length;
                    buffers[1].pvBuffer = dataPtr;

                    buffers[2].BufferType = (UInt32)SecBufferType.SECBUFFER_PADDING;
                    buffers[2].cbBuffer = _blockSize;
                    buffers[2].pvBuffer = paddingPtr;

                    SSPI.EncryptMessage(_context, 0, buffers, NextSeqNo());

                    byte[] wrapped = new byte[buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer];
                    int offset = 0;
                    if (buffers[0].cbBuffer > 0)
                    {
                        Buffer.BlockCopy(token, 0, wrapped, offset, (int)buffers[0].cbBuffer);
                        offset += (int)buffers[0].cbBuffer;
                    }

                    Marshal.Copy((IntPtr)dataPtr, wrapped, offset, (int)buffers[1].cbBuffer);
                    offset += (int)buffers[1].cbBuffer;

                    if (buffers[2].cbBuffer > 0)
                    {
                        Buffer.BlockCopy(padding, 0, wrapped, offset, (int)buffers[2].cbBuffer);
                        offset += (int)buffers[2].cbBuffer;
                    }

                    return wrapped;
                }
            }
            finally
            {
                shared.Return(token);
                shared.Return(padding);
            }
        }
    }

    public override byte[] WrapWinRM(Span<byte> data, out int encryptedLength, out int paddingLength)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        unsafe
        {
            ArrayPool<byte> shared = ArrayPool<byte>.Shared;
            byte[] token = shared.Rent((int)_trailerSize);

            try
            {
                fixed (byte* tokenPtr = token, dataPtr = data)
                {
                    Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[2];
                    buffers[0].BufferType = (UInt32)SecBufferType.SECBUFFER_TOKEN;
                    buffers[0].cbBuffer = _trailerSize;
                    buffers[0].pvBuffer = tokenPtr;

                    buffers[1].BufferType = (UInt32)SecBufferType.SECBUFFER_DATA;
                    buffers[1].cbBuffer = (UInt32)data.Length;
                    buffers[1].pvBuffer = dataPtr;

                    SSPI.EncryptMessage(_context, 0, buffers, NextSeqNo());

                    byte[] header = new Span<byte>(buffers[0].pvBuffer, (int)buffers[0].cbBuffer).ToArray();
                    encryptedLength = (int)buffers[1].cbBuffer;
                    paddingLength = 0;

                    return header;
                }
            }
            finally
            {
                shared.Return(token);
            }
        }
    }

    public override byte[] Unwrap(Span<byte> data)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        unsafe
        {
            fixed (byte* dataPtr = data)
            {
                Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[2];
                buffers[0].BufferType = (UInt32)SecBufferType.SECBUFFER_STREAM;
                buffers[0].cbBuffer = (UInt32)data.Length;
                buffers[0].pvBuffer = dataPtr;

                buffers[1].BufferType = (UInt32)SecBufferType.SECBUFFER_DATA;
                buffers[1].cbBuffer = 0;
                buffers[1].pvBuffer = null;

                SSPI.DecryptMessage(_context, buffers, NextSeqNo());

                byte[] unwrapped = new byte[buffers[1].cbBuffer];
                Marshal.Copy((IntPtr)buffers[1].pvBuffer, unwrapped, 0, unwrapped.Length);

                return unwrapped;
            }
        }
    }

    public override Span<byte> UnwrapWinRM(Span<byte> data)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        int headerLength = BitConverter.ToInt32(data[..4]);
        Span<byte> encHeader = data.Slice(4, headerLength);
        Span<byte> encData = data[(4 + headerLength)..];

        unsafe
        {
            fixed (byte* headerPtr = encHeader, dataPtr = encData)
            {
                Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[2];
                buffers[0].BufferType = (UInt32)SecBufferType.SECBUFFER_TOKEN;
                buffers[0].cbBuffer = (UInt32)encHeader.Length;
                buffers[0].pvBuffer = headerPtr;

                buffers[1].BufferType = (UInt32)SecBufferType.SECBUFFER_DATA;
                buffers[1].cbBuffer = (UInt32)encData.Length;
                buffers[1].pvBuffer = dataPtr;

                SSPI.DecryptMessage(_context, buffers, NextSeqNo());

                // Data is decrypted in place, just return a span that points to the decrypted payload.
                return encData[..(int)buffers[1].cbBuffer];
            }
        }
    }

    public override void SetChannelBindings(ChannelBindings? bindings)
    {
        if (bindings == null)
            return;

        int structOffset = Marshal.SizeOf<Helpers.SEC_CHANNEL_BINDINGS>();
        int binaryLength = bindings.InitiatorAddr?.Length ?? 0 + bindings.AcceptorAddr?.Length ?? 0 +
            bindings.ApplicationData?.Length ?? 0;
        _bindingData = new byte[structOffset + binaryLength];
        unsafe
        {
            fixed (byte* bindingPtr = _bindingData)
            {
                Helpers.SEC_CHANNEL_BINDINGS* bindingStruct = (Helpers.SEC_CHANNEL_BINDINGS*)bindingPtr;

                bindingStruct->dwInitiatorAddrType = (UInt32)bindings.InitiatorAddrType;
                if (bindings.InitiatorAddr != null)
                {
                    bindingStruct->cbInitiatorLength = (UInt32)bindings.InitiatorAddr.Length;
                    bindingStruct->dwInitiatorOffset = (UInt32)structOffset;
                    Buffer.BlockCopy(bindings.InitiatorAddr, 0, _bindingData, structOffset,
                        bindings.InitiatorAddr.Length);

                    structOffset += bindings.InitiatorAddr.Length;
                }

                bindingStruct->dwAcceptorAddrType = (UInt32)bindings.AcceptorAddrType;
                if (bindings.AcceptorAddr != null)
                {
                    bindingStruct->cbAcceptorLength = (UInt32)bindings.AcceptorAddr.Length;
                    bindingStruct->dwAcceptorOffset = (UInt32)structOffset;
                    Buffer.BlockCopy(bindings.AcceptorAddr, 0, _bindingData, structOffset,
                        bindings.AcceptorAddr.Length);

                    structOffset += bindings.AcceptorAddr.Length;
                }

                if (bindings.ApplicationData != null)
                {
                    bindingStruct->cbApplicationDataLength = (UInt32)bindings.ApplicationData.Length;
                    bindingStruct->dwApplicationDataOffset = (UInt32)structOffset;
                    Buffer.BlockCopy(bindings.ApplicationData, 0, _bindingData, structOffset,
                        bindings.ApplicationData.Length);
                }
            }
        }
    }

    private UInt32 NextSeqNo()
    {
        UInt32 seqNo = _seqNo;
        _seqNo++;

        return seqNo;
    }

    public override void Dispose()
    {
        _credential.Dispose();
        _context?.Dispose();
    }
}
