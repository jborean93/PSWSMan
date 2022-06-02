using PSWSMan.Native;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace PSWSMan;

internal enum GssapiProvider
{
    None,
    MIT,
    Heimdal,
    GSSFramework,
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

internal abstract class SecurityContext : IDisposable
{
    public bool Complete { get; internal set; }
    public virtual ChannelBindings? ChannelBindings { set { return; } }

    public abstract byte[] Step(byte[]? inputToken = null);
    public abstract (byte[], byte[], int) Wrap(Span<byte> data);
    public abstract Span<byte> Unwrap(Span<byte> data, int headerLength);
    public virtual void SetChannelBindings(ChannelBindings? bindings) { return; }

    public abstract void Dispose();
    ~SecurityContext() => Dispose();
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

    public GssapiContext(string? username, string? password, AuthenticationMethod method, string target)
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

    public override (byte[], byte[], int) Wrap(Span<byte> data)
    {
        if (_context == null || !Complete)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        if (_negotiatedMech?.SequenceEqual(GSSAPI.NTLM) == true)
        {
            // NTLM doesn't support gss_wrap_iov but luckily the header is always 16 bytes and there is no padding so
            // gss_wrap can be used instead.
            (byte[] wrappedData, bool _) = GSSAPI.Wrap(_context, true, 0, data);
            Span<byte> wrappedSpan = wrappedData.AsSpan();

            return (wrappedSpan[..16].ToArray(), wrappedData[16..].ToArray(), 0);
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
                    byte[] header = new byte[iov[0].Length];
                    Marshal.Copy(iov[0].Data, header, 0, header.Length);

                    Span<byte> encData = new(iov[1].Data.ToPointer(), iov[1].Length);

                    return (header, encData.ToArray(), iov[2].Length);
                }
            }
        }
    }

    public override Span<byte> Unwrap(Span<byte> data, int headerLength)
    {
        if (_context == null || !Complete)
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

        if (_negotiatedMech?.SequenceEqual(GSSAPI.NTLM) == true || GlobalState.GssapiProvider != GssapiProvider.MIT)
        {
            (byte[] unwrappedData, bool _1, int _2) = GSSAPI.Unwrap(_context, data);
            return unwrappedData;
        }
        else
        {
            Span<byte> header = data[..headerLength];
            Span<byte> encData = data[headerLength..];

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

                    iov[2].Flags = IOVBufferFlags.GSS_IOV_BUFFER_FLAG_ALLOCATE;
                    iov[2].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_DATA;
                    iov[2].Data = IntPtr.Zero;
                    iov[2].Length = 0;

                    using IOVResult res = GSSAPI.UnwrapIOV(_context, iov);
                    return new Span<byte>(iov[1].Data.ToPointer(), iov[1].Length);
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

    public SspiContext(string? username, string? password, AuthenticationMethod method, string target)
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

    public override (byte[], byte[], int) Wrap(Span<byte> data)
    {
        if (_context == null || !Complete)
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

                    byte[] header = new byte[buffers[0].cbBuffer];
                    Buffer.BlockCopy(token, 0, header, 0, (int)buffers[0].cbBuffer);

                    byte[] encData = new byte[buffers[1].cbBuffer];
                    Marshal.Copy((IntPtr)dataPtr, encData, 0, (int)buffers[1].cbBuffer);

                    return (header, encData, 0);
                }
            }
            finally
            {
                shared.Return(token);
            }
        }
    }

    public override Span<byte> Unwrap(Span<byte> data, int headerLength)
    {
        if (_context == null || !Complete)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        Span<byte> encHeader = data[..headerLength];
        Span<byte> encData = data[headerLength..];

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
