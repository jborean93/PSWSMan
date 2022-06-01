using PSWSMan.Native;
using System;
using System.Buffers;
using System.Collections.Generic;
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
    public abstract byte[] Wrap(ReadOnlySpan<byte> data, bool encrypt);
    public abstract byte[] Unwrap(ReadOnlySpan<byte> data);
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
        }

        return res.OutputToken ?? Array.Empty<byte>();
    }

    public override byte[] Wrap(ReadOnlySpan<byte> data, bool encrypt)
    {
        if (_context == null || !Complete)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        (byte[] wrappedData, bool _) = GSSAPI.Wrap(_context, encrypt, 0, data);
        return wrappedData;
    }

    public override byte[] Unwrap(ReadOnlySpan<byte> data)
    {
        if (_context == null || !Complete)
            throw new InvalidOperationException("Cannot unwrap without a completed context");

        (byte[] unwrappedData, bool _1, int _2) = GSSAPI.Unwrap(_context, data);
        return unwrappedData;
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
                    inputBuffers[idx].pvBuffer = (IntPtr)input;
                    idx++;
                }

                if (_bindingData != null)
                {
                    inputBuffers[idx].cbBuffer = (UInt32)_bindingData.Length;
                    inputBuffers[idx].BufferType = (UInt32)SecBufferType.SECBUFFER_CHANNEL_BINDINGS;
                    inputBuffers[idx].pvBuffer = (IntPtr)cbBuffer;
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

    public override byte[] Wrap(ReadOnlySpan<byte> data, bool encrypt)
    {
        if (_context == null || !Complete)
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
                    buffers[0].pvBuffer = (IntPtr)tokenPtr;

                    buffers[1].BufferType = (UInt32)SecBufferType.SECBUFFER_DATA;
                    buffers[1].cbBuffer = (UInt32)data.Length;
                    buffers[1].pvBuffer = (IntPtr)dataPtr;

                    buffers[2].BufferType = (UInt32)SecBufferType.SECBUFFER_PADDING;
                    buffers[2].cbBuffer = _blockSize;
                    buffers[2].pvBuffer = (IntPtr)paddingPtr;

                    UInt32 qop = encrypt ? 0 : 0x80000001; // SECQOP_WRAP_NO_ENCRYPT
                    SSPI.EncryptMessage(_context, qop, buffers, NextSeqNo());

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

    public override byte[] Unwrap(ReadOnlySpan<byte> data)
    {
        if (_context == null || !Complete)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        unsafe
        {
            fixed (byte* dataPtr = data)
            {
                Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[2];
                buffers[0].BufferType = (UInt32)SecBufferType.SECBUFFER_STREAM;
                buffers[0].cbBuffer = (UInt32)data.Length;
                buffers[0].pvBuffer = (IntPtr)dataPtr;

                buffers[1].BufferType = (UInt32)SecBufferType.SECBUFFER_DATA;
                buffers[1].cbBuffer = 0;
                buffers[1].pvBuffer = IntPtr.Zero;

                SSPI.DecryptMessage(_context, buffers, NextSeqNo());

                byte[] unwrapped = new byte[buffers[1].cbBuffer];
                Marshal.Copy(buffers[1].pvBuffer, unwrapped, 0, unwrapped.Length);

                return unwrapped;
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
