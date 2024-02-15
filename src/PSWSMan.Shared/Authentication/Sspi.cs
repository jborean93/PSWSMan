using PSWSMan.Shared.Authentication.Native;
using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace PSWSMan.Shared.Authentication;

public sealed class SspiCredential : WSManCredential
{
    private readonly NegotiateMethod _authMethod;
    private readonly SspiProvider _provider;
    private SafeSspiCredentialHandle _credential;

    private bool _isDisposed = false;

    internal SspiCredential(SspiProvider provider, string? username, string? password, NegotiateMethod method)
    {
        _authMethod = method;
        _provider = provider;

        string package = method switch
        {
            NegotiateMethod.NTLM => "NTLM",
            NegotiateMethod.Kerberos => "Kerberos",
            _ => "Negotiate",
        };
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
        _credential = Sspi.AcquireCredentialsHandle(_provider, null, package, CredentialUse.SECPKG_CRED_OUTBOUND,
            identity).Creds;
    }

    protected internal override AuthenticationContext CreateAuthContext()
    {
        return new SspiAuthContext(_provider, _credential, _authMethod);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (!_isDisposed)
            {
                _credential?.Dispose();
            }
            _isDisposed = true;
        }

        base.Dispose(disposing);
    }
}

public sealed class SspiAuthContext : NegotiateAuthContext, IWSManEncryptionContext
{
    private readonly SspiProvider _provider;
    private readonly SafeSspiCredentialHandle _credential;
    private readonly string _wsmanAuthHeader;
    private readonly string _wsmanEncryptionProtocol;

    private SafeSspiContextHandle? _context;
    private bool _complete;
    private UInt32 _blockSize = 0;
    private UInt32 _trailerSize = 0;
    private UInt32 _sendSeqNo = 0;
    private UInt32 _recvSeqNo = 0;

    public override bool Complete => _complete;

    public override string HttpAuthLabel => _wsmanAuthHeader;

    public string EncryptionProtocol
    {
        get => _wsmanEncryptionProtocol;
    }

    public int MaxEncryptionChunkSize
    {
        get => -1;
    }

    internal SspiAuthContext(SspiProvider provider, SafeSspiCredentialHandle credential, NegotiateMethod method)
    {
        _provider = provider;
        _credential = credential;

        if (method == NegotiateMethod.Kerberos)
        {
            _wsmanAuthHeader = "Kerberos";
            _wsmanEncryptionProtocol = WSManEncryptionProtocol.KERBEROS;
        }
        else
        {
            _wsmanAuthHeader = "Negotiate";
            _wsmanEncryptionProtocol = WSManEncryptionProtocol.SPNEGO;
        }
    }

    protected internal override byte[]? Step(Span<byte> inToken, NegotiateOptions options, ChannelBindings? bindings)
    {
        string targetSpn = $"{options.SPNService ?? "host"}/{options.SPNHostName ?? "unknown"}";

        InitiatorContextRequestFlags flags = (InitiatorContextRequestFlags)0;
        if (options.Flags.HasFlag(NegotiateRequestFlags.Delegate) ||
            options.Flags.HasFlag(NegotiateRequestFlags.DelegatePolicy))
        {
            flags |= InitiatorContextRequestFlags.ISC_REQ_DELEGATE;
        }
        if (options.Flags.HasFlag(NegotiateRequestFlags.MutualAuth))
        {
            flags |= InitiatorContextRequestFlags.ISC_REQ_MUTUAL_AUTH;
        }
        if (options.Flags.HasFlag(NegotiateRequestFlags.ReplayDetect))
        {
            flags |= InitiatorContextRequestFlags.ISC_REQ_REPLAY_DETECT;
        }
        if (options.Flags.HasFlag(NegotiateRequestFlags.SequenceDetect))
        {
            flags |= InitiatorContextRequestFlags.ISC_REQ_SEQUENCE_DETECT;
        }
        if (options.Flags.HasFlag(NegotiateRequestFlags.Confidentiality))
        {
            flags |= InitiatorContextRequestFlags.ISC_REQ_CONFIDENTIALITY;
        }
        if (options.Flags.HasFlag(NegotiateRequestFlags.Integrity))
        {
            flags |= InitiatorContextRequestFlags.ISC_REQ_INTEGRITY;
        }
        if (options.Flags.HasFlag(NegotiateRequestFlags.Identify))
        {
            flags |= InitiatorContextRequestFlags.ISC_REQ_IDENTIFY;
        }

        int bufferCount = 0;
        if (inToken.Length > 0)
            bufferCount++;

        byte[]? bindingData = ConvertChannelBindings(bindings);
        if (bindingData != null)
            bufferCount++;

        unsafe
        {
            fixed (byte* input = inToken, cbBuffer = bindingData)
            {
                Span<Helpers.SecBuffer> inputBuffers = stackalloc Helpers.SecBuffer[bufferCount];
                int idx = 0;

                if (inToken != null)
                {
                    inputBuffers[idx].cbBuffer = (UInt32)inToken.Length;
                    inputBuffers[idx].BufferType = (UInt32)SecBufferType.SECBUFFER_TOKEN;
                    inputBuffers[idx].pvBuffer = input;
                    idx++;
                }

                if (bindingData != null)
                {
                    inputBuffers[idx].cbBuffer = (UInt32)bindingData.Length;
                    inputBuffers[idx].BufferType = (UInt32)SecBufferType.SECBUFFER_CHANNEL_BINDINGS;
                    inputBuffers[idx].pvBuffer = cbBuffer;
                }

                SspiSecContext context = Sspi.InitializeSecurityContext(_provider, _credential, _context, targetSpn,
                    flags, TargetDataRep.SECURITY_NATIVE_DREP, inputBuffers,
                    new[] { SecBufferType.SECBUFFER_TOKEN, });
                _context = context.Context;

                if (!context.MoreNeeded)
                {
                    _complete = true;

                    Span<Helpers.SecPkgContext_Sizes> sizes = stackalloc Helpers.SecPkgContext_Sizes[1];
                    fixed (Helpers.SecPkgContext_Sizes* sizesPtr = sizes)
                    {
                        Sspi.QueryContextAttributes(_provider, _context, SecPkgAttribute.SECPKG_ATTR_SIZES,
                            (IntPtr)sizesPtr);

                        _trailerSize = sizes[0].cbSecurityTrailer;
                        _blockSize = sizes[0].cbBlockSize;
                    }
                }

                return context.OutputBuffers.Length > 0 ? context.OutputBuffers[0] : null;
            }
        }
    }

    protected internal override byte[] Wrap(Span<byte> data)
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

                    Sspi.EncryptMessage(_provider, _context, 0, buffers, NextSendSeqNo());

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

    protected internal override byte[] Unwrap(Span<byte> data)
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

                Sspi.DecryptMessage(_provider, _context, buffers, NextRecvSeqNo());

                byte[] unwrapped = new byte[buffers[1].cbBuffer];
                Marshal.Copy((IntPtr)buffers[1].pvBuffer, unwrapped, 0, unwrapped.Length);

                return unwrapped;
            }
        }
    }

    public byte[] WrapWinRM(Span<byte> data, out int headerLength, out int paddingLength)
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

                    Sspi.EncryptMessage(_provider, _context, 0, buffers, NextSendSeqNo());

                    headerLength = (int)buffers[0].cbBuffer;
                    paddingLength = 0;

                    byte[] encData = new byte[headerLength + (int)buffers[1].cbBuffer];
                    new Span<byte>(buffers[0].pvBuffer, (int)buffers[0].cbBuffer).CopyTo(encData);
                    new Span<byte>(buffers[1].pvBuffer, (int)buffers[1].cbBuffer).CopyTo(encData.AsSpan(headerLength));

                    return encData;
                }
            }
            finally
            {
                shared.Return(token);
            }
        }
    }

    public Span<byte> UnwrapWinRM(Span<byte> data, Span<byte> header, Span<byte> encData)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        unsafe
        {
            fixed (byte* headerPtr = header, dataPtr = encData)
            {
                Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[2];
                buffers[0].BufferType = (UInt32)SecBufferType.SECBUFFER_TOKEN;
                buffers[0].cbBuffer = (UInt32)header.Length;
                buffers[0].pvBuffer = headerPtr;

                buffers[1].BufferType = (UInt32)SecBufferType.SECBUFFER_DATA;
                buffers[1].cbBuffer = (UInt32)encData.Length;
                buffers[1].pvBuffer = dataPtr;

                Sspi.DecryptMessage(_provider, _context, buffers, NextRecvSeqNo());

                // Data is decrypted in place, just return a span that points to the decrypted payload.
                return encData[..(int)buffers[1].cbBuffer];
            }
        }
    }

    private byte[]? ConvertChannelBindings(ChannelBindings? bindings)
    {
        if (bindings == null)
        {
            return null;
        }

        int structOffset = Marshal.SizeOf<Helpers.SEC_CHANNEL_BINDINGS>();
        int binaryLength = bindings.InitiatorAddr?.Length ?? 0 + bindings.AcceptorAddr?.Length ?? 0 +
            bindings.ApplicationData?.Length ?? 0;
        byte[] bindingData = new byte[structOffset + binaryLength];
        unsafe
        {
            fixed (byte* bindingPtr = bindingData)
            {
                Helpers.SEC_CHANNEL_BINDINGS* bindingStruct = (Helpers.SEC_CHANNEL_BINDINGS*)bindingPtr;

                bindingStruct->dwInitiatorAddrType = (UInt32)bindings.InitiatorAddrType;
                if (bindings.InitiatorAddr != null)
                {
                    bindingStruct->cbInitiatorLength = (UInt32)bindings.InitiatorAddr.Length;
                    bindingStruct->dwInitiatorOffset = (UInt32)structOffset;
                    Buffer.BlockCopy(bindings.InitiatorAddr, 0, bindingData, structOffset,
                        bindings.InitiatorAddr.Length);

                    structOffset += bindings.InitiatorAddr.Length;
                }

                bindingStruct->dwAcceptorAddrType = (UInt32)bindings.AcceptorAddrType;
                if (bindings.AcceptorAddr != null)
                {
                    bindingStruct->cbAcceptorLength = (UInt32)bindings.AcceptorAddr.Length;
                    bindingStruct->dwAcceptorOffset = (UInt32)structOffset;
                    Buffer.BlockCopy(bindings.AcceptorAddr, 0, bindingData, structOffset,
                        bindings.AcceptorAddr.Length);

                    structOffset += bindings.AcceptorAddr.Length;
                }

                if (bindings.ApplicationData != null)
                {
                    bindingStruct->cbApplicationDataLength = (UInt32)bindings.ApplicationData.Length;
                    bindingStruct->dwApplicationDataOffset = (UInt32)structOffset;
                    Buffer.BlockCopy(bindings.ApplicationData, 0, bindingData, structOffset,
                        bindings.ApplicationData.Length);
                }
            }
        }

        return bindingData;
    }

    private UInt32 NextSendSeqNo()
    {
        UInt32 nextSeqNo = _sendSeqNo;
        _sendSeqNo++;
        return nextSeqNo;
    }

    private UInt32 NextRecvSeqNo()
    {
        UInt32 nextSeqNo = _recvSeqNo;
        _recvSeqNo++;
        return nextSeqNo;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _context?.Dispose();
            _context = null;
        }

        base.Dispose(disposing);
    }
}
