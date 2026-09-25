using PSWSMan.Authentication.Native;
using PSWSMan.Connection;
using System;
using System.Security.Authentication;
using System.Buffers.Binary;
using System.Security.Cryptography.X509Certificates;

namespace PSWSMan.Authentication;

internal sealed class SspiCredential : WSManCredential
{
    private readonly NegotiateMethod _authMethod;
    private readonly SspiProvider _provider;
    private readonly NegotiateOptions _options;
    private readonly SafeSspiCredentialHandle _credential;

    internal SspiCredential(SspiProvider provider, string? username, string? password, NegotiateMethod method,
        NegotiateOptions options)
    {
        _options = options;
        _authMethod = method;
        _provider = provider;

        string package = method switch
        {
            NegotiateMethod.NTLM => "NTLM",
            NegotiateMethod.Kerberos => "Kerberos",
            _ => "Negotiate",
        };
        string? domain = null;
        bool explicitIdentity = !string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password);
        if (explicitIdentity && username?.Contains('\\') == true)
        {
            string[] stringSplit = username.Split('\\', 2);
            domain = stringSplit[0];
            username = stringSplit[1];
        }

        unsafe
        {
            // SSPI takes the identity as an opaque pointer that only needs to stay valid for the call.
            fixed (char* userPtr = username, domainPtr = domain, passPtr = password)
            {
                Helpers.SEC_WINNT_AUTH_IDENTITY_W identity = new()
                {
                    User = userPtr,
                    UserLength = (uint)(username?.Length ?? 0),
                    Domain = domainPtr,
                    DomainLength = (uint)(domain?.Length ?? 0),
                    Password = passPtr,
                    PasswordLength = (uint)(password?.Length ?? 0),
                    Flags = WinNTAuthIdentityFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE,
                };

                _credential = _provider.AcquireCredentialsHandle(null, package, CredentialUse.SECPKG_CRED_OUTBOUND,
                    explicitIdentity ? &identity : null, null);
            }
        }
    }

    public override IWSManAuthenticationContext CreateAuthContext(X509Certificate2? serverCertificate)
        => new SspiAuthContext(_provider, _credential, _authMethod, _options, serverCertificate);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _credential.Dispose();
        }

        base.Dispose(disposing);
    }
}

internal sealed unsafe class SspiAuthContext : NegotiateAuthContext, IWSManEncryptionContext
{
    private readonly SspiProvider _provider;
    private readonly SafeSspiCredentialHandle _credential;
    private readonly string _wsmanAuthHeader;
    private readonly string _wsmanEncryptionProtocol;

    // Derived from the options on the first Step call. Contexts are also created just to probe what they support
    // so this work is not done in the constructor.
    private string? _targetSpn;
    private InitiatorContextRequestFlags _contextReq;
    private byte[]? _bindingData;

    private SafeSspiContextHandle? _context;
    private bool _complete;
    private (uint Trailer, uint Block)? _sizes;
    private uint _sendSeqNo;
    private uint _recvSeqNo;

    public override bool Complete => _complete;

    public override string HttpAuthLabel => _wsmanAuthHeader;

    public string EncryptionProtocol => _wsmanEncryptionProtocol;

    public int MaxEncryptionChunkSize => -1;

    internal SspiAuthContext(SspiProvider provider, SafeSspiCredentialHandle credential, NegotiateMethod method,
        NegotiateOptions options, X509Certificate2? serverCertificate) : base(options, serverCertificate)
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

    public override byte[]? Step(Span<byte> inToken)
    {
        if (inToken.IsEmpty && _context is not null)
        {
            // InitializeSecurityContext on an existing context needs the server's token to continue.
            throw new AuthenticationException(
                $"WinRM {HttpAuthLabel} authentication failure - the server did not provide a token to continue the exchange");
        }

        if (_targetSpn is null)
        {
            _targetSpn = $"{Options.SPNService ?? "host"}/{Options.SPNHostName ?? "unknown"}";
            _contextReq = ConvertRequestFlags(Options.Flags);
            _bindingData = ConvertChannelBindings(Bindings);
        }

        int bufferCount = 0;
        if (inToken.Length > 0)
            bufferCount++;
        if (_bindingData is not null)
            bufferCount++;

        fixed (byte* inputPtr = inToken, bindingPtr = _bindingData)
        {
            Span<Helpers.SecBuffer> inputBuffers = stackalloc Helpers.SecBuffer[bufferCount];
            int idx = 0;

            if (inToken.Length > 0)
            {
                inputBuffers[idx].cbBuffer = (uint)inToken.Length;
                inputBuffers[idx].BufferType = (uint)SecBufferType.SECBUFFER_TOKEN;
                inputBuffers[idx].pvBuffer = inputPtr;
                idx++;
            }

            if (_bindingData is not null)
            {
                inputBuffers[idx].cbBuffer = (uint)_bindingData.Length;
                inputBuffers[idx].BufferType = (uint)SecBufferType.SECBUFFER_CHANNEL_BINDINGS;
                inputBuffers[idx].pvBuffer = bindingPtr;
            }

            // The package allocates the output token, it is copied out and freed before returning.
            Span<Helpers.SecBuffer> outputBuffers = stackalloc Helpers.SecBuffer[1];
            outputBuffers[0].BufferType = (uint)SecBufferType.SECBUFFER_TOKEN;

            try
            {
                SspiSecContext context = _provider.InitializeSecurityContext(_credential, _context, _targetSpn,
                    _contextReq, TargetDataRep.SECURITY_NATIVE_DREP, inputBuffers, outputBuffers, null);
                _context = context.Context;

                if (!context.MoreNeeded)
                {
                    _complete = true;
                }

                return outputBuffers[0].cbBuffer > 0
                    ? new ReadOnlySpan<byte>(outputBuffers[0].pvBuffer, (int)outputBuffers[0].cbBuffer).ToArray()
                    : null;
            }
            finally
            {
                if (outputBuffers[0].pvBuffer != null)
                {
                    _provider.FreeContextBuffer(outputBuffers[0].pvBuffer);
                }
            }
        }
    }

    protected internal override byte[] Wrap(Span<byte> data)
    {
        byte[] block = EncryptBlock(data, 0, out int tokenLength, out int paddingLength);

        // The block is only trimmed when the package used less than the reserved space.
        int length = tokenLength + data.Length + paddingLength;
        return block.Length == length ? block : block.AsSpan(0, length).ToArray();
    }

    protected internal override Span<byte> Unwrap(Span<byte> data)
    {
        if (_context is null)
            throw new InvalidOperationException("Cannot unwrap without a completed context");

        fixed (byte* dataPtr = data)
        {
            Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[2];
            buffers[0].BufferType = (uint)SecBufferType.SECBUFFER_STREAM;
            buffers[0].cbBuffer = (uint)data.Length;
            buffers[0].pvBuffer = dataPtr;

            buffers[1].BufferType = (uint)SecBufferType.SECBUFFER_DATA;
            buffers[1].cbBuffer = 0;
            buffers[1].pvBuffer = null;

            _provider.DecryptMessage(_context, buffers, _recvSeqNo++, null);

            // The package points the data buffer at the plaintext inside the stream buffer.
            int offset = (int)(buffers[1].pvBuffer - dataPtr);
            return data.Slice(offset, (int)buffers[1].cbBuffer);
        }
    }

    public ReadOnlyMemory<byte> WrapWinRM(ReadOnlySpan<byte> data, out int paddingLength)
    {
        byte[] block = EncryptBlock(data, 4, out int tokenLength, out paddingLength);
        BinaryPrimitives.WriteInt32LittleEndian(block, tokenLength);

        // The padding bytes are counted in paddingLength but are not part of the block, matching the Windows client.
        return new ReadOnlyMemory<byte>(block, 0, 4 + tokenLength + data.Length);
    }

    public Span<byte> UnwrapWinRM(Span<byte> block)
    {
        if (_context is null)
            throw new InvalidOperationException("Cannot unwrap without a completed context");

        // The length prefix is the signature length for SSPI.
        int headerLength = BinaryPrimitives.ReadInt32LittleEndian(block);
        Span<byte> wrapped = block[4..];
        Span<byte> header = wrapped[..headerLength];
        Span<byte> encData = wrapped[headerLength..];

        fixed (byte* headerPtr = header, dataPtr = encData)
        {
            Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[2];
            buffers[0].BufferType = (uint)SecBufferType.SECBUFFER_TOKEN;
            buffers[0].cbBuffer = (uint)header.Length;
            buffers[0].pvBuffer = headerPtr;

            buffers[1].BufferType = (uint)SecBufferType.SECBUFFER_DATA;
            buffers[1].cbBuffer = (uint)encData.Length;
            buffers[1].pvBuffer = dataPtr;

            _provider.DecryptMessage(_context, buffers, _recvSeqNo++, null);

            // Data is decrypted in place, just return a span that points to the decrypted payload.
            return encData[..(int)buffers[1].cbBuffer];
        }
    }

    /// <summary>Gets the trailer and block sizes the package needs for EncryptMessage.</summary>
    /// <remarks>
    /// Queried on first use rather than when the context completes. CredSSP wraps with an NTLM over SPNEGO context
    /// before the server's final token has been processed, so the context may not be complete at the first wrap.
    /// </remarks>
    private (uint Trailer, uint Block) GetSizes()
    {
        if (_sizes is null)
        {
            Helpers.SecPkgContext_Sizes sizes;
            _provider.QueryContextAttributes(_context!, SecPkgAttribute.SECPKG_ATTR_SIZES, &sizes);
            _sizes = (sizes.cbSecurityTrailer, sizes.cbBlockSize);
        }

        return _sizes.Value;
    }

    /// <summary>Encrypts the data into a new block laid out as <c>[prefix][token][data][padding]</c>.</summary>
    /// <remarks>
    /// <c>cbSecurityTrailer</c> and <c>cbBlockSize</c> are upper bounds so the block reserves that much and the data
    /// is encrypted in place inside it. The package reports the real sizes and the data and padding are shifted down
    /// to sit directly after the token, so the block may be longer than the message and the caller slices it with
    /// the reported lengths. The prefix bytes are left for the caller to fill.
    /// </remarks>
    private byte[] EncryptBlock(ReadOnlySpan<byte> data, int prefixLength, out int tokenLength,
        out int paddingLength)
    {
        if (_context is null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        (uint trailerSize, uint blockSize) = GetSizes();
        int reservedToken = (int)trailerSize;
        int reservedPadding = (int)blockSize;
        int dataOffset = prefixLength + reservedToken;

        byte[] block = new byte[dataOffset + data.Length + reservedPadding];
        data.CopyTo(block.AsSpan(dataOffset));

        fixed (byte* blockPtr = block)
        {
            Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[3];
            buffers[0].BufferType = (uint)SecBufferType.SECBUFFER_TOKEN;
            buffers[0].cbBuffer = (uint)reservedToken;
            buffers[0].pvBuffer = blockPtr + prefixLength;

            buffers[1].BufferType = (uint)SecBufferType.SECBUFFER_DATA;
            buffers[1].cbBuffer = (uint)data.Length;
            buffers[1].pvBuffer = blockPtr + dataOffset;

            buffers[2].BufferType = (uint)SecBufferType.SECBUFFER_PADDING;
            buffers[2].cbBuffer = (uint)reservedPadding;
            buffers[2].pvBuffer = reservedPadding > 0 ? blockPtr + dataOffset + data.Length : null;

            _provider.EncryptMessage(_context, 0, buffers, _sendSeqNo++);

            tokenLength = (int)buffers[0].cbBuffer;
            paddingLength = (int)buffers[2].cbBuffer;
        }

        if (tokenLength < reservedToken)
        {
            block.AsSpan(dataOffset, data.Length + paddingLength).CopyTo(block.AsSpan(prefixLength + tokenLength));
        }

        return block;
    }

    private static InitiatorContextRequestFlags ConvertRequestFlags(NegotiateRequestFlags flags)
    {
        InitiatorContextRequestFlags contextReq = InitiatorContextRequestFlags.ISC_REQ_ALLOCATE_MEMORY;
        if (flags.HasFlag(NegotiateRequestFlags.Delegate) || flags.HasFlag(NegotiateRequestFlags.DelegatePolicy))
        {
            contextReq |= InitiatorContextRequestFlags.ISC_REQ_DELEGATE;
        }
        if (flags.HasFlag(NegotiateRequestFlags.MutualAuth))
        {
            contextReq |= InitiatorContextRequestFlags.ISC_REQ_MUTUAL_AUTH;
        }
        if (flags.HasFlag(NegotiateRequestFlags.ReplayDetect))
        {
            contextReq |= InitiatorContextRequestFlags.ISC_REQ_REPLAY_DETECT;
        }
        if (flags.HasFlag(NegotiateRequestFlags.SequenceDetect))
        {
            contextReq |= InitiatorContextRequestFlags.ISC_REQ_SEQUENCE_DETECT;
        }
        if (flags.HasFlag(NegotiateRequestFlags.Confidentiality))
        {
            contextReq |= InitiatorContextRequestFlags.ISC_REQ_CONFIDENTIALITY;
        }
        if (flags.HasFlag(NegotiateRequestFlags.Integrity))
        {
            contextReq |= InitiatorContextRequestFlags.ISC_REQ_INTEGRITY;
        }
        if (flags.HasFlag(NegotiateRequestFlags.Identify))
        {
            contextReq |= InitiatorContextRequestFlags.ISC_REQ_IDENTIFY;
        }

        return contextReq;
    }

    private static byte[]? ConvertChannelBindings(ChannelBindings? bindings)
    {
        if (bindings is null)
        {
            return null;
        }

        int structOffset = sizeof(Helpers.SEC_CHANNEL_BINDINGS);
        int binaryLength = (bindings.InitiatorAddr?.Length ?? 0) + (bindings.AcceptorAddr?.Length ?? 0) +
            (bindings.ApplicationData?.Length ?? 0);
        byte[] bindingData = new byte[structOffset + binaryLength];

        fixed (byte* bindingPtr = bindingData)
        {
            Helpers.SEC_CHANNEL_BINDINGS* bindingStruct = (Helpers.SEC_CHANNEL_BINDINGS*)bindingPtr;

            bindingStruct->dwInitiatorAddrType = (uint)bindings.InitiatorAddrType;
            if (bindings.InitiatorAddr is not null)
            {
                bindingStruct->cbInitiatorLength = (uint)bindings.InitiatorAddr.Length;
                bindingStruct->dwInitiatorOffset = (uint)structOffset;
                bindings.InitiatorAddr.CopyTo(bindingData.AsSpan(structOffset));

                structOffset += bindings.InitiatorAddr.Length;
            }

            bindingStruct->dwAcceptorAddrType = (uint)bindings.AcceptorAddrType;
            if (bindings.AcceptorAddr is not null)
            {
                bindingStruct->cbAcceptorLength = (uint)bindings.AcceptorAddr.Length;
                bindingStruct->dwAcceptorOffset = (uint)structOffset;
                bindings.AcceptorAddr.CopyTo(bindingData.AsSpan(structOffset));

                structOffset += bindings.AcceptorAddr.Length;
            }

            if (bindings.ApplicationData is not null)
            {
                bindingStruct->cbApplicationDataLength = (uint)bindings.ApplicationData.Length;
                bindingStruct->dwApplicationDataOffset = (uint)structOffset;
                bindings.ApplicationData.CopyTo(bindingData.AsSpan(structOffset));
            }
        }

        return bindingData;
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
