using PSWSMan.Authentication.Native;
using PSWSMan.Connection;
using System;
using System.Security.Authentication;
using System.Buffers.Binary;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PSWSMan.Authentication;

internal sealed unsafe class GssapiCredential : WSManCredential
{
    private readonly GssapiProvider _provider;
    private readonly byte[] _mech;
    private readonly NegotiateOptions _options;
    private readonly SafeGssapiCred? _credential;

    // Every context created from this credential shares the same gss_cred_id_t. MIT krb5 crashes inside
    // gss_init_sec_context when two threads initiate contexts on one credential at the same time, which
    // happens when several pooled connections reconnect together, so the handshake steps are serialised here.
    private readonly object _stepLock = new();

    internal GssapiCredential(GssapiProvider provider, string? username, string? password, NegotiateMethod method,
        NegotiateOptions options)
    {
        _options = options;
        _provider = provider;
        _mech = method switch
        {
            NegotiateMethod.NTLM => GssapiOid.NTLM,
            NegotiateMethod.Kerberos => GssapiOid.KERBEROS,
            _ => GssapiOid.SPNEGO,
        };

        // Without a username the default credential of the process is used, GSS_C_NO_CREDENTIAL.
        if (string.IsNullOrEmpty(username))
        {
            return;
        }

        using SafeGssapiOidSet mechs = provider.CreateEmptyOidSet();
        provider.AddOidSetMember(_mech, mechs);
        if (provider.IsHeimdal && method == NegotiateMethod.Negotiate)
        {
            // Heimdal needs the concrete mechanisms alongside SPNEGO for the credential to be usable with them.
            provider.AddOidSetMember(GssapiOid.KERBEROS, mechs);
            provider.AddOidSetMember(GssapiOid.NTLM, mechs);
        }

        using SafeGssapiName name = provider.ImportName(Encoding.UTF8.GetBytes(username),
            GssapiOid.GSS_C_NT_USER_NAME);
        _credential = string.IsNullOrEmpty(password)
            ? provider.AcquireCred(name, 0, mechs, GssapiCredUsage.GSS_C_INITIATE, null, null)
            : provider.AcquireCredWithPassword(name, Encoding.UTF8.GetBytes(password), 0, mechs,
                GssapiCredUsage.GSS_C_INITIATE, null, null);
    }

    public override IWSManAuthenticationContext CreateAuthContext(X509Certificate2? serverCertificate)
        => new GssapiAuthContext(_provider, _credential, _stepLock, _mech, _options, serverCertificate);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _credential?.Dispose();
        }

        base.Dispose(disposing);
    }
}

internal sealed unsafe class GssapiAuthContext : NegotiateAuthContext, IWSManEncryptionContext
{
    private readonly GssapiProvider _provider;
    private readonly SafeGssapiCred? _credential;
    private readonly object _stepLock;
    private readonly string _wsmanAuthHeader;
    private readonly string _wsmanEncryptionProtocol;
    private readonly byte[] _mech;

    // Imported on the first Step call. Contexts are also created just to probe what they support so this work is
    // not done in the constructor.
    private SafeGssapiName? _targetName;

    private SafeGssapiSecContext? _context;
    private byte[]? _negotiatedMech;
    private bool _complete;
    private int? _wrapHeaderLength;

    // False until Step has completed the context and recorded the mechanism.
    private bool IsNtlm => _negotiatedMech is not null && _negotiatedMech.AsSpan().SequenceEqual(GssapiOid.NTLM);

    // GSS.framework places the NTLM wrap header at the end of the token rather than the front Windows expects.
    private bool IsNtlmOnGssFramework => IsNtlm && _provider.IsGssFramework;

    public override bool Complete => _complete;

    public override string HttpAuthLabel => _wsmanAuthHeader;

    public string EncryptionProtocol => _wsmanEncryptionProtocol;

    public int MaxEncryptionChunkSize => -1;

    internal GssapiAuthContext(GssapiProvider provider, SafeGssapiCred? credential, object stepLock, byte[] mech,
        NegotiateOptions options, X509Certificate2? serverCertificate) : base(options, serverCertificate)
    {
        _provider = provider;
        _credential = credential;
        _stepLock = stepLock;
        _mech = mech;

        if (mech.AsSpan().SequenceEqual(GssapiOid.KERBEROS))
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
        // See GssapiCredential, contexts sharing a credential must not step concurrently.
        lock (_stepLock)
        {
            return StepCore(inToken);
        }
    }

    private byte[]? StepCore(Span<byte> inToken)
    {
        if (inToken.IsEmpty && _context?.IsInvalid == false)
        {
            // gss_init_sec_context on an existing context needs the acceptor's token, MIT krb5 dereferences a
            // missing one rather than reporting it.
            throw new AuthenticationException(
                $"WinRM {_wsmanAuthHeader} authentication failure - the server did not provide a token to continue the exchange");
        }

        if (_targetName is null)
        {
            string target = $"{Options.SPNService ?? "host"}@{Options.SPNHostName ?? "unknown"}";
            _targetName = _provider.ImportName(Encoding.UTF8.GetBytes(target), GssapiOid.GSS_C_NT_HOSTBASED_SERVICE);
        }
        _context ??= new SafeGssapiSecContext(_provider);

        fixed (byte* initiatorAddr = Bindings?.InitiatorAddr)
        fixed (byte* acceptorAddr = Bindings?.AcceptorAddr)
        fixed (byte* applicationData = Bindings?.ApplicationData)
        {
            GssChannelBindings bindings = new()
            {
                InitiatorAddrType = (uint)(Bindings?.InitiatorAddrType ?? 0),
                InitiatorAddr = initiatorAddr,
                InitiatorLength = Bindings?.InitiatorAddr?.Length ?? 0,
                AcceptorAddrType = (uint)(Bindings?.AcceptorAddrType ?? 0),
                AcceptorAddr = acceptorAddr,
                AcceptorLength = Bindings?.AcceptorAddr?.Length ?? 0,
                ApplicationData = applicationData,
                ApplicationLength = Bindings?.ApplicationData?.Length ?? 0,
            };

            // The library allocates the output token, it is copied out and released before returning.
            void* actualMech = null;
            Helpers.gss_buffer_desc outputToken = default;
            try
            {
                bool continueNeeded = _provider.InitSecContext(
                    _credential,
                    _context,
                    _targetName,
                    _mech,
                    (GssapiContextFlags)Options.Flags,
                    0,
                    Bindings is null ? null : &bindings,
                    inToken,
                    &actualMech,
                    &outputToken,
                    null,
                    null);

                if (!continueNeeded)
                {
                    _complete = true;
                    _negotiatedMech = _provider.ReadOid(actualMech).ToArray();
                }

                return outputToken.length > 0
                    ? new ReadOnlySpan<byte>(outputToken.value, (int)outputToken.length).ToArray()
                    : null;
            }
            finally
            {
                _provider.ReleaseBuffer(&outputToken);
            }
        }
    }

    protected internal override byte[] Wrap(Span<byte> data) => WrapToBlock(data, 0);

    /// <summary>Wraps the data with <c>gss_wrap</c> into a new array with free bytes in front for the caller.</summary>
    /// <param name="data">The data to wrap.</param>
    /// <param name="prefixLength">The number of bytes to leave free at the start of the array.</param>
    /// <returns>The array holding the prefix followed by the wrapped token, header first.</returns>
    private byte[] WrapToBlock(ReadOnlySpan<byte> data, int prefixLength)
    {
        if (_context is null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        Helpers.gss_buffer_desc output = default;
        try
        {
            _provider.Wrap(_context, 1, 0, data, null, &output);
            ReadOnlySpan<byte> wrapped = new(output.value, (int)output.length);

            byte[] block = new byte[prefixLength + wrapped.Length];
            if (IsNtlmOnGssFramework)
            {
                // Move the 16 byte header from the end of the token to the front as Windows expects.
                wrapped[^16..].CopyTo(block.AsSpan(prefixLength));
                wrapped[..^16].CopyTo(block.AsSpan(prefixLength + 16));
            }
            else
            {
                wrapped.CopyTo(block.AsSpan(prefixLength));
            }

            return block;
        }
        finally
        {
            _provider.ReleaseBuffer(&output);
        }
    }

    protected internal override Span<byte> Unwrap(Span<byte> data)
    {
        if (_context is null)
            throw new InvalidOperationException("Cannot unwrap without a completed context");

        ReadOnlySpan<byte> wrapped = data;
        if (IsNtlmOnGssFramework)
        {
            // Move the 16 byte header from the front of the token to the end where GSS.framework expects it.
            byte[] swapped = new byte[data.Length];
            data[16..].CopyTo(swapped);
            data[..16].CopyTo(swapped.AsSpan(data.Length - 16));
            wrapped = swapped;
        }

        Helpers.gss_buffer_desc output = default;
        try
        {
            _provider.Unwrap(_context, wrapped, &output, null, null);

            // gss_unwrap allocates its own output so it is copied back over the input to keep the in place contract.
            Span<byte> plaintext = data[..(int)output.length];
            new ReadOnlySpan<byte>(output.value, (int)output.length).CopyTo(plaintext);
            return plaintext;
        }
        finally
        {
            _provider.ReleaseBuffer(&output);
        }
    }

    public ReadOnlyMemory<byte> WrapWinRM(ReadOnlySpan<byte> data, out int paddingLength)
    {
        if (_context is null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        if (IsNtlm)
        {
            // NTLM doesn't support the IOV functions, gss_wrap returns the 16 byte header followed by the data
            // which is exactly the block layout after the length prefix. NTLM never pads.
            byte[] ntlmBlock = WrapToBlock(data, 4);
            BinaryPrimitives.WriteInt32LittleEndian(ntlmBlock, 16);

            paddingLength = 0;
            return ntlmBlock;
        }

        // The header length is constant for a context so it is queried once, letting the block be laid out and the
        // data encrypted in place inside it. Padding is only added by the legacy RC4 and DES etypes, AES uses
        // ciphertext stealing. The padding bytes are not sent, only their count is reported.
        int headerLength = GetHeaderLength(data.Length);
        byte[] block = new byte[4 + headerLength + data.Length];
        BinaryPrimitives.WriteInt32LittleEndian(block, headerLength);
        data.CopyTo(block.AsSpan(4 + headerLength));

        fixed (byte* blockPtr = block)
        {
            Span<IOVBuffer> iov = stackalloc IOVBuffer[3];
            iov[0].Flags = IOVBufferFlags.GSS_IOV_BUFFER_FLAG_ALLOCATE;
            iov[0].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_HEADER;

            iov[1].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_DATA;
            iov[1].Data = blockPtr + 4 + headerLength;
            iov[1].Length = data.Length;

            iov[2].Flags = IOVBufferFlags.GSS_IOV_BUFFER_FLAG_ALLOCATE;
            iov[2].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_PADDING;

            try
            {
                _provider.WrapIov(_context, 1, 0, null, iov);

                if (iov[0].Length != headerLength)
                {
                    throw new InvalidOperationException(
                        $"GSSAPI produced a {iov[0].Length} byte header but gss_wrap_iov_length reported {headerLength}");
                }
                new ReadOnlySpan<byte>(iov[0].Data, iov[0].Length).CopyTo(block.AsSpan(4));

                paddingLength = iov[2].Length;
                return block;
            }
            finally
            {
                _provider.ReleaseIovBuffer(iov);
            }
        }
    }

    private int GetHeaderLength(int dataLength)
    {
        if (_wrapHeaderLength is int cached)
        {
            return cached;
        }

        Span<IOVBuffer> iov = stackalloc IOVBuffer[3];
        iov[0].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_HEADER;
        iov[1].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_DATA;
        iov[1].Length = dataLength;
        iov[2].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_PADDING;
        _provider.WrapIovLength(_context!, 1, 0, null, iov);

        _wrapHeaderLength = iov[0].Length;
        return iov[0].Length;
    }

    public Span<byte> UnwrapWinRM(Span<byte> block)
    {
        if (_context is null)
            throw new InvalidOperationException("Cannot unwrap without a completed context");

        // The length prefix is the header length for GSSAPI.
        int headerLength = BinaryPrimitives.ReadInt32LittleEndian(block);
        Span<byte> wrapped = block[4..];
        Span<byte> header = wrapped[..headerLength];
        Span<byte> encData = wrapped[headerLength..];

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
        if (IsNtlm || _provider.IsHeimdal)
        {
            return Unwrap(wrapped);
        }

        fixed (byte* headerPtr = header, encDataPtr = encData)
        {
            Span<IOVBuffer> iov = stackalloc IOVBuffer[3];
            iov[0].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_HEADER;
            iov[0].Data = headerPtr;
            iov[0].Length = header.Length;

            iov[1].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_DATA;
            iov[1].Data = encDataPtr;
            iov[1].Length = encData.Length;

            // Receives the padding info, it is not needed but the buffer must be present.
            iov[2].Flags = IOVBufferFlags.GSS_IOV_BUFFER_FLAG_ALLOCATE;
            iov[2].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_DATA;

            try
            {
                _provider.UnwrapIov(_context, null, null, iov);

                // The data is decrypted in place, just return the slice holding the plaintext.
                return encData[..iov[1].Length];
            }
            finally
            {
                _provider.ReleaseIovBuffer(iov);
            }
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _context?.Dispose();
            _context = null;
            _targetName?.Dispose();
            _targetName = null;
        }

        base.Dispose(disposing);
    }
}
