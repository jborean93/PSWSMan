using PSWSMan.Authentication.Native;
using PSWSMan.Connection;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace PSWSMan.Authentication;

internal sealed class GssapiCredential : WSManCredential
{
    private readonly NegotiateMethod _authMethod;
    private readonly GssapiProvider _provider;
    private readonly byte[] _mech;
    private readonly NegotiateOptions _options;
    private SafeGssapiCred? _credential;

    internal GssapiCredential(GssapiProvider provider, string? username, string? password, NegotiateMethod method,
        NegotiateOptions options)
    {
        _authMethod = method;
        _options = options;
        _provider = provider;
        _mech = method switch
        {
            NegotiateMethod.NTLM => Gssapi.NTLM,
            NegotiateMethod.Kerberos => Gssapi.KERBEROS,
            _ => Gssapi.SPNEGO,
        };

        List<byte[]> mechList = new() { _mech };
        if (provider.IsHeimdal && method == NegotiateMethod.Negotiate)
        {
            mechList.AddRange(new[] { Gssapi.KERBEROS, Gssapi.NTLM });
        }

        SafeGssapiName? name = null;
        if (!string.IsNullOrEmpty(username))
        {
            name = Gssapi.ImportName(provider, username, Gssapi.GSS_C_NT_USER_NAME);
        }

        using (name)
        {
            if (name is not null && !string.IsNullOrEmpty(password))
            {
                _credential = Gssapi.AcquireCredWithPassword(provider, name, password, 0, mechList,
                    GssapiCredUsage.GSS_C_INITIATE).Creds;
            }
            else if (name != null)
            {
                _credential = Gssapi.AcquireCred(provider, name, 0, mechList, GssapiCredUsage.GSS_C_INITIATE).Creds;
            }
        }
    }

    public override IWSManAuthenticationContext CreateAuthContext(X509Certificate2? serverCertificate)
    {
        return new GssapiAuthContext(_provider, _credential, _mech, _options, serverCertificate);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _credential?.Dispose();
            _credential = null;
        }

        base.Dispose(disposing);
    }
}

internal sealed class GssapiAuthContext : NegotiateAuthContext, IWSManEncryptionContext
{
    private readonly GssapiProvider _provider;
    private readonly SafeGssapiCred? _credential;
    private readonly string _wsmanAuthHeader;
    private readonly string _wsmanEncryptionProtocol;
    private readonly byte[] _mech;

    private SafeGssapiSecContext? _context;
    private byte[]? _negotiatedMech;
    private bool _complete;
    private int? _wrapHeaderLength;

    private bool IsNtlm => _negotiatedMech?.SequenceEqual(Gssapi.NTLM) == true;

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

    internal GssapiAuthContext(GssapiProvider provider, SafeGssapiCred? credential, byte[] mech,
        NegotiateOptions options, X509Certificate2? serverCertificate) : base(options, serverCertificate)
    {
        _provider = provider;
        _credential = credential;

        if (mech.SequenceEqual(Gssapi.KERBEROS))
        {
            _wsmanAuthHeader = "Kerberos";
            _wsmanEncryptionProtocol = WSManEncryptionProtocol.KERBEROS;
        }
        else
        {
            _wsmanAuthHeader = "Negotiate";
            _wsmanEncryptionProtocol = WSManEncryptionProtocol.SPNEGO;
        }
        _mech = mech;
    }

    public override byte[]? Step(Span<byte> inToken)
    {
        GssapiContextFlags flags = (GssapiContextFlags)Options.Flags;
        string target = $"{Options.SPNService ?? "host"}@{Options.SPNHostName ?? "unknown"}";
        using SafeGssapiName targetSpn = Gssapi.ImportName(_provider, target, Gssapi.GSS_C_NT_HOSTBASED_SERVICE);

        var res = Gssapi.InitSecContext(_provider, _credential, _context, targetSpn, _mech, flags, 0, Bindings,
            inToken);
        _context = res.Context;

        if (!res.MoreNeeded)
        {
            _complete = true;
            _negotiatedMech = res.MechType;
        }

        return res.OutputToken;
    }

    protected internal override byte[] Wrap(Span<byte> data)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        (byte[] wrappedData, bool _) = Gssapi.Wrap(_provider, _context, true, 0, data);

        if (_negotiatedMech?.SequenceEqual(Gssapi.NTLM) == true && _provider is GSSFrameworkProvider)
        {
            // gss_wrap on macOS for NTLM places the header at the end of the buffer and not the beginning as expected
            // by Windows. It needs to be swapped around
            Span<byte> header = stackalloc byte[16];
            wrappedData.AsSpan(wrappedData.Length - 16, 16).CopyTo(header);

            wrappedData.AsSpan(0, wrappedData.Length - 16).CopyTo(wrappedData.AsSpan(16));
            header.CopyTo(wrappedData.AsSpan(0, 16));
        }

        return wrappedData;
    }

    protected internal override byte[] Unwrap(Span<byte> data)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot unwrap without a completed context");

        if (_negotiatedMech?.SequenceEqual(Gssapi.NTLM) == true && _provider is GSSFrameworkProvider)
        {
            // gss_unwrap on macOS for NTLM requires the header to be placed at the end of the buffer and not the
            // beginning.
            byte[] newBuffer = new byte[data.Length];
            data[16..].CopyTo(newBuffer.AsSpan()[..(data.Length - 16)]);
            data.Slice(0, 16).CopyTo(newBuffer.AsSpan(newBuffer.Length - 16, 16));

            data = newBuffer.AsSpan();
        }

        (byte[] unwrappedData, bool _1, int _2) = Gssapi.Unwrap(_provider, _context, data);

        return unwrappedData;
    }

    public byte[] WrapWinRM(ReadOnlySpan<byte> data, out int paddingLength)
    {
        if (_context == null)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        if (IsNtlm)
        {
            // NTLM doesn't support the IOV functions, gss_wrap returns the 16 byte header followed by the data.
            byte[] wrapped = Wrap(data.ToArray());
            byte[] ntlmBlock = new byte[4 + wrapped.Length];
            BinaryPrimitives.WriteInt32LittleEndian(ntlmBlock, 16);
            wrapped.CopyTo(ntlmBlock, 4);

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

        unsafe
        {
            fixed (byte* dataPtr = block)
            {
                Span<IOVBuffer> iov = stackalloc IOVBuffer[3];
                iov[0].Flags = IOVBufferFlags.GSS_IOV_BUFFER_FLAG_ALLOCATE;
                iov[0].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_HEADER;
                iov[0].Data = IntPtr.Zero;
                iov[0].Length = 0;

                iov[1].Flags = IOVBufferFlags.NONE;
                iov[1].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_DATA;
                iov[1].Data = (IntPtr)(dataPtr + 4 + headerLength);
                iov[1].Length = data.Length;

                iov[2].Flags = IOVBufferFlags.GSS_IOV_BUFFER_FLAG_ALLOCATE;
                iov[2].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_PADDING;
                iov[2].Data = IntPtr.Zero;
                iov[2].Length = 0;

                using IOVResult res = Gssapi.WrapIOV(_provider, _context, true, 0, iov);

                if (iov[0].Length != headerLength)
                {
                    throw new InvalidOperationException(
                        $"GSSAPI produced a {iov[0].Length} byte header but gss_wrap_iov_length reported {headerLength}");
                }
                new Span<byte>(iov[0].Data.ToPointer(), iov[0].Length).CopyTo(block.AsSpan(4));

                paddingLength = iov[2].Length;
                return block;
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
        Gssapi.WrapIOVLength(_provider, _context!, true, 0, iov);

        _wrapHeaderLength = iov[0].Length;
        return iov[0].Length;
    }

    public Span<byte> UnwrapWinRM(Span<byte> block)
    {
        if (_context == null)
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
            // As gss_unwrap doesn't decrypt in place, the output array needs to be copied back into the input span.
            byte[] unwrappedData = Unwrap(wrapped);

            Span<byte> decData = encData[..unwrappedData.Length];
            unwrappedData.CopyTo(decData);

            return decData;
        }
        else
        {
            unsafe
            {
                fixed (byte* headerPtr = header, encDataPtr = encData)
                {
                    Span<IOVBuffer> iov = stackalloc IOVBuffer[3];
                    iov[0].Flags = IOVBufferFlags.NONE;
                    iov[0].Type = IOVBufferType.GSS_IOV_BUFFER_TYPE_HEADER;
                    iov[0].Data = (IntPtr)headerPtr;
                    iov[0].Length = header.Length;

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

                    using IOVResult res = Gssapi.UnwrapIOV(_provider, _context, iov);

                    // IOV will decrypt the data in place, no need for a copy, just return a span that tells the caller
                    // the location of the decrypted payload.
                    return encData[..iov[1].Length];
                }
            }
        }
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
