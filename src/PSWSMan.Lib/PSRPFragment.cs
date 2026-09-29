using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace PSWSMan.Lib;

/// <summary>Known PSRP message types, see MS-PSRP 2.2.1.</summary>
public static class PSRPMessageType
{
    /// <summary>SESSION_CAPABILITY, the first message each side sends to open a runspace pool.</summary>
    public const int SessionCapability = 0x00010002;

    /// <summary>INIT_RUNSPACEPOOL, the last message the client sends to open a runspace pool.</summary>
    public const int InitRunspacePool = 0x00010004;

    /// <summary>CREATE_PIPELINE, the message that starts a pipeline.</summary>
    public const int CreatePipeline = 0x00021006;

    /// <summary>
    /// GET_COMMAND_METADATA, the message that starts a command metadata request, used by Enter-PSSession and implicit
    /// remoting in place of CREATE_PIPELINE.
    /// </summary>
    public const int GetCommandMetadata = 0x0002100A;
}

/// <summary>Reads the fragment framing of a PSRP data stream, see MS-PSRP 2.2.4.</summary>
public static class PSRPFragment
{
    // ObjectId (8) FragmentId (8) Flags (1) BlobLength (4), big endian.
    private const int HeaderLength = 21;
    private const byte StartFlag = 0x1;
    private const byte EndFlag = 0x2;

    /// <summary>Whether the data holds every fragment of a message of the given type.</summary>
    /// <param name="data">
    /// The fragment stream from its start. It may end part way through a fragment, as the client splits the stream
    /// into chunks without regard for fragment boundaries.
    /// </param>
    /// <param name="messageType">The message type to look for, see <see cref="PSRPMessageType"/>.</param>
    /// <returns>True once the end fragment of such a message is in the data.</returns>
    /// <exception cref="FormatException">The data is not a valid fragment stream.</exception>
    public static bool ContainsCompleteMessage(ReadOnlySpan<byte> data, int messageType)
        => Find(data, messageType, null);

    /// <summary>Whether the data holds every fragment of its first message, whatever its type.</summary>
    /// <param name="data">The fragment stream from its start, it may end part way through a fragment.</param>
    /// <returns>True once the end fragment of the first message is in the data.</returns>
    /// <exception cref="FormatException">The data is not a valid fragment stream.</exception>
    public static bool ContainsCompleteFirstMessage(ReadOnlySpan<byte> data)
        => Find(data, null, null);

    /// <summary>Reassembles the first complete message of the given type in a fragment stream.</summary>
    /// <param name="data">The fragment stream from its start, it may end part way through a fragment.</param>
    /// <param name="messageType">The message type to look for, see <see cref="PSRPMessageType"/>.</param>
    /// <param name="message">The message, its header and data, when found.</param>
    /// <returns>True if every fragment of such a message is in the data.</returns>
    /// <exception cref="FormatException">The data is not a valid fragment stream.</exception>
    public static bool TryGetMessage(ReadOnlySpan<byte> data, int messageType, [NotNullWhen(true)] out byte[]? message)
    {
        using MemoryStream collected = new();
        if (Find(data, messageType, collected))
        {
            message = collected.ToArray();
            return true;
        }

        message = null;
        return false;
    }

    private static bool Find(ReadOnlySpan<byte> data, int? messageType, MemoryStream? collect)
    {
        long? matchingObject = null;
        int offset = 0;
        while (data.Length - offset >= HeaderLength)
        {
            ReadOnlySpan<byte> header = data.Slice(offset, HeaderLength);
            long objectId = BinaryPrimitives.ReadInt64BigEndian(header);
            byte flags = header[16];
            int blobLength = BinaryPrimitives.ReadInt32BigEndian(header[17..]);
            if (blobLength < 0)
            {
                throw new FormatException($"PSRP fragment at offset {offset} has a negative blob length.");
            }

            int blobOffset = offset + HeaderLength;
            ReadOnlySpan<byte> available = data[blobOffset..];

            // The message header in the blob of the start fragment is Destination (4) then MessageType (4), little
            // endian.
            if (matchingObject is null && (flags & StartFlag) != 0 && available.Length >= 8 &&
                (messageType is null || BinaryPrimitives.ReadInt32LittleEndian(available[4..]) == messageType))
            {
                matchingObject = objectId;
            }

            if (available.Length < blobLength)
            {
                return false;
            }
            if (objectId == matchingObject)
            {
                collect?.Write(available[..blobLength]);
                if ((flags & EndFlag) != 0)
                {
                    return true;
                }
            }

            offset = blobOffset + blobLength;
        }

        return false;
    }
}

/// <summary>Reads PSRP messages, see MS-PSRP 2.2.1.</summary>
public static class PSRPMessage
{
    // Destination (4) MessageType (4) RPID (16) PID (16).
    private const int HeaderLength = 40;

    /// <summary>Reads the protocolversion a SESSION_CAPABILITY message advertises.</summary>
    /// <param name="message">The whole message, its header and data.</param>
    /// <returns>The protocol version.</returns>
    /// <exception cref="FormatException">The message is not a valid SESSION_CAPABILITY.</exception>
    public static Version GetProtocolVersion(ReadOnlySpan<byte> message)
    {
        if (message.Length < HeaderLength ||
            BinaryPrimitives.ReadInt32LittleEndian(message[4..]) != PSRPMessageType.SessionCapability)
        {
            throw new FormatException("The PSRP message is not a SESSION_CAPABILITY message.");
        }

        ReadOnlySpan<byte> data = message[HeaderLength..];
        if (data.StartsWith(Encoding.UTF8.Preamble))
        {
            data = data[Encoding.UTF8.Preamble.Length..];
        }

        XElement obj;
        try
        {
            obj = XElement.Parse(Encoding.UTF8.GetString(data));
        }
        catch (XmlException e)
        {
            throw new FormatException("The SESSION_CAPABILITY message is not valid XML.", e);
        }

        string? rawVersion = obj.Descendants()
            .FirstOrDefault(e => e.Name.LocalName == "Version" && (string?)e.Attribute("N") == "protocolversion")
            ?.Value;
        return Version.TryParse(rawVersion, out Version? version)
            ? version
            : throw new FormatException($"The SESSION_CAPABILITY protocolversion '{rawVersion}' is not a version.");
    }
}
