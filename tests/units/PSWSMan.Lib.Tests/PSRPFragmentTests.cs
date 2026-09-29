using System;
using System.Buffers.Binary;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PSWSMan.Lib.Tests;

public class PSRPFragmentTests
{
    private static byte[] Message(int messageType, string data = "<Obj RefId=\"0\" />", bool bom = false)
    {
        byte[] header = new byte[40];
        BinaryPrimitives.WriteInt32LittleEndian(header, 0x00000002);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(4), messageType);
        byte[] payload = Encoding.UTF8.GetBytes(data);
        return bom
            ? [.. header, .. Encoding.UTF8.Preamble, .. payload]
            : [.. header, .. payload];
    }

    private static byte[] Fragment(long objectId, long fragmentId, bool start, bool end, ReadOnlySpan<byte> blob)
    {
        byte[] fragment = new byte[21 + blob.Length];
        BinaryPrimitives.WriteInt64BigEndian(fragment, objectId);
        BinaryPrimitives.WriteInt64BigEndian(fragment.AsSpan(8), fragmentId);
        fragment[16] = (byte)((start ? 1 : 0) | (end ? 2 : 0));
        BinaryPrimitives.WriteInt32BigEndian(fragment.AsSpan(17), blob.Length);
        blob.CopyTo(fragment.AsSpan(21));
        return fragment;
    }

    private static byte[] Split(long objectId, byte[] message, int size)
    {
        byte[][] fragments = message.Chunk(size)
            .Select((chunk, i) => Fragment(objectId, i, i == 0, (i + 1) * size >= message.Length, chunk))
            .ToArray();
        return fragments.SelectMany(f => f).ToArray();
    }

    [Test]
    public async Task ContainsCompleteMessage_SingleFragment()
    {
        byte[] data = [
            .. Fragment(1, 0, true, true, Message(PSRPMessageType.SessionCapability)),
            .. Fragment(2, 0, true, true, Message(PSRPMessageType.InitRunspacePool)),
        ];

        await Assert.That(PSRPFragment.ContainsCompleteMessage(data, PSRPMessageType.InitRunspacePool)).IsTrue();
        await Assert.That(PSRPFragment.ContainsCompleteMessage(data, PSRPMessageType.CreatePipeline)).IsFalse();
    }

    [Test]
    public async Task ContainsCompleteMessage_WaitsForEndFragment()
    {
        byte[] message = Message(PSRPMessageType.CreatePipeline, new string('a', 100));
        byte[] data = Split(5, message, 30);

        await Assert.That(PSRPFragment.ContainsCompleteMessage(data, PSRPMessageType.CreatePipeline)).IsTrue();
        // Every cut short of the last byte, including ones inside a header or blob, is incomplete.
        for (int length = 0; length < data.Length; length++)
        {
            await Assert.That(PSRPFragment.ContainsCompleteMessage(data.AsSpan(0, length),
                PSRPMessageType.CreatePipeline)).IsFalse();
        }
    }

    [Test]
    public async Task ContainsCompleteMessage_NegativeBlobLength()
    {
        byte[] data = Fragment(1, 0, true, true, Message(PSRPMessageType.InitRunspacePool));
        BinaryPrimitives.WriteInt32BigEndian(data.AsSpan(17), -1);

        await Assert.That(() => PSRPFragment.ContainsCompleteMessage(data, PSRPMessageType.InitRunspacePool))
            .Throws<FormatException>();
    }

    [Test]
    public async Task ContainsCompleteFirstMessage_AnyType()
    {
        byte[] first = Message(PSRPMessageType.GetCommandMetadata, new string('m', 100));
        byte[] data = [.. Split(4, first, 30), .. Fragment(5, 0, true, false, Message(PSRPMessageType.CreatePipeline))];

        await Assert.That(PSRPFragment.ContainsCompleteFirstMessage(data)).IsTrue();
        // Up to the last byte of the first message it is not complete, the second message never matters.
        int firstLength = Split(4, first, 30).Length;
        for (int length = 0; length < firstLength; length++)
        {
            await Assert.That(PSRPFragment.ContainsCompleteFirstMessage(data.AsSpan(0, length))).IsFalse();
        }
    }

    [Test]
    public async Task TryGetMessage_Reassembles()
    {
        byte[] other = Message(PSRPMessageType.SessionCapability);
        byte[] message = Message(PSRPMessageType.InitRunspacePool, new string('b', 200));
        byte[] data = [.. Fragment(1, 0, true, true, other), .. Split(2, message, 64)];

        bool found = PSRPFragment.TryGetMessage(data, PSRPMessageType.InitRunspacePool, out byte[]? actual);

        await Assert.That(found).IsTrue();
        await Assert.That(actual).IsEquivalentTo(message);
    }

    [Test]
    public async Task TryGetMessage_Missing()
    {
        byte[] data = Split(1, Message(PSRPMessageType.InitRunspacePool, new string('c', 90)), 40);

        bool found = PSRPFragment.TryGetMessage(data.AsSpan(0, data.Length - 1), PSRPMessageType.InitRunspacePool,
            out byte[]? actual);

        await Assert.That(found).IsFalse();
        await Assert.That(actual).IsNull();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task GetProtocolVersion(bool bom)
    {
        const string capability = "<Obj RefId=\"0\"><MS>" +
            "<Version N=\"protocolversion\">2.3</Version>" +
            "<Version N=\"PSVersion\">2.0</Version>" +
            "<Version N=\"SerializationVersion\">1.1.0.1</Version>" +
            "</MS></Obj>";

        Version actual = PSRPMessage.GetProtocolVersion(Message(PSRPMessageType.SessionCapability, capability, bom));

        await Assert.That(actual).IsEqualTo(new Version(2, 3));
    }

    [Test]
    public async Task GetProtocolVersion_WrongMessageType()
    {
        await Assert.That(() => PSRPMessage.GetProtocolVersion(Message(PSRPMessageType.InitRunspacePool)))
            .Throws<FormatException>();
    }

    [Test]
    public async Task GetProtocolVersion_InvalidXml()
    {
        byte[] message = Message(PSRPMessageType.SessionCapability, "<Obj RefId=\"0\"><MS>");

        await Assert.That(() => PSRPMessage.GetProtocolVersion(message)).Throws<FormatException>()
            .WithInnerException().And.IsTypeOf<System.Xml.XmlException>();
    }

    [Test]
    public async Task GetProtocolVersion_NoVersion()
    {
        byte[] message = Message(PSRPMessageType.SessionCapability, "<Obj RefId=\"0\"><MS /></Obj>");

        await Assert.That(() => PSRPMessage.GetProtocolVersion(message)).Throws<FormatException>();
    }
}
