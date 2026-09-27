using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace PSWSMan.Connection.Tests;

public class WinRSLineDecoderTests
{
    private static List<string> DecodeAll(WinRSLineDecoder decoder, params string[] chunks)
    {
        List<string> lines = new();
        foreach (string chunk in chunks)
        {
            lines.AddRange(decoder.Decode(Encoding.UTF8.GetBytes(chunk)));
        }

        return lines;
    }

    [Test]
    public async Task Decode_SplitsOnEachTerminatorStyle()
    {
        WinRSLineDecoder decoder = new(Encoding.UTF8);

        List<string> lines = DecodeAll(decoder, "one\r\ntwo\nthree\rfour\r\n");

        await Assert.That(lines).IsEquivalentTo(new[] { "one", "two", "three", "four" });
        await Assert.That(decoder.Flush()).IsNull();
    }

    [Test]
    public async Task Decode_HoldsPartialLineUntilTerminated()
    {
        WinRSLineDecoder decoder = new(Encoding.UTF8);

        List<string> first = DecodeAll(decoder, "hel");
        List<string> second = DecodeAll(decoder, "lo\r\nwor");

        await Assert.That(first.Count).IsEqualTo(0);
        await Assert.That(second).IsEquivalentTo(new[] { "hello" });
        await Assert.That(decoder.Flush()).IsEqualTo("wor");
    }

    [Test]
    public async Task Decode_CarriageReturnLineFeedSplitAcrossChunks()
    {
        WinRSLineDecoder decoder = new(Encoding.UTF8);

        List<string> first = DecodeAll(decoder, "one\r");
        List<string> second = DecodeAll(decoder, "\ntwo\n");

        await Assert.That(first).IsEquivalentTo(new[] { "one" });
        await Assert.That(second).IsEquivalentTo(new[] { "two" });
    }

    [Test]
    public async Task Decode_EmptyLinesArePreserved()
    {
        WinRSLineDecoder decoder = new(Encoding.UTF8);

        List<string> lines = DecodeAll(decoder, "\r\n\n\r\nx\r\n\r\n");

        await Assert.That(lines).IsEquivalentTo(new[] { "", "", "", "x", "" });
    }

    [Test]
    public async Task Decode_MultiByteCharacterSplitAcrossChunks()
    {
        WinRSLineDecoder decoder = new(Encoding.UTF8);
        byte[] bytes = Encoding.UTF8.GetBytes("café\n");

        List<string> lines = new(decoder.Decode(bytes.AsSpan(0, 4)));
        lines.AddRange(decoder.Decode(bytes.AsSpan(4)));

        await Assert.That(lines).IsEquivalentTo(new[] { "café" });
    }

    [Test]
    public async Task Flush_TruncatedCharacterBecomesReplacement()
    {
        WinRSLineDecoder decoder = new(Encoding.UTF8);
        byte[] bytes = Encoding.UTF8.GetBytes("aé");

        List<string> lines = new(decoder.Decode(bytes.AsSpan(0, 2)));

        await Assert.That(lines.Count).IsEqualTo(0);
        await Assert.That(decoder.Flush()).IsEqualTo("a�");
    }

    [Test]
    public async Task Flush_ResetsForReuse()
    {
        WinRSLineDecoder decoder = new(Encoding.UTF8);
        DecodeAll(decoder, "left");

        await Assert.That(decoder.Flush()).IsEqualTo("left");
        await Assert.That(decoder.Flush()).IsNull();
        await Assert.That(DecodeAll(decoder, "next\n")).IsEquivalentTo(new[] { "next" });
    }

    [Test]
    public async Task Decode_EmptyChunkYieldsNothing()
    {
        WinRSLineDecoder decoder = new(Encoding.UTF8);

        await Assert.That(decoder.Decode(ReadOnlySpan<byte>.Empty).Count).IsEqualTo(0);
        await Assert.That(decoder.Flush()).IsNull();
    }
}
