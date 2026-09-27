using System;
using System.Collections.Generic;
using System.Text;

namespace PSWSMan.Connection;

/// <summary>Turns the raw byte chunks of one WinRS output stream into text lines.</summary>
/// <remarks>
/// <para>
/// The server splits output wherever its buffer happened to fill, so a chunk can end in the middle of a multi byte
/// character or a line. The decoder keeps that remainder until the next chunk arrives and <see cref="Flush"/>
/// returns whatever is left once the stream has ended.
/// </para>
/// <para>
/// A line ends at <c>\n</c>, <c>\r</c> or <c>\r\n</c>, the same rules as <see cref="System.IO.StreamReader.ReadLine"/>
/// which is what PowerShell applies to a local native command. The terminator is not part of the line.
/// </para>
/// </remarks>
internal sealed class WinRSLineDecoder
{
    private readonly Decoder _decoder;
    private readonly StringBuilder _pending = new();
    private bool _skipLineFeed;

    /// <summary>Creates a decoder for one stream.</summary>
    /// <param name="encoding">The encoding the remote process writes its output in.</param>
    public WinRSLineDecoder(Encoding encoding)
    {
        _decoder = encoding.GetDecoder();
    }

    /// <summary>Decodes a chunk and returns the lines it completed, in order.</summary>
    /// <param name="data">The raw bytes of the chunk.</param>
    /// <returns>The complete lines, an incomplete trailing line is held for the next call.</returns>
    public IReadOnlyList<string> Decode(ReadOnlySpan<byte> data)
    {
        int charCount = _decoder.GetCharCount(data, flush: false);
        if (charCount == 0)
        {
            return [];
        }

        char[] chars = new char[charCount];
        int written = _decoder.GetChars(data, chars, flush: false);
        return SplitLines(chars.AsSpan(0, written));
    }

    /// <summary>Returns the incomplete last line once the stream has ended.</summary>
    /// <returns>The trailing text without a line terminator, or null when there is none.</returns>
    public string? Flush()
    {
        // A truncated multi byte sequence at the very end becomes the replacement character.
        int charCount = _decoder.GetCharCount(ReadOnlySpan<byte>.Empty, flush: true);
        if (charCount > 0)
        {
            char[] chars = new char[charCount];
            int written = _decoder.GetChars(ReadOnlySpan<byte>.Empty, chars, flush: true);
            _pending.Append(chars, 0, written);
        }

        _skipLineFeed = false;
        if (_pending.Length == 0)
        {
            return null;
        }

        string line = _pending.ToString();
        _pending.Clear();
        return line;
    }

    private List<string> SplitLines(ReadOnlySpan<char> chars)
    {
        List<string> lines = new();
        int start = 0;
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (_skipLineFeed)
            {
                // The \n of a \r\n pair whose \r ended the previous chunk, or came just before.
                _skipLineFeed = false;
                if (c == '\n')
                {
                    start = i + 1;
                    continue;
                }
            }

            if (c is '\r' or '\n')
            {
                _pending.Append(chars[start..i]);
                lines.Add(_pending.ToString());
                _pending.Clear();
                start = i + 1;
                _skipLineFeed = c == '\r';
            }
        }

        _pending.Append(chars[start..]);
        return lines;
    }
}
