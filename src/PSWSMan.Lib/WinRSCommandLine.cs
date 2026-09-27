using System;
using System.Collections.Generic;
using System.Text;

namespace PSWSMan.Lib;

/// <summary>Builds a command line for the WinRS cmd shell that gives a process an exact argv.</summary>
/// <remarks>
/// The WinRS service runs the command as <c>cmd.exe /C &lt;command&gt;</c>, so the line is parsed twice. cmd.exe
/// expands <c>%VAR%</c>, removes <c>^</c> escapes and acts on its operators, then the process splits what is left
/// with the Microsoft C runtime rules used by <c>CommandLineToArgvW</c>.
/// </remarks>
public static class WinRSCommandLine
{
    private static readonly char[] s_invalidChars = ['\0', '\r', '\n'];

    /// <summary>Builds the command line that runs an executable with the arguments given.</summary>
    /// <param name="filePath">The executable to run.</param>
    /// <param name="arguments">The arguments the executable receives as its argv after argv[0].</param>
    /// <returns>The command line to run in a WinRS cmd shell.</returns>
    /// <exception cref="ArgumentException">A value contains a character that cannot be passed through cmd.exe.</exception>
    public static string Build(string filePath, IEnumerable<string> arguments)
    {
        if (string.IsNullOrEmpty(filePath))
        {
            throw new ArgumentException("The file path must not be empty.", nameof(filePath));
        }
        if (filePath.IndexOfAny([.. s_invalidChars, '"']) != -1)
        {
            throw new ArgumentException(
                "The file path must not contain a double quote, carriage return, line feed or null character.",
                nameof(filePath));
        }

        StringBuilder argumentLine = new();
        foreach (string argument in arguments)
        {
            if (argument.IndexOfAny(s_invalidChars) != -1)
            {
                throw new ArgumentException(
                    "An argument must not contain a carriage return, line feed or null character.",
                    nameof(arguments));
            }

            argumentLine.Append(' ');
            AppendArgument(argumentLine, argument);
        }

        // cmd.exe /C strips the first and last quote of a line that starts with one. The line always has at least
        // four quotes so it never meets the conditions to keep them, the outer pair is the one removed.
        StringBuilder commandLine = new("\"");

        // The file path is not put in real quotes as a ^ inside them is kept, which leaves no way to escape a %.
        // Escaping the quotes and every character that is not plainly part of a path keeps it one token for
        // cmd.exe, which removes the carets and passes it on quoted so the process still sees one argv[0].
        commandLine.Append("^\"");
        AppendEscaped(
            commandLine,
            filePath,
            c => !(char.IsAsciiLetterOrDigit(c) || c is '\\' or ':' or '.' or '-' or '_'));
        commandLine.Append("^\"");

        // Every quote in the arguments is escaped so cmd.exe never enters quote mode there and each ^ applies.
        AppendEscaped(
            commandLine,
            argumentLine.ToString(),
            c => c is '^' or '&' or '|' or '<' or '>' or '(' or ')' or '"' or '%');

        return commandLine.Append('"').ToString();
    }

    private static void AppendEscaped(StringBuilder sb, string value, Func<char, bool> needsEscape)
    {
        // A ^ before % does not stop variable expansion as that happens before escapes are processed. A ^ after it
        // makes every %...% pair name a variable starting with ^. That is undefined, which cmd.exe leaves as is
        // outside a batch file.
        bool afterPercent = false;
        foreach (char c in value)
        {
            if (afterPercent || needsEscape(c))
            {
                sb.Append('^');
            }
            sb.Append(c);
            afterPercent = c == '%';
        }
    }

    private static void AppendArgument(StringBuilder sb, string argument)
    {
        if (argument.Length > 0 && argument.IndexOfAny([' ', '\t', '"']) == -1)
        {
            sb.Append(argument);
            return;
        }

        sb.Append('"');
        int backslashes = 0;
        foreach (char c in argument)
        {
            if (c == '\\')
            {
                backslashes++;
                continue;
            }

            // Backslashes are only special before a quote, where each one is doubled and the quote is escaped.
            if (c == '"')
            {
                sb.Append('\\', backslashes * 2 + 1);
            }
            else
            {
                sb.Append('\\', backslashes);
            }
            backslashes = 0;
            sb.Append(c);
        }

        // The closing quote follows any trailing backslashes, so they are doubled too.
        sb.Append('\\', backslashes * 2).Append('"');
    }
}
