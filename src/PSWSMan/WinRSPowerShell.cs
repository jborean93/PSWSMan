using System;
using System.IO;
using System.Management.Automation.Language;
using System.Reflection;
using System.Text;

namespace PSWSMan;

/// <summary>Builds WinRS command lines that run the module's embedded scripts with Windows PowerShell.</summary>
internal static class WinRSPowerShell
{
    // cmd.exe rejects longer command lines.
    private const int MaxCommandLineLength = 8191;

    /// <summary>Builds the command line that runs an embedded script with the arguments given.</summary>
    /// <remarks>
    /// The script is run by a short -Command that decodes it from UTF-8 base64 and runs it with Invoke-Expression.
    /// Base64 has no characters cmd.exe interprets and UTF-8 keeps it about half the size of -EncodedCommand, which
    /// takes UTF-16. The arguments are embedded as single quoted strings so they are never interpreted. The scripts
    /// use ::new, so the remote host needs Windows PowerShell 5.1.
    /// </remarks>
    /// <param name="scriptName">The name of the script under Scripts/.</param>
    /// <param name="arguments">The positional arguments for the script's param block.</param>
    /// <exception cref="ArgumentException">The command line is too long for cmd.exe.</exception>
    public static string GetCommandLine(string scriptName, params string[] arguments)
    {
        StringBuilder script = new StringBuilder("& {\n")
            .Append(GetScript(scriptName))
            .Append("\n}");
        foreach (string argument in arguments)
        {
            script.Append(" '").Append(CodeGeneration.EscapeSingleQuotedStringContent(argument)).Append('\'');
        }

        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(script.ToString()));
        // Unquoted as cmd.exe strips the first and last quote of a line that starts with one, %windir% has no spaces.
        string commandLine = @"%windir%\System32\WindowsPowerShell\v1.0\powershell.exe " +
            "-NoProfile -NonInteractive -InputFormat None -Command " +
            $"\"iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}')))\"";
        if (commandLine.Length > MaxCommandLineLength)
        {
            throw new ArgumentException(
                $"The remote PowerShell command line is {commandLine.Length} characters, more than the " +
                $"{MaxCommandLineLength} cmd.exe accepts. Use shorter paths.");
        }

        return commandLine;
    }

    private static string GetScript(string scriptName)
    {
        Assembly assembly = typeof(WinRSPowerShell).Assembly;
        using Stream stream = assembly.GetManifestResourceStream($"PSWSMan.Scripts.{scriptName}")
            ?? throw new ArgumentException($"The embedded script '{scriptName}' does not exist.", nameof(scriptName));
        using StreamReader reader = new(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
