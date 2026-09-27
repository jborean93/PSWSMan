using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace PSWSMan.Lib.Tests;

public class WinRSCommandLineTests
{
    // Shared with tests/Invoke-WinRSCommand.Tests.ps1, which checks every expected line gives the arguments back as
    // argv when run on a real host.
    public sealed record CommandLineCase(string Name, string FilePath, string[] Arguments, string Expected)
    {
        public override string ToString() => Name;
    }

    public static IEnumerable<Func<CommandLineCase>> SharedCases()
    {
        using JsonDocument doc = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "WinRSCommandLine.json")));
        string filePath = doc.RootElement.GetProperty("file_path").GetString()!;

        foreach (JsonElement entry in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            CommandLineCase testCase = new(
                entry.GetProperty("name").GetString()!,
                filePath,
                [.. entry.GetProperty("arguments").EnumerateArray().Select(a => a.GetString()!)],
                entry.GetProperty("expected").GetString()!);
            yield return () => testCase;
        }
    }

    [Test]
    [MethodDataSource(nameof(SharedCases))]
    public async Task Build_SharedCase(CommandLineCase testCase)
    {
        string actual = WinRSCommandLine.Build(testCase.FilePath, testCase.Arguments);

        await Assert.That(actual).IsEqualTo(testCase.Expected);
    }

    [Test]
    [Arguments("app.exe", "\"^\"app.exe^\"\"")]
    [Arguments(@"C:\Windows\System32\whoami.exe", "\"^\"C:\\Windows\\System32\\whoami.exe^\"\"")]
    [Arguments(@"C:\a b\c & (d) ^e !f ;,=\app.exe", "\"^\"C:\\a^ b\\c^ ^&^ ^(d^)^ ^^e^ ^!f^ ^;^,^=\\app.exe^\"\"")]
    [Arguments(@"C:\%TEMP%\100%\app.exe", "\"^\"C:\\^%^TEMP^%^\\100^%^\\app.exe^\"\"")]
    [Arguments("C:/a/b.exe", "\"^\"C:^/a^/b.exe^\"\"")]
    public async Task Build_EscapesFilePath(string filePath, string expected)
    {
        string actual = WinRSCommandLine.Build(filePath, []);

        await Assert.That(actual).IsEqualTo(expected);
    }

    [Test]
    [Arguments("")]
    [Arguments("C:\\a\"b.exe")]
    [Arguments("app\r.exe")]
    [Arguments("app\n.exe")]
    [Arguments("app\0.exe")]
    public async Task Build_RejectsFilePath(string filePath)
    {
        ArgumentException? ex = await Assert.That(() => WinRSCommandLine.Build(filePath, []))
            .Throws<ArgumentException>();

        await Assert.That(ex!.ParamName).IsEqualTo("filePath");
    }

    [Test]
    [Arguments("a\rb")]
    [Arguments("a\nb")]
    [Arguments("a\r\nb")]
    [Arguments("a\0b")]
    public async Task Build_RejectsArgument(string argument)
    {
        ArgumentException? ex = await Assert.That(() => WinRSCommandLine.Build("app.exe", ["ok", argument]))
            .Throws<ArgumentException>();

        await Assert.That(ex!.ParamName).IsEqualTo("arguments");
    }
}
