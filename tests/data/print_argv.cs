// Compiled on the test host by tests/ConvertTo-WinRSCommandLine.Tests.ps1 with Windows PowerShell's Add-Type.
// Writes the raw command line and how .NET and CommandLineToArgvW split it as JSON. Everything outside printable
// ASCII is written as a \u escape so the output does not depend on the console code page.
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class PrintArgv
{
    [DllImport("Kernel32.dll")]
    private static extern IntPtr GetCommandLineW();

    [DllImport("Shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string lpCmdLine, out int pNumArgs);

    [DllImport("Kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public static void Main(string[] args)
    {
        string commandLine = Marshal.PtrToStringUni(GetCommandLineW());

        int count;
        IntPtr argvPtr = CommandLineToArgvW(commandLine, out count);
        string[] argv = new string[count];
        for (int i = 0; i < count; i++)
        {
            argv[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argvPtr, i * IntPtr.Size));
        }
        LocalFree(argvPtr);

        StringBuilder sb = new StringBuilder();
        sb.Append("{\"CommandLine\":");
        AppendString(sb, commandLine);
        sb.Append(",\"Args\":");
        AppendArray(sb, args, 0);
        sb.Append(",\"Argv\":");
        AppendArray(sb, argv, 1);
        sb.Append("}");
        Console.Out.Write(sb.ToString());
    }

    private static void AppendArray(StringBuilder sb, string[] values, int start)
    {
        sb.Append("[");
        for (int i = start; i < values.Length; i++)
        {
            if (i > start)
            {
                sb.Append(",");
            }
            AppendString(sb, values[i]);
        }
        sb.Append("]");
    }

    private static void AppendString(StringBuilder sb, string value)
    {
        sb.Append("\"");
        foreach (char c in value)
        {
            if (c == '"' || c == '\\' || c < 0x20 || c > 0x7E)
            {
                sb.AppendFormat("\\u{0:X4}", (int)c);
            }
            else
            {
                sb.Append(c);
            }
        }
        sb.Append("\"");
    }
}
