---
document type: cmdlet
external help file: PSWSMan.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/PSWSMan/ConvertTo-WinRSCommandLine.md
Module Name: PSWSMan
ms.date: ''
PlatyPS schema version: 2024-05-01
---

# ConvertTo-WinRSCommandLine

## SYNOPSIS

Builds a command line for `Invoke-WinRSCommand` that runs an executable with an exact list of arguments.

## SYNTAX

### __AllParameterSets

```
ConvertTo-WinRSCommandLine [-FilePath] <string> [[-ArgumentList] <string[]>] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

The `ConvertTo-WinRSCommandLine` cmdlet builds a command line that runs `-FilePath` with the `-ArgumentList` values as its arguments.
The output is used as the `-Command` of `Invoke-WinRSCommand`.
It lets you pass an executable and a list of arguments without having to know the quoting and escaping rules of `cmd.exe`.

The WinRS service runs a command line as `cmd.exe /C $Command`, so it is parsed twice before the process sees its arguments:

- `cmd.exe` expands `%VAR%` references, removes `^` escapes and acts on its operators like `&`, `|`, `<`, `>`, `(` and `)`
- The process splits what is left into its argv with the Microsoft C runtime rules, the same rules `CommandLineToArgvW` and .NET use

The cmdlet first quotes each argument for the C runtime rules.
It then escapes that text for `cmd.exe`, so `cmd.exe` removes the escaping again and the process receives each argument exactly as given.
Arguments with spaces, quotes, backslashes, `%VAR%` references and `cmd.exe` operators are all passed through as they are without being replaced by `cmd.exe`.
The file path is escaped the same way and passed on in double quotes, so the process sees it as one argument even with spaces and `%` in it.
The whole line is also wrapped in an extra pair of double quotes, which `cmd.exe /C` removes.

The result is exact only in the following conditions:

- The executable must split its command line with the Microsoft C runtime rules. Most executables do, including .NET programs and C and C++ programs built with MSVC.
- A batch file (`.bat` or `.cmd`) parses its arguments with different rules. The same applies to `cmd.exe` builtins like `echo`, `dir` and `copy`, and to programs that parse their own command line like `msiexec.exe`.
- Delayed expansion must be disabled for `cmd.exe` on the remote host, which is the default. When the `DelayedExpansion` value under `HKLM:\Software\Microsoft\Command Processor` or `HKCU:\Software\Microsoft\Command Processor` enables it, a line containing `!` may cause the escaped string to be treated incorrectly.
- The file path cannot contain a double quote, which Windows does not allow in a path anyway.
- An argument cannot contain a carriage return, line feed or null character, `cmd.exe` has no way to pass them to the process.
- `cmd.exe` accepts a line of at most 8191 characters. The escaping adds characters to each argument, so check the length of the output when passing a lot of data.

The cmdlet throws an error for a value that cannot be passed through `cmd.exe`, rather than build a line that would give the process different arguments.

The arguments can be given with `-ArgumentList` or as the remaining positional arguments after the file path.
Remaining arguments are bound by PowerShell first, so a value that matches a parameter of this cmdlet, like `-F` for `-FilePath` or `-Verbose`, is bound to that parameter.
PowerShell also removes a bare `--` from the arguments.
Quote such values or pass them with `-ArgumentList`.

## EXAMPLES

### Example 1: Run an executable from a path with spaces

```powershell
PS C:\> $cmd = ConvertTo-WinRSCommandLine 'C:\Program Files\7-Zip\7z.exe' l 'C:\temp\my archive.zip'
PS C:\> $cmd
"^"C:\Program^ Files\7-Zip\7z.exe^" l ^"C:\temp\my archive.zip^""

PS C:\> Invoke-WinRSCommand Server01 $cmd
```

Builds the command line for `7z.exe` with the arguments `l` and `C:\temp\my archive.zip` and runs it on `Server01`.

### Example 2: Pass arguments with characters cmd.exe interprets

```powershell
PS C:\> $arguments = @(
>>     '%PATH%'
>>     'say "hi"'
>>     'a & b'
>>     'C:\temp dir\'
>> )
PS C:\> ConvertTo-WinRSCommandLine C:\tools\app.exe -ArgumentList $arguments
"^"C:\tools\app.exe^" ^%^PATH^%^ ^"say \^"hi\^"^" ^"a ^& b^" ^"C:\temp dir\\^""
```

The process receives the four arguments exactly as they are in `$arguments`.
`%PATH%` is not expanded, the embedded quotes are kept, `&` does not start a new command and the trailing backslash is kept.

### Example 3: Pass arguments that look like parameters

```powershell
PS C:\> ConvertTo-WinRSCommandLine C:\tools\app.exe -ArgumentList '-FilePath', '--', 'x'
"^"C:\tools\app.exe^" -FilePath -- x"
```

Passing the values with `-ArgumentList` stops PowerShell from binding `-FilePath` to this cmdlet and from removing `--`.

## PARAMETERS

### -ArgumentList

The arguments the executable receives, in order.
Each value is passed as one argument, including empty strings.
A `$null` value is skipped, the same as when calling a native command in PowerShell, so an argument built with something like `$(if ($Verbose) { '-v' })` is left out rather than passed as an empty argument.
Values that are not strings are converted with their string form.

```yaml
Type: System.String[]
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 1
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: true
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -FilePath

The path of the executable to run on the remote host.
It is used as is, so a relative path or a name without a directory is resolved by `cmd.exe` on the remote host.
A relative path is relative to the working directory of the WinRS shell, which is the profile directory of the user.

```yaml
Type: System.String
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 0
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### System.String

The command line to pass to the `-Command` parameter of `Invoke-WinRSCommand`.

## NOTES

## RELATED LINKS

- [Invoke-WinRSCommand](./Invoke-WinRSCommand.md)
