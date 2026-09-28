---
external help file: PSWSMan.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/Invoke-WinRSCommand.md
schema: 2.0.0
---

# Invoke-WinRSCommand

## SYNOPSIS
Runs a process on a remote host through a WinRS shell and outputs its stdout and stderr.

## SYNTAX

### ComputerName (Default)
```
Invoke-WinRSCommand [-Command] <String> [-InputObject <PSObject>] [-ConsoleEncoding <Encoding>] [-AsByteStream]
 [-ComputerName] <String> [-Credential <PSCredential>] [-Port <Int32>] [-UseSSL] [-ApplicationName <String>]
 [-SessionOption <PSSessionOption>] [-Authentication <AuthenticationMethod>] [-CertificateThumbprint <String>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### ConnectionUri
```
Invoke-WinRSCommand [-Command] <String> [-InputObject <PSObject>] [-ConsoleEncoding <Encoding>] [-AsByteStream]
 [-ConnectionUri] <Uri> [-Credential <PSCredential>] [-SessionOption <PSSessionOption>]
 [-Authentication <AuthenticationMethod>] [-CertificateThumbprint <String>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
The `Invoke-WinRSCommand` cmdlet runs a command line on a remote Windows host using the WinRS (Windows Remote Shell) protocol over WSMan, the same mechanism `winrs.exe` uses.
Unlike `Invoke-Command` it does not start a PowerShell session on the remote host, the command line is run by `cmd.exe` in a WinRS shell and only its raw output is sent back.

The `-Command` string is handed to the remote host exactly as stored by that string and the WinRS service runs it as `cmd.exe /C $Command`.
Nothing on the client side quotes, escapes or splits it, so all of the interpretation is done by `cmd.exe` on the remote host: quoting, `%VAR%` expansion, `^` escaping, redirection like `2>&1` and `&&` chaining all work as they would when typed after `cmd /C` locally.
This also means the `/C` quoting rule of `cmd.exe` applies, a command line that starts with a double quote has its first and last double quote removed.
Wrap the whole line in one more pair of double quotes when it starts with a quoted path, for example `""C:\Program Files\App\app.exe" -arg"`.
You can use single quotes in PowerShell to write the command line so nothing is expanded on the client first.

Use `ConvertTo-WinRSCommandLine` to build the command line from an executable and a list of arguments, it quotes and escapes them so the process receives each argument exactly as given.
Prefer it over putting values into the command line yourself, especially values from variables or user input.
A value interpolated into `-Command` is interpreted by `cmd.exe`, so a `%VAR%` in it is expanded, a quote in it changes how the rest of the line is split, and an `&` or `|` in it runs another command on the remote host.
See `ConvertTo-WinRSCommandLine` for the escaping rules and the few cases it cannot cover, like batch files and delayed expansion.

The output is written the same way PowerShell writes the output of a local native command.
Each line the process writes to stdout is written to the output stream as a string and each line written to stderr is written to the error stream as a `NativeCommandError` record, which is displayed as plain text.
When the process exits its exit code is stored in `$LASTEXITCODE`.
Calling `ToString()` on one of the stderr records, or putting it in a string like `"$_"`, gives the text of the line.

The stderr records are written like the errors of any other cmdlet, so they follow `-ErrorAction` and `$ErrorActionPreference`, which is different from a local native command:

- With `Stop`, the first stderr line becomes a terminating error, and the remote process is terminated along with the shell before it finishes. `$LASTEXITCODE` is not updated. A local native command ignores `$ErrorActionPreference` for its stderr. Redirecting the error stream with `2>&1` or `2>$null` does not change this, set `-ErrorAction Continue|SilentlyContinue|Ignore` on the cmdlet when a script runs with `$ErrorActionPreference = 'Stop'`.
- `SilentlyContinue` hides the lines but still adds them to `$Error` and to `-ErrorVariable`. `Ignore` discards them completely.
- `$?` is `$false` after the cmdlet writes any stderr line, even if the process exits with `0`. Check `$LASTEXITCODE` to see whether the process succeeded.

The stdout and stderr lines are written in the order the server returns them, so with `2>&1` they are interleaved as the process wrote them.
The server reads the two streams separately, so a stdout and a stderr line written at almost the same moment can still come back in the opposite order.

The remote shell is created with the code page of `-ConsoleEncoding`, UTF-8 by default, and the same encoding decodes the output and encodes the input.
Set it to the code page a program actually writes, for example `437` or `oem`, when its output is not UTF-8.
Use `-AsByteStream` to get the raw stdout of the process as `byte[]` chunks rather than lines of text, for example to copy a binary file with `type`.
The shell still runs with the code page of `-ConsoleEncoding` in that mode, and it is still used to encode string input and to decode stderr into error records.

Pipeline input is written to the stdin of the process as it arrives.
A string is written as a line with a CRLF terminator and encoded with `-ConsoleEncoding`, a `byte[]` is written as is, and single bytes, which is how the pipeline delivers an enumerated byte array, are collected and written together.
Any other object is written as its string form, one line each.
Stdin is closed once all the input has been sent, or straight away when there is none, so a process that reads from stdin gets end of file rather than blocking.
Input that arrives after the process has exited or closed its stdin is discarded, as it is for a local native command.

Stopping the cmdlet with `Ctrl+C`, or stopping the pipeline it is part of, sends `Ctrl+C` to the remote process so it can exit cleanly, like it would when run locally.
If the process has not exited within 10 seconds it is terminated.
This also happens when a later command in the pipeline stops early, like `Select-Object -First 3`.

This cmdlet does not require `Enable-PSWSMan` to have been run as it uses the WSMan client of this module directly.
The connection is configured with the same parameters as `Invoke-Command`, `-ComputerName`, `-Port`, `-UseSSL`, `-ApplicationName`, `-Credential`, `-CertificateThumbprint` and `-SessionOption`, and they mean the same thing.
Instead of `-ComputerName`, `-Port`, `-UseSSL` and `-ApplicationName`, the endpoint can be given as a whole with `-ConnectionUri`, like `https://Server01:5986/wsman`.
The `-SessionOption` parameter accepts the output of either `New-PSSessionOption` or `New-PSWSManSessionOption`, the options that apply to a WinRS command are the timeouts, `NoEncryption`, `NoMachineProfile`, `Culture`, `UICulture`, `MaxConnectionRetryCount`, the certificate checks and all of the PSWSMan specific options like the authentication provider, SPN and TLS settings.

Without `-Credential` or `-CertificateThumbprint` the credential of the current user is used, on Linux and macOS this needs a Kerberos ticket to be available.
The default authentication is Negotiate, which uses Kerberos where possible and falls back to NTLM otherwise, and a HTTP connection encrypts the messages with it unless `NoEncryption` is set in the session option.

## EXAMPLES

### Example 1: Run a command with an explicit credential
```powershell
PS C:\> $cred = Get-Credential
PS C:\> Invoke-WinRSCommand -ComputerName Server01 -Command 'ipconfig /all' -Credential $cred
```

Runs `ipconfig /all` on `Server01` and outputs each line of its output as a string.

### Example 2: Check the exit code of a process
```powershell
PS C:\> Invoke-WinRSCommand Server01 'exit 3'
PS C:\> $LASTEXITCODE
3
```

Runs the command using positional parameters and shows the exit code, `exit` here is the `cmd.exe` builtin as the line runs under `cmd.exe /C`.

### Example 3: Collect stderr separately from the output
```powershell
PS C:\> $stdout = Invoke-WinRSCommand Server01 'dir C:\Windows\win.ini C:\missing.txt' -ErrorAction SilentlyContinue -ErrorVariable err
PS C:\> $stderr = ($err | ForEach-Object ToString) -join [Environment]::NewLine
```

Hides the stderr lines while collecting them in `$err`, then joins them into a single string.

### Example 4: Run in a script that stops on errors
```powershell
PS C:\> $ErrorActionPreference = 'Stop'
PS C:\> $output = Invoke-WinRSCommand Server01 'my-tool.exe --verbose' -ErrorAction Continue 2>&1
PS C:\> if ($LASTEXITCODE -ne 0) { throw "my-tool.exe failed with $LASTEXITCODE`n$output" }
```

Without `-ErrorAction Continue` the first line `my-tool.exe` writes to stderr would stop the script and terminate the process.
Setting it on the cmdlet lets the process run to completion, and the exit code decides whether it failed.

### Example 5: Use cmd.exe features in the command line
```powershell
PS C:\> Invoke-WinRSCommand Server01 'echo %COMPUTERNAME% && whoami /groups 2>&1 | findstr /i admin'
```

The command line is interpreted by `cmd.exe` on the remote host, so its variable expansion, command chaining, redirection and pipes are all available.

### Example 6: Run an executable from a path with spaces
```powershell
PS C:\> Invoke-WinRSCommand Server01 '""C:\Program Files\7-Zip\7z.exe" l "C:\temp\my archive.zip""'
```

The executable path and the archive path both contain spaces so each is quoted.
The line starts with a quote so it is also wrapped in an extra pair of double quotes, `cmd.exe /C` removes that outer pair and runs `"C:\Program Files\7-Zip\7z.exe" l "C:\temp\my archive.zip"`.
Without the extra pair `cmd.exe` would remove the quote before `C:\Program Files` and the one after `my archive.zip`, and fail to find `C:\Program`.
`ConvertTo-WinRSCommandLine` builds an equivalent line without having to work out the quoting, see the next example.

### Example 7: Build the command line from an executable and its arguments
```powershell
PS C:\> $archive = 'C:\temp\100% done & (final).zip'
PS C:\> $cmd = ConvertTo-WinRSCommandLine 'C:\Program Files\7-Zip\7z.exe' l $archive
PS C:\> Invoke-WinRSCommand Server01 $cmd
```

`ConvertTo-WinRSCommandLine` escapes the executable path and each argument for `cmd.exe`, so `7z.exe` receives `l` and the value of `$archive` as its two arguments.
The `%`, `&`, spaces and parentheses in the value are passed through as they are, where writing the line by hand would need them escaped in ways that differ inside and outside of quotes.

### Example 8: Run a program that writes in the OEM code page
```powershell
PS C:\> Invoke-WinRSCommand Server01 'legacy.exe /report' -ConsoleEncoding 437
```

Creates the remote shell with code page 437 and decodes the output with it, for a program that ignores the UTF-8 code page and writes in the OEM code page of a US English system.

### Example 9: Copy a binary file from the remote host
```powershell
PS C:\> Invoke-WinRSCommand Server01 'type C:\temp\archive.zip' -AsByteStream |
>>     Set-Content -Path ./archive.zip -AsByteStream
```

Outputs the raw bytes `type` writes as `byte[]` chunks and writes them unchanged to a local file.
`Receive-WinRSFile` copies a file the same way but also checks its length and hash before writing it to the destination.

### Example 10: Send input to the process
```powershell
PS C:\> 'apple', 'banana', 'cherry' | Invoke-WinRSCommand Server01 'findstr an'
banana
PS C:\> Get-Content -Path ./archive.zip -AsByteStream -Raw | Invoke-WinRSCommand Server01 'certutil -hashfile - SHA256'
```

The first command writes each string as a line to the stdin of `findstr` and outputs the line that matched.
The second sends the raw bytes of a file to a process reading its stdin.

### Example 11: Connect over HTTPS with NTLM
```powershell
PS C:\> $so = New-PSWSManSessionOption -SkipCACheck -SkipCNCheck
PS C:\> Invoke-WinRSCommand Server01 hostname -UseSSL -Credential $cred -Authentication NTLM -SessionOption $so
```

Connects to port 5986 over HTTPS without validating the certificate of the server and authenticates with NTLM.

### Example 12: Connect with a connection URI
```powershell
PS C:\> Invoke-WinRSCommand -ConnectionUri https://Server01:5986/custom -Command hostname -Credential $cred
```

Connects to a listener on a non-standard port and application name without having to specify `-Port`, `-UseSSL` and `-ApplicationName` separately.

### Example 13: Connect with a client certificate
```powershell
PS C:\> Invoke-WinRSCommand Server01 whoami -UseSSL -CertificateThumbprint 'E54E20C7E7D2B7D82B3F71B0CB4E4D6A4E5C0A62'
```

Authenticates with the certificate from the current user or local machine certificate store that has the thumbprint.

## PARAMETERS

### -ApplicationName
The application name segment of the connection URI, the default is `wsman`.

```yaml
Type: String
Parameter Sets: ComputerName
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AsByteStream
Outputs the stdout of the process as raw `byte[]` chunks instead of decoding it into lines of text.
Each chunk is written to the pipeline as a single object, in the size and order the server returned it, so collect them with `Set-Content -AsByteStream` or flatten them with `ForEach-Object { $_ }` to get one byte array.
The shell still uses the code page of `-ConsoleEncoding`, which is also used to encode string input and to decode stderr, as stderr is still written as error records.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Authentication
The authentication method used to authenticate with the remote host.
The default selects Negotiate, or certificate authentication when `-CertificateThumbprint` or a client certificate in the session option is set.
Unlike `-Authentication` on `Invoke-Command` this uses the authentication methods of PSWSMan so `NTLM` and `CredSSP` can be selected directly.
When set to anything other than `Default` it takes precedence over the `AuthMethod` of the `-SessionOption`.
`Basic` requires either `-UseSSL` or `NoEncryption` in the session option.

```yaml
Type: AuthenticationMethod
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CertificateThumbprint
The thumbprint of a client certificate in the current user or local machine certificate store to authenticate with.
It requires `-UseSSL` or a `https` `-ConnectionUri` and cannot be used with `-Credential` or `-Authentication`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Command
The command line to run on the remote host.
It is passed as is to the WinRS service which runs it as `cmd.exe /C $Command`, so it is written and quoted the way `cmd.exe` expects rather than the way PowerShell or `Start-Process` would split arguments.
See the description for how `cmd.exe` interprets it.
Use `ConvertTo-WinRSCommandLine` to build it from an executable and a list of arguments.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerName
The host to run the process on.

```yaml
Type: String
Parameter Sets: ComputerName
Aliases: Cn

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConnectionUri
The full URI of the WSMan endpoint, for example `http://Server01:5985/wsman` or `https://Server01:5986/wsman`.
It must be an absolute `http` or `https` URI and it is used as is, a URI without a port connects to port 80 or 443 as it does for `Invoke-Command`, and one without a path uses `/wsman`.
It cannot be used with `-ComputerName`, `-Port`, `-UseSSL` or `-ApplicationName`.

```yaml
Type: Uri
Parameter Sets: ConnectionUri
Aliases: URI, CU

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConsoleEncoding
The encoding of the remote console.
Its code page is set on the remote shell so `cmd.exe` and the programs it starts read and write in it, and the cmdlet uses it to decode stdout and stderr and to encode string input.
It accepts an `Encoding` object, a code page number like `437`, one of the names `UTF8`, `UTF8Bom`, `UTF8NoBom`, `ASCII`, `ANSI`, `OEM`, `ConsoleInput` or `ConsoleOutput`, or any other name `[System.Text.Encoding]::GetEncoding()` accepts.
The `ANSI`, `OEM`, `ConsoleInput` and `ConsoleOutput` names resolve to the encodings of the local machine, not the remote host.
The default is UTF-8.
With `-AsByteStream` it still sets the code page and encodes string input and decodes stderr, only stdout is left as raw bytes.

UTF-16 and UTF-32 cannot be used, the remote host rejects them as `cmd.exe` does not support them as a console code page.

```yaml
Type: Encoding
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: UTF8
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
The credential used to authenticate with the remote host through Negotiate authentication.
When not set the credential of the current user is used.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InputObject
The objects to write to the stdin of the process, usually from the pipeline.
Strings are written as lines, byte arrays and single bytes as raw data, and anything else as its string form.

```yaml
Type: PSObject
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Port
The port of the WSMan listener, the default is `5985` or `5986` with `-UseSSL`.

```yaml
Type: Int32
Parameter Sets: ComputerName
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
New common parameter introduced in PowerShell 7.4.

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SessionOption
The session options created by `New-PSSessionOption` or `New-PSWSManSessionOption`.
Only the options that apply to a WinRS command are used, see the description for the list.

```yaml
Type: PSSessionOption
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UseSSL
Connect over HTTPS instead of HTTP.

```yaml
Type: SwitchParameter
Parameter Sets: ComputerName
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Management.Automation.PSObject
Objects piped to the cmdlet are written to the stdin of the process, see `-InputObject`.

## OUTPUTS

### System.String
Each line the process writes to stdout. The stderr lines are written to the error stream as `System.Management.Automation.ErrorRecord` objects with the `NativeCommandError` and `NativeCommandErrorMessage` error ids.

### System.Byte[]
The raw stdout chunks when `-AsByteStream` is used.

## NOTES
The exit code of the process is stored in `$LASTEXITCODE`.

This cmdlet has the alias `iwcm`.

## RELATED LINKS

[ConvertTo-WinRSCommandLine](./ConvertTo-WinRSCommandLine.md)

[MS-WSMV WinRS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/)
