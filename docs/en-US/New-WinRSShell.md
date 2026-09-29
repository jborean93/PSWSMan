---
external help file: PSWSMan.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/New-WinRSShell.md
schema: 2.0.0
---

# New-WinRSShell

## SYNOPSIS
Creates a WinRS shell on a remote host that several WinRS commands can run in.

## SYNTAX

### ComputerName (Default)
```
New-WinRSShell [-ConsoleEncoding <Encoding>] [-ComputerName] <String> [-Credential <PSCredential>]
 [-Port <Int32>] [-UseSSL] [-ApplicationName <String>] [-SessionOption <WinRMSessionOption>]
 [-Authentication <AuthenticationMethod>] [-CertificateThumbprint <String>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### ConnectionUri
```
New-WinRSShell [-ConsoleEncoding <Encoding>] [-ConnectionUri] <Uri> [-Credential <PSCredential>]
 [-SessionOption <WinRMSessionOption>] [-Authentication <AuthenticationMethod>]
 [-CertificateThumbprint <String>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
The `New-WinRSShell` cmdlet connects to a remote Windows host and creates a WinRS `cmd` shell on it.
Pass the shell to the `-Shell` parameter of `Invoke-WinRSCommand`, `Send-WinRSFile` and `Receive-WinRSFile` to run their commands in it.
Without `-Shell` those cmdlets connect and create a shell of their own on every call, so a shared shell is faster when running many commands against the same host.

The shell is the WinRS shell resource that the WinRM service keeps for the client, not a `cmd.exe` process.
Keeping the shell does not keep a command prompt open between commands.
The WinRM service starts every command in a new `cmd.exe /C` process that exits when the command finishes, so nothing one command changes in its process carries over to the next.
This includes the working directory from `cd`, the environment variables from `set`, and `doskey` macros.
Each command starts with the working directory and environment the shell was created with.
Chain the commands in one command line, like `cd C:\temp && build.cmd`, when they need the same state.
Commands can run in the same shell at the same time, for example from `ForEach-Object -Parallel`, up to the limit of processes per shell the remote host allows.

The connection settings, like the credential, the authentication and the session options, are fixed when the shell is created.
The code page of `-ConsoleEncoding` is set on the shell and is the default `-ConsoleEncoding` of `Invoke-WinRSCommand` when it uses the shell.
The file cmdlets do not depend on the code page of the shell.

The shell stays on the remote host until it is removed with `Remove-WinRSShell`, and `Get-WinRSShell` lists it until then.
If it is not removed, it is deleted when the runspace that created it is closed, like when PowerShell exits, or by the remote host once it has been idle for longer than its idle timeout, 2 hours by default.
Once the shell has been removed or deleted, a cmdlet given the shell fails.

This cmdlet does not require `Enable-PSWSMan` to have been run.
The connection parameters are the same as `Invoke-WinRSCommand` and mean the same thing as they do for `Invoke-Command`.
Without `-Credential` or `-CertificateThumbprint` the credential of the current user is used, on Linux and macOS this needs a Kerberos ticket to be available.

## EXAMPLES

### Example 1: Run several commands in one shell
```powershell
PS C:\> $shell = New-WinRSShell -ComputerName Server01 -Credential (Get-Credential)
PS C:\> Invoke-WinRSCommand -Shell $shell -Command 'hostname'
PS C:\> Invoke-WinRSCommand -Shell $shell -Command 'ipconfig'
PS C:\> Remove-WinRSShell -Shell $shell
```

Creates a shell on `Server01`, runs two commands in it and then removes it.

### Example 2: Copy a file and run it in the same shell
```powershell
PS C:\> $shell = New-WinRSShell Server01
PS C:\> try {
>>     Send-WinRSFile -Shell $shell ./setup.exe C:\Windows\Temp\setup.exe
>>     Invoke-WinRSCommand -Shell $shell 'C:\Windows\Temp\setup.exe /quiet'
>> }
>> finally {
>>     Remove-WinRSShell $shell
>> }
```

Copies an installer to the remote host and runs it using the one shell, then removes the shell even if a step failed.

### Example 3: Create a shell with the OEM code page
```powershell
PS C:\> $shell = New-WinRSShell Server01 -ConsoleEncoding 437
PS C:\> Invoke-WinRSCommand -Shell $shell 'dir C:\'
```

Creates the shell with code page 437, the commands run in it write their output in that code page and `Invoke-WinRSCommand` decodes it with the same encoding.

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

### -ComputerName
The host to create the shell on.

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
Its code page is set on the remote shell so `cmd.exe` and the programs it starts read and write in it, and `Invoke-WinRSCommand` uses it by default to decode stdout and stderr and to encode string input of the commands run in the shell.
It accepts an `Encoding` object, a code page number like `437`, one of the names `UTF8`, `UTF8Bom`, `UTF8NoBom`, `ASCII`, `ANSI`, `OEM`, `ConsoleInput` or `ConsoleOutput`, or any other name `[System.Text.Encoding]::GetEncoding()` accepts.
The `ANSI`, `OEM`, `ConsoleInput` and `ConsoleOutput` names resolve to the encodings of the local machine, not the remote host.
The default is UTF-8.

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
The connection options, the output of `New-WinRMSessionOption` or a hashtable of its option names and values, like `@{ OperationTimeout = 30000; AuthProvider = 'Devolutions' }`.
A `PSSessionOption`, like the output of `New-PSSessionOption`, is accepted too, but it is an error if it sets an option PSWSMan does not support, like `NoCompression`, `IdleTimeout` or a proxy.
See `New-WinRMSessionOption` for the options and their defaults.

```yaml
Type: WinRMSessionOption
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

### None
## OUTPUTS

### PSWSMan.WinRSRemoteShell
The shell that was created, pass it to the `-Shell` parameter of the WinRS cmdlets. Its `State` property is `Opened` until the shell is removed.

## NOTES

## RELATED LINKS

[Get-WinRSShell](./Get-WinRSShell.md)

[Remove-WinRSShell](./Remove-WinRSShell.md)

[Invoke-WinRSCommand](./Invoke-WinRSCommand.md)
