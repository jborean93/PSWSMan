---
external help file: PSWSMan.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/Send-WinRSFile.md
schema: 2.0.0
---

# Send-WinRSFile

## SYNOPSIS
Copies local files to a remote host over a WinRS connection.

## SYNTAX

### ComputerName (Default)
```
Send-WinRSFile [-Path] <String[]> [-Destination] <String> [-Compression <CompressionMethod>]
 [-ComputerName] <String> [-Credential <PSCredential>] [-Port <Int32>] [-UseSSL] [-ApplicationName <String>]
 [-SessionOption <PSSessionOption>] [-Authentication <AuthenticationMethod>] [-CertificateThumbprint <String>]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### ConnectionUri
```
Send-WinRSFile [-Path] <String[]> [-Destination] <String> [-Compression <CompressionMethod>]
 [-ConnectionUri] <Uri> [-Credential <PSCredential>] [-SessionOption <PSSessionOption>]
 [-Authentication <AuthenticationMethod>] [-CertificateThumbprint <String>]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The `Send-WinRSFile` cmdlet copies files from the local host to a remote Windows host over a WinRS connection, the same connection `Invoke-WinRSCommand` uses.

WinRS is designed for running commands rather than copying files, so copying through it is slower than tools built for the job.
If the remote host runs an SSH server, `scp` or `sftp` are a better choice, especially for large files.
`Copy-Item` with `-ToSession` and `-FromSession` can also copy files through a PowerShell remoting session, but that needs a PSSession to the remote host and, when PSWSMan is used as the WSMan client, `Enable-PSWSMan` to have been run first.
This cmdlet needs neither.

Each value of `-Path` is the path of a single file.
Directories cannot be copied and wildcards are not expanded.
To copy several files, pass more than one path or pipe them in, for example from `Get-ChildItem`, and each file is copied in turn.
When piping files, `-Destination` can be a script block that returns the destination of each file based on the input value.

When `-Destination` is an existing directory on the remote host, each file is copied into it with its own name.
Otherwise `-Destination` is the path of the file to create, and its parent directory must already exist.
An existing file is replaced.

Each copy is checked against a SHA256 hash of the source before it is written to the destination.
A copy that fails or is stopped never leaves a partial file at the destination, and an existing file there is left unchanged.

The remote host needs Windows PowerShell 5.1 (`powershell.exe`) that runs in the full language mode.
No PowerShell remoting session or file share is needed.

A file that cannot be copied is written as a non-terminating error and the cmdlet moves on to the next file.
Failing to connect to the remote host is a terminating error.
Use `-Verbose` to see the full path each file was copied to.

Stopping the cmdlet with `Ctrl+C` removes the partially copied file from the remote host.
If the connection is lost in the middle of a copy, a hidden file named `.<file name>.<random id>.tmp` can be left in the destination directory on the remote host.

This cmdlet does not require `Enable-PSWSMan` to have been run.
The connection parameters are the same as `Invoke-WinRSCommand` and mean the same thing as they do for `Invoke-Command`.
Without `-Credential` or `-CertificateThumbprint` the credential of the current user is used, on Linux and macOS this needs a Kerberos ticket to be available.

## EXAMPLES

### Example 1: Copy a file to a remote directory
```powershell
PS C:\> Send-WinRSFile -ComputerName Server01 -Path ./installer.msi -Destination C:\Windows\Temp -Credential $cred
```

Copies `installer.msi` to `C:\Windows\Temp\installer.msi` on `Server01`.

### Example 2: Copy a file to a new name
```powershell
PS C:\> Send-WinRSFile Server01 ./app.config 'C:\Program Files\App\app.config'
```

Copies `app.config` using positional parameters, replacing the file if it already exists.

### Example 3: Copy the files matching a wildcard
```powershell
PS C:\> Get-ChildItem ./logs/*.log | Send-WinRSFile Server01 -Destination C:\Logs -Verbose
```

`-Path` does not expand wildcards, so `Get-ChildItem` finds the files and pipes them in.
Each file is copied into `C:\Logs` and the verbose stream shows where it was copied to.

### Example 4: Connect over HTTPS with a connection URI
```powershell
PS C:\> $so = New-PSWSManSessionOption -SkipCACheck -SkipCNCheck
PS C:\> Send-WinRSFile -ConnectionUri https://Server01:5986/wsman -Path ./script.ps1 -Destination C:\temp -SessionOption $so
```

Connects to the HTTPS listener without validating the certificate of the server.

### Example 5: Copy each file to its own destination
```powershell
PS C:\> Get-ChildItem ./configs/*.json | Send-WinRSFile Server01 -Destination { "C:\App\$($_.BaseName).prod.json" }
```

The script block is run for each piped file with the file in `$_`, so each one is copied to a destination built from its name.

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
Accepted values: Default, Basic, Negotiate, NTLM, Kerberos, CredSSP

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

### -Compression
The compression used for the transfer.
`Deflate`, the default, makes text, logs and other compressible files faster to copy.
Use `None` for files that are already compressed, like archives, images or installers, to avoid compressing them again for no benefit.

```yaml
Type: CompressionMethod
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: Deflate
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerName
The host to copy the files to.

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

### -Destination
The path on the remote host to copy the files to, either an existing directory or the path of the file to create.
Relative paths are relative to the profile directory of the user on the remote host.
It can be bound from the pipeline by property name, or given as a script block that is run for each piped file with the file in `$_`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Path
The local files to copy, each value must be the path of a file.
Wildcards are not expanded and relative paths are resolved from the current location.
Files piped from `Get-ChildItem` or `Get-Item` bind by their `PSPath` property.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: PSPath, LiteralPath, FullName

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
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
Only the options that apply to a WinRS connection are used, see `Invoke-WinRSCommand` for the list.

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

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String[]
The local paths to copy, see `-Path`. Objects with a `PSPath`, `LiteralPath` or `FullName` property, like the output of `Get-ChildItem`, bind by that property.

## OUTPUTS

### None
The cmdlet writes no output.

## NOTES

## RELATED LINKS
