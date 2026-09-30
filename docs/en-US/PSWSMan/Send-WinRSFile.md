---
document type: cmdlet
external help file: PSWSMan.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/PSWSMan/Send-WinRSFile.md
Module Name: PSWSMan
ms.date: ''
PlatyPS schema version: 2024-05-01
---

# Send-WinRSFile

## SYNOPSIS

Copies local files to a remote host over a WinRS connection.

## SYNTAX

### ComputerName (Default)

```
Send-WinRSFile [-ComputerName] <string> [-Path] <string[]> [-Destination] <string>
 [-Compression <CompressionMethod>] [-Credential <pscredential>] [-Port <int>] [-UseSSL]
 [-ApplicationName <string>] [-SessionOption <WinRMSessionOption>]
 [-Authentication <AuthenticationMethod>] [-CertificateThumbprint <string>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

### Shell

```
Send-WinRSFile [-Shell] <WinRSRemoteShell> [-Path] <string[]> [-Destination] <string>
 [-Compression <CompressionMethod>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### ConnectionUri

```
Send-WinRSFile [-ConnectionUri] <uri> [-Path] <string[]> [-Destination] <string>
 [-Compression <CompressionMethod>] [-Credential <pscredential>]
 [-SessionOption <WinRMSessionOption>] [-Authentication <AuthenticationMethod>]
 [-CertificateThumbprint <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

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
Instead of connecting, `-Shell` copies the files through a shell created by `New-WinRSShell`, which is left open afterwards.
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
PS C:\> $so = New-WinRMSessionOption -SkipCACheck -SkipCNCheck
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
Type: System.String
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: ComputerName
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Authentication

The authentication method used to authenticate with the remote host.
The default selects Negotiate, or certificate authentication when `-CertificateThumbprint` or a client certificate in the session option is set.
Unlike `-Authentication` on `Invoke-Command` this uses the authentication methods of PSWSMan so `NTLM` and `CredSSP` can be selected directly.
When set to anything other than `Default` it takes precedence over the `AuthMethod` of the `-SessionOption`.
`Basic` requires either `-UseSSL` or `NoEncryption` in the session option.

```yaml
Type: PSWSMan.AuthenticationMethod
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: ComputerName
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
- Name: ConnectionUri
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues:
- Default
- Basic
- Negotiate
- NTLM
- Kerberos
- CredSSP
HelpMessage: ''
```

### -CertificateThumbprint

The thumbprint of a client certificate in the current user or local machine certificate store to authenticate with.
It requires `-UseSSL` or a `https` `-ConnectionUri` and cannot be used with `-Credential` or `-Authentication`.

```yaml
Type: System.String
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: ComputerName
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
- Name: ConnectionUri
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Compression

The compression used for the transfer.
`Deflate`, the default, makes text, logs and other compressible files faster to copy.
Use `None` for files that are already compressed, like archives, images or installers, to avoid compressing them again for no benefit.

```yaml
Type: PSWSMan.CompressionMethod
DefaultValue: Deflate
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -ComputerName

The host to copy the files to.

```yaml
Type: System.String
DefaultValue: None
SupportsWildcards: false
Aliases:
- Cn
ParameterSets:
- Name: ComputerName
  Position: 0
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Confirm

Prompts you for confirmation before running the cmdlet.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: None
SupportsWildcards: false
Aliases:
- cf
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -ConnectionUri

The full URI of the WSMan endpoint, for example `http://Server01:5985/wsman` or `https://Server01:5986/wsman`.
It must be an absolute `http` or `https` URI and it is used as is, a URI without a port connects to port 80 or 443 as it does for `Invoke-Command`, and one without a path uses `/wsman`.
It cannot be used with `-ComputerName`, `-Port`, `-UseSSL` or `-ApplicationName`.

```yaml
Type: System.Uri
DefaultValue: None
SupportsWildcards: false
Aliases:
- URI
- CU
ParameterSets:
- Name: ConnectionUri
  Position: 0
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Credential

The credential used to authenticate with the remote host through Negotiate authentication.
When not set the credential of the current user is used.

```yaml
Type: System.Management.Automation.PSCredential
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: ComputerName
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
- Name: ConnectionUri
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Destination

The path on the remote host to copy the files to, either an existing directory or the path of the file to create.
Relative paths are relative to the profile directory of the user on the remote host.
It can be bound from the pipeline by property name, or given as a script block that is run for each piped file with the file in `$_`.

```yaml
Type: System.String
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 2
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: true
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Path

The local files to copy, each value must be the path of a file.
Wildcards are not expanded and relative paths are resolved from the current location.
Files piped from `Get-ChildItem` or `Get-Item` bind by their `PSPath` property.

```yaml
Type: System.String[]
DefaultValue: None
SupportsWildcards: false
Aliases:
- PSPath
- LiteralPath
- FullName
ParameterSets:
- Name: (All)
  Position: 1
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: true
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Port

The port of the WSMan listener, the default is `5985` or `5986` with `-UseSSL`.

```yaml
Type: System.Int32
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: ComputerName
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -SessionOption

The connection options, the output of `New-WinRMSessionOption` or a hashtable of its option names and values, like `@{ OperationTimeout = 30000; AuthProvider = 'Devolutions' }`.
A `PSSessionOption`, like the output of `New-PSSessionOption`, is accepted too, but it is an error if it sets an option PSWSMan does not support, like `NoCompression`, `IdleTimeout` or a proxy.
See `New-WinRMSessionOption` for the options and their defaults.

```yaml
Type: PSWSMan.WinRMSessionOption
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: ComputerName
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
- Name: ConnectionUri
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Shell

A WinRS shell created by `New-WinRSShell` to copy the files through, instead of connecting with the connection parameters.
The shell is left open once the files have been copied, remove it with `Remove-WinRSShell`.

```yaml
Type: PSWSMan.WinRSRemoteShell
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: Shell
  Position: 0
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -UseSSL

Connect over HTTPS instead of HTTP.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: ComputerName
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -WhatIf

Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: None
SupportsWildcards: false
Aliases:
- wi
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
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

### System.String[]

The local paths to copy, see `-Path`. Objects with a `PSPath`, `LiteralPath` or `FullName` property, like the output of `Get-ChildItem`, bind by that property.

### System.String

The remote destination, see `-Destination`, from an object with a `Destination` property.

## OUTPUTS

## NOTES

## RELATED LINKS

- [Receive-WinRSFile](./Receive-WinRSFile.md)
- [New-WinRSShell](./New-WinRSShell.md)
- [Invoke-WinRSCommand](./Invoke-WinRSCommand.md)
