---
document type: cmdlet
external help file: PSWSMan.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/PSWSMan/New-WinRMSession.md
Module Name: PSWSMan
ms.date: ''
PlatyPS schema version: 2024-05-01
---

# New-WinRMSession

## SYNOPSIS

Creates a PowerShell session over PSWSMan's WinRM client without hooking PowerShell.

## SYNTAX

### ComputerName (Default)

```
New-WinRMSession [-ComputerName] <string[]> [-ConfigurationName <string>] [-Name <string[]>]
 [-ThrottleLimit <int>] [-Credential <pscredential>] [-Port <int>] [-UseSSL]
 [-ApplicationName <string>] [-SessionOption <WinRMSessionOption>]
 [-Authentication <AuthenticationMethod>] [-CertificateThumbprint <string>] [<CommonParameters>]
```

### ConnectionUri

```
New-WinRMSession [-ConnectionUri] <uri[]> [-ConfigurationName <string>] [-Name <string[]>]
 [-ThrottleLimit <int>] [-Credential <pscredential>] [-SessionOption <WinRMSessionOption>]
 [-Authentication <AuthenticationMethod>] [-CertificateThumbprint <string>] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

The `New-WinRMSession` cmdlet creates a PowerShell session (PSSession) on a remote host using PSWSMan's own WinRM client.
The session can be used with the builtin cmdlets that take a PSSession, like `Invoke-Command -Session`, `Enter-PSSession -Session`, `Import-PSSession`, `Copy-Item -ToSession` and `Remove-PSSession`, and it is listed by `Get-PSSession` with the transport `PSWSMan`.

Unlike `New-PSSession` this cmdlet does not require `Enable-PSWSMan`.
It plugs into PowerShell through the public custom remoting transport API of PowerShell 7.3 and newer, so nothing in the PowerShell engine is modified and the builtin WSMan client is left as is for any other session.
The PowerShell Remoting Protocol (PSRP) messages exchanged with the remote host are the same as a session created by `New-PSSession`, only the client that sends them over WinRM differs.

Several sessions can be created at once by passing more than one host to `-ComputerName` or `-ConnectionUri`, or by piping the host names in.
The sessions are opened at the same time, up to `-ThrottleLimit` at once, and each one is output as soon as it is open, so they are not necessarily in the order of the hosts.
A host that cannot be connected to is written as a non-terminating error with the host as its target object and the other sessions are still created.
Stopping the cmdlet with `Ctrl+C` abandons the connections still being made and keeps the sessions that were already output.

A session created this way cannot be disconnected and reconnected with `Disconnect-PSSession` and `Connect-PSSession`, and `Invoke-Command -InDisconnectedSession` is not supported.
When the connection fails while the session is in use, the whole session is broken rather than just the command that was running.

The connection parameters are the same as the WinRS cmdlets like `Invoke-WinRSCommand` and mean the same thing as they do for `New-PSSession`.
Without `-Credential` or `-CertificateThumbprint` the credential of the current user is used, on Linux and macOS this needs a Kerberos ticket to be available.
The default authentication is Negotiate, which uses Kerberos where possible and falls back to NTLM otherwise, and a HTTP connection encrypts the messages with it unless `NoEncryption` is set in the session option.

## EXAMPLES

### Example 1: Run a command in a session

```powershell
PS C:\> $session = New-WinRMSession -ComputerName Server01 -Credential (Get-Credential)
PS C:\> Invoke-Command -Session $session -ScriptBlock { hostname.exe }
PS C:\> Remove-PSSession -Session $session
```

Creates a session on `Server01`, runs `hostname.exe` in it and then removes the session.

### Example 2: Connect over HTTPS with options from a hashtable

```powershell
PS C:\> $so = @{ OperationTimeout = 30000; AuthProvider = 'Devolutions' }
PS C:\> $session = New-WinRMSession Server01 -UseSSL -SessionOption $so -Name build
PS C:\> Enter-PSSession -Session $session
```

Creates a session named `build` over HTTPS with a 30 second operation timeout and the Devolutions authentication provider, then enters it interactively.

### Example 3: Connect to a JEA endpoint

```powershell
PS C:\> $session = New-WinRMSession -ComputerName Server01 -ConfigurationName JEAMaintenance
PS C:\> Invoke-Command -Session $session -ScriptBlock { Get-Command }
```

Creates a session on the `JEAMaintenance` session configuration and lists the commands it exposes.

### Example 4: Create sessions to several hosts

```powershell
PS C:\> $sessions = Get-Content ./servers.txt | New-WinRMSession -ThrottleLimit 8 -ErrorVariable failed
PS C:\> Invoke-Command -Session $sessions -ScriptBlock { Get-Service -Name WinRM }
PS C:\> $failed.TargetObject
```

Opens a session to each host listed in `servers.txt`, eight at a time, runs a command on all of them in parallel and then lists the hosts that could not be connected to.

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
Unlike `-Authentication` on `New-PSSession` this uses the authentication methods of PSWSMan so `NTLM` and `CredSSP` can be selected directly.
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

### -ComputerName

The hosts to create a session on, one session for each.
The host names can also be piped in, or come from the `ComputerName` property of the piped objects.

```yaml
Type: System.String[]
DefaultValue: None
SupportsWildcards: false
Aliases:
- Cn
ParameterSets:
- Name: ComputerName
  Position: 0
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: true
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -ConfigurationName

The session configuration (endpoint) on the remote host to connect to, the default is `Microsoft.PowerShell`.
A name is turned into the resource URI `http://schemas.microsoft.com/powershell/<name>`, a value that contains a `/` is used as the resource URI as is.

```yaml
Type: System.String
DefaultValue: None
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

### -ConnectionUri

The full URI of the WSMan endpoint, for example `http://Server01:5985/wsman` or `https://Server01:5986/wsman`.
It must be an absolute `http` or `https` URI and it is used as is, a URI without a port connects to port 80 or 443 as it does for `New-PSSession`, and one without a path uses `/wsman`.
It cannot be used with `-ComputerName`, `-Port`, `-UseSSL` or `-ApplicationName`.
A session is created for each URI, which can also come from the `ConnectionUri` property of the piped objects.

```yaml
Type: System.Uri[]
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
  ValueFromPipelineByPropertyName: true
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Credential

The credential used to authenticate with the remote host.
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

### -Name

Friendly names for the sessions, shown by `Get-PSSession` and usable with its `-Name` parameter.
The names are matched to the hosts in order, the first name is given to the session of the first host and so on.
When there are fewer names than hosts the remaining sessions get the default name `Runspace<Id>`, and the name of a host that could not be connected to is not used.

```yaml
Type: System.String[]
DefaultValue: None
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
The `ApplicationArguments` of the options are sent to the remote session and available there in `$PSSenderInfo.ApplicationArguments`.
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

### -ThrottleLimit

The most sessions that are opened at the same time.
The default is `32`, a value of `0` or less also uses the default.
It only limits the opening of the sessions, not how many are created.

```yaml
Type: System.Int32
DefaultValue: None
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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String[]

The host names to create a session on. An object with a `ComputerName` property binds by that property.

### System.Uri[]

The connection URIs of the hosts to create a session on, from an object with a `ConnectionUri` property.

## OUTPUTS

### System.Management.Automation.Runspaces.PSSession

A session for each host that was connected to, its `Transport` is `PSWSMan` and its `Runspace.ConnectionInfo` is a `PSWSMan.CustomTransport.WinRMConnectionInfo`.

## NOTES

## RELATED LINKS

- [New-WinRMSessionOption](./New-WinRMSessionOption.md)
- [Enable-PSWSMan](./Enable-PSWSMan.md)
- [Invoke-WinRSCommand](./Invoke-WinRSCommand.md)
