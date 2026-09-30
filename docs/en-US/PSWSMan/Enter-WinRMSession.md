---
document type: cmdlet
external help file: PSWSMan.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/PSWSMan/Enter-WinRMSession.md
Module Name: PSWSMan
ms.date: ''
PlatyPS schema version: 2024-05-01
---

# Enter-WinRMSession

## SYNOPSIS

Starts an interactive session with a remote host over PSWSMan's WinRM client without hooking PowerShell.

## SYNTAX

### ComputerName (Default)

```
Enter-WinRMSession [-ComputerName] <string> [-ConfigurationName <string>]
 [-Credential <pscredential>] [-Port <int>] [-UseSSL] [-ApplicationName <string>]
 [-SessionOption <WinRMSessionOption>] [-Authentication <AuthenticationMethod>]
 [-CertificateThumbprint <string>] [<CommonParameters>]
```

### ConnectionUri

```
Enter-WinRMSession [-ConnectionUri] <uri> [-ConfigurationName <string>] [-Credential <pscredential>]
 [-SessionOption <WinRMSessionOption>] [-Authentication <AuthenticationMethod>]
 [-CertificateThumbprint <string>] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

The `Enter-WinRMSession` cmdlet starts an interactive session with a single remote host, the same as `Enter-PSSession -ComputerName`, but the session uses PSWSMan's own WinRM client.
While in the session the commands typed run on the remote host and the prompt is prefixed with the name of the host, like `[Server01]: PS C:\>`.
Use `Exit-PSSession` or `exit` to leave the session, which also closes it on the remote host.

Unlike `Enter-PSSession` this cmdlet does not require `Enable-PSWSMan`.
The session is created through the public custom remoting transport API of PowerShell 7.3 and newer, like `New-WinRMSession`, so the builtin WSMan client is left as is for any other session.
To enter a session that should stay open after exiting it, create it with `New-WinRMSession` and use `Enter-PSSession -Session`.

The connection parameters are the same as `New-WinRMSession` and mean the same thing as they do for `Enter-PSSession`.
A host that cannot be connected to is written as a non-terminating error with the host as its target object.
Stopping the cmdlet with `Ctrl+C` while it connects abandons the connection.

The cmdlet only works in a host that supports interactive sessions, like the `pwsh` console, and not from a nested prompt.

## EXAMPLES

### Example 1: Start an interactive session

```powershell
PS C:\> Enter-WinRMSession -ComputerName Server01 -Credential (Get-Credential)
[Server01]: PS C:\Users\User\Documents> hostname.exe
Server01
[Server01]: PS C:\Users\User\Documents> exit
PS C:\>
```

Starts an interactive session on `Server01`, runs `hostname.exe` there and then leaves and closes the session.

### Example 2: Enter a session over HTTPS with Kerberos delegation

```powershell
PS C:\> $so = New-WinRMSessionOption -AuthMethod Kerberos -RequestKerberosDelegate
PS C:\> Enter-WinRMSession Server01 -UseSSL -SessionOption $so
```

Starts an interactive session on `Server01` over HTTPS with a Kerberos ticket that can be used to access other hosts from the session.

### Example 3: Enter a JEA endpoint with a connection URI

```powershell
PS C:\> Enter-WinRMSession -ConnectionUri https://Server01:5986/wsman -ConfigurationName JEAMaintenance
```

Starts an interactive session on the `JEAMaintenance` session configuration of `Server01`.

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
Unlike `-Authentication` on `Enter-PSSession` this uses the authentication methods of PSWSMan so `NTLM` and `CredSSP` can be selected directly.
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

The host to start the interactive session on.
The host name can also be piped in, or come from the `ComputerName` property of the piped object.

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
It must be an absolute `http` or `https` URI and it is used as is, a URI without a port connects to port 80 or 443 as it does for `Enter-PSSession`, and one without a path uses `/wsman`.
It cannot be used with `-ComputerName`, `-Port`, `-UseSSL` or `-ApplicationName`.
It can also come from the `ConnectionUri` property of the piped object.

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

### System.String

The host name to start the interactive session on. An object with a `ComputerName` property binds by that property.

### System.Uri

The connection URI of the host to start the interactive session on, from an object with a `ConnectionUri` property.

## OUTPUTS

## NOTES

Like `Enter-PSSession -ComputerName`, the session is closed when it is left, which relies on an internal PowerShell property as there is no public way to close it at that point.
A PowerShell release that changes it can stop this cmdlet from working until PSWSMan is updated, `Enter-PSSession -Session (New-WinRMSession ...)` only uses public APIs and keeps working.

The session cannot be disconnected with `Disconnect-PSSession`, and when the connection fails the session is broken and the prompt returns to the local host.

## RELATED LINKS

- [New-WinRMSession](./New-WinRMSession.md)
- [New-WinRMSessionOption](./New-WinRMSessionOption.md)
