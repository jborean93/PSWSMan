---
document type: cmdlet
external help file: PSWSMan.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/PSWSMan/New-WinRMSessionOption.md
Module Name: PSWSMan
ms.date: ''
PlatyPS schema version: 2024-05-01
---

# New-WinRMSessionOption

## SYNOPSIS

Creates the connection options for PSWSMan and the builtin remoting cmdlets.

## SYNTAX

### SimpleTls (Default)

```
New-WinRMSessionOption [-NoMachineProfile] [-Culture <cultureinfo>] [-UICulture <cultureinfo>]
 [-MaxConnectionRetryCount <int>] [-ApplicationArguments <psprimitivedictionary>]
 [-OpenTimeout <int>] [-CancelTimeout <int>] [-OperationTimeout <int>] [-SkipCACheck] [-SkipCNCheck]
 [-ClientCertificate <X509Certificate>] [-NoEncryption] [-SPNService <string>]
 [-SPNHostName <string>] [-AuthMethod <AuthenticationMethod>]
 [-AuthProvider <AuthenticationProvider>] [-RequestKerberosDelegate]
 [-CredSSPAuthMethod <AuthenticationMethod>] [-CredSSPTlsOption <SslClientAuthenticationOptions>]
 [-TracePath <string>] [<CommonParameters>]
```

### TlsOption

```
New-WinRMSessionOption [-NoMachineProfile] [-Culture <cultureinfo>] [-UICulture <cultureinfo>]
 [-MaxConnectionRetryCount <int>] [-ApplicationArguments <psprimitivedictionary>]
 [-OpenTimeout <int>] [-CancelTimeout <int>] [-OperationTimeout <int>]
 [-TlsOption <SslClientAuthenticationOptions>] [-NoEncryption] [-SPNService <string>]
 [-SPNHostName <string>] [-AuthMethod <AuthenticationMethod>]
 [-AuthProvider <AuthenticationProvider>] [-RequestKerberosDelegate]
 [-CredSSPAuthMethod <AuthenticationMethod>] [-CredSSPTlsOption <SslClientAuthenticationOptions>]
 [-TracePath <string>] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

The `New-WinRMSessionOption` cmdlet creates an object with the connection options for every way PSWSMan connects to a host.
It has the options of `New-PSSessionOption` that PSWSMan supports and the options specific to PSWSMan, like the authentication provider, the Kerberos SPN, the CredSSP settings and custom TLS options.

The object can be used with:

+ The `-SessionOption` parameter of `New-WinRMSession` and the WinRS cmdlets, like `Invoke-WinRSCommand` and `New-WinRSShell`

+ The `-SessionOption` parameter of the builtin remoting cmdlets, like `New-PSSession`, `Invoke-Command` and `Enter-PSSession`, and the `$PSSessionOption` preference variable they use when `-SessionOption` is not set

For the builtin cmdlets the object is converted to a `PSSessionOption` automatically, or explicitly with `[System.Management.Automation.Remoting.PSSessionOption]$option` or `$option.ToPSSessionOption()`.
The options specific to PSWSMan are attached to the converted object and only apply once `Enable-PSWSMan` has been run, PowerShell's own WSMan client ignores them.

The `-SessionOption` parameters of `New-WinRMSession` and the WinRS cmdlets also accept a hashtable whose keys are the names of the properties of the object this cmdlet creates, like `@{ OperationTimeout = 30000; SkipCACheck = $true }`.
The keys are not case sensitive and an unknown key is an error.
The timeouts in a hashtable can be a `TimeSpan`, a `TimeSpan` string like `'00:00:30'`, or a number of milliseconds like the parameters of this cmdlet.
They accept a `PSSessionOption` too, like the output of `New-PSSessionOption`, but it is an error if it sets an option PSWSMan does not support.

The following options of `New-PSSessionOption` are not available:

+ `-IdleTimeout`, `-OutputBufferingMode`: disconnected sessions are not implemented

+ `-IncludePortInSPN`: use `-SPNHostName` to set the host portion of the SPN instead

+ `-MaximumRedirection`: redirection is not implemented

+ `-MaximumReceivedDataSizePerCommand`, `-MaximumReceivedObjectSize`: these limits are applied by PowerShell rather than the WinRM client so only the builtin cmdlets can use them, set them on the converted `PSSessionOption` as shown in the examples

+ `-NoCompression`: compression is not implemented

+ `-ProxyAccessType`, `-ProxyAuthentication`, `-ProxyCredential`: proxies are not implemented

+ `-SkipRevocationCheck`: .NET does not check revocation by default as it is not implemented on all platforms, use `-TlsOption` with `CertificateRevocationCheckMode` set to `Offline` or `Online` to check it

+ `-UseUTF16`: not implemented

## EXAMPLES

### Example 1: Create the default options

```powershell
PS C:\> New-WinRMSessionOption
```

Creates an options object with the default values.

### Example 2: Use Kerberos with delegation for a session

```powershell
PS C:\> $so = New-WinRMSessionOption -AuthMethod Kerberos -RequestKerberosDelegate
PS C:\> $session = New-WinRMSession -ComputerName Server01 -SessionOption $so
```

Creates a session on `Server01` that authenticates with Kerberos and requests a delegatable ticket so the session can authenticate to other hosts.

### Example 3: Use a hashtable instead of this cmdlet

```powershell
PS C:\> Invoke-WinRSCommand Server01 hostname -UseSSL -SessionOption @{ SkipCNCheck = $true; OperationTimeout = 30000 }
```

Passes the options as a hashtable, the same as `-SessionOption (New-WinRMSessionOption -SkipCNCheck -OperationTimeout 30000)`.

### Example 4: Use the options with the builtin remoting cmdlets

```powershell
PS C:\> Enable-PSWSMan -Force
PS C:\> $so = New-WinRMSessionOption -AuthProvider Devolutions -Culture en-AU
PS C:\> Invoke-Command -ComputerName Server01 -SessionOption $so -ScriptBlock { Get-Culture }
PS C:\> $PSSessionOption = $so
PS C:\> Enter-PSSession -ComputerName Server01
```

Uses the Devolutions authentication provider and the `en-AU` culture with `Invoke-Command`, then sets the options as the default for the builtin remoting cmdlets through `$PSSessionOption`.

### Example 5: Set a builtin option that this cmdlet does not have

```powershell
PS C:\> $pso = [System.Management.Automation.Remoting.PSSessionOption](New-WinRMSessionOption -AuthMethod Kerberos)
PS C:\> $pso.MaximumReceivedObjectSize = 500MB
PS C:\> Invoke-Command -ComputerName Server01 -SessionOption $pso -ScriptBlock { Get-Process }
```

Converts the options to a `PSSessionOption` so the builtin `MaximumReceivedObjectSize` can be set, the PSWSMan options stay attached to it.
Such an object is only for the builtin cmdlets, `New-WinRMSession` and the WinRS cmdlets reject it as they cannot apply the limit.

### Example 6: Validate the server certificate with a scriptblock

```powershell
PS C:\> $tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
>>     TargetHost = 'Server01'
>>     RemoteCertificateValidationCallback = New-RemoteCertificateValidationCallback { param($Sender, $Cert, $Chain, $Errors) $Cert.Issuer -eq 'CN=My CA' }
>> }
PS C:\> $session = New-WinRMSession Server01 -UseSSL -SessionOption (New-WinRMSessionOption -TlsOption $tlsOption)
```

Accepts the server certificate only when it was issued by `CN=My CA`.

## PARAMETERS

### -ApplicationArguments

A `PSPrimitiveDictionary` that is sent to the remote PowerShell session.
Commands and scripts in the remote session, including startup scripts in the session configuration, can find this dictionary with `$PSSenderInfo.ApplicationArguments`.
A `PSPrimitiveDictionary` is limited to case-insensitive keys and a subset of primitive value types, like `string`, `int`, `datetime`, etc.
A hashtable is converted to one.
The WinRS cmdlets do not start a PowerShell session so they ignore it.

```yaml
Type: System.Management.Automation.PSPrimitiveDictionary
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

### -AuthMethod

The authentication method to use.
If omitted, or set to `Default`, Negotiate is used, or certificate authentication when a client certificate is set.
The `-Authentication` parameter of the cmdlet using the options, including the builtin remoting cmdlets, takes precedence when it is set to anything other than `Default`.

```yaml
Type: PSWSMan.AuthenticationMethod
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
AcceptedValues:
- Default
- Basic
- Negotiate
- NTLM
- Kerberos
- CredSSP
HelpMessage: ''
```

### -AuthProvider

The authentication provider to use when doing `NTLM`, `Kerberos`, `Negotiate`, or `CredSSP` authentication.
If omitted, or set to `Default`, then the default provider of the current runspace is used.
Use [Get-PSWSManAuth](./Get-PSWSManAuth.md) to get the runspace default and [Set-PSWSManAuth](./Set-PSWSManAuth.md) to set it.

Using `System` will use the system provided authentication provider.
On Windows this is `SSPI`, on Linux this is `GSSAPI`, and on macOS this is `GSS.Framework`.

Using `Devolutions` will use the [sspi-rs](https://github.com/Devolutions/sspi-rs) provider from Devolutions which is a standalone Kerberos and NTLM implementation written in Rust.

```yaml
Type: PSWSMan.AuthenticationProvider
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
AcceptedValues:
- Default
- System
- Devolutions
HelpMessage: ''
```

### -CancelTimeout

How long, in milliseconds, PowerShell waits for a cancel operation (`ctrl + c`) of a command in a session to finish.
The default value is `60000` (one minute).

```yaml
Type: System.Int32
DefaultValue: None
SupportsWildcards: false
Aliases:
- CancelTimeoutMSec
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

### -ClientCertificate

The `X509Certificate` used for TLS client authentication, otherwise known as certificate authentication with WinRM.
The certificate must have a private key and the connection must use HTTPS.
Use the `-CertificateThumbprint` parameter of the cmdlet using the options for a certificate in the `Cert:\CurrentUser\My` or `Cert:\LocalMachine\My` store instead.

You cannot use this parameter with `-TlsOption`, set the `ClientCertificates` property of the TLS options instead.

```yaml
Type: System.Security.Cryptography.X509Certificates.X509Certificate
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: SimpleTls
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -CredSSPAuthMethod

The sub-authentication protocol that CredSSP uses.
By default CredSSP uses `Negotiate` but it can be set to `Negotiate`, `NTLM` or `Kerberos`.
The `Basic` and `CredSSP` options cannot be specified here.

```yaml
Type: PSWSMan.AuthenticationMethod
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
AcceptedValues:
- Default
- Basic
- Negotiate
- NTLM
- Kerberos
- CredSSP
HelpMessage: ''
```

### -CredSSPTlsOption

The TLS options used by CredSSP when it establishes its TLS connection to the server.
This allows you to control the TLS behaviour of the CredSSP connection, like validating the server certificate, or the TLS protocol and cipher suites.

```yaml
Type: System.Net.Security.SslClientAuthenticationOptions
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

### -Culture

The culture to use for the remote session or shell, like `ja-JP` or `en-US`, or a `CultureInfo` object.
The default is the culture of the current thread.

```yaml
Type: System.Globalization.CultureInfo
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

### -MaxConnectionRetryCount

The number of times a `Receive` request is resent on a new connection if it fails due to network issues, for example when the remote command restarts the network adapter and the response is lost.
WSMan returns the same response for a repeated request so the retry does not lose or duplicate any output.
Each retry waits twice as long as the previous one, starting at 2 seconds.
Set to `0` to fail on the first network failure.
The default value is `5`.

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

### -NoEncryption

Turns off the message encryption used by `NTLM`, `Kerberos`, and `CredSSP` authentication over HTTP.
This should only be used for testing purposes as any data exchanged over the network will be in plaintext.

```yaml
Type: System.Management.Automation.SwitchParameter
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

### -NoMachineProfile

Prevents loading the user's Windows user profile on the remote host.
The session or shell might be created faster, but user-specific registry settings, environment variables, and certificates are not available in it.

```yaml
Type: System.Management.Automation.SwitchParameter
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

### -OpenTimeout

How long, in milliseconds, to wait for a connection to the remote host to be established.
The default is `180000` (3 minutes) and a value of `0` uses a 10 second timeout.
Pressing `Ctrl+C` stops a connection attempt before the timeout expires.

```yaml
Type: System.Int32
DefaultValue: None
SupportsWildcards: false
Aliases:
- OpenTimeoutMSec
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

### -OperationTimeout

The maximum time, in milliseconds, the WinRM service on the remote host waits to complete an operation, like creating a shell or waiting for output, before it replies.
The client waits 30 seconds longer than this for a reply before it treats the request as lost.
The default and the value used for `0` is `180000` (3 minutes).

```yaml
Type: System.Int32
DefaultValue: None
SupportsWildcards: false
Aliases:
- OperationTimeoutMSec
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

### -RequestKerberosDelegate

When using Kerberos auth, or Kerberos through Negotiate, this requests the ticket from the KDC to have delegation enabled.
For this to work on Linux and macOS the ticket retrieved through `kinit` must be forwardable, or if an explicit credential is specified then the `krb5.conf` used must be configured to request forwardable tickets.

```yaml
Type: System.Management.Automation.SwitchParameter
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

### -SkipCACheck

Specifies that when it connects over HTTPS, the client does not validate that the server certificate is signed by a trusted certification authority (CA).
This option is mutually exclusive to `-TlsOption`.

Use this option only when the remote computer is trusted by using another mechanism.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: SimpleTls
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -SkipCNCheck

Specifies that the certificate common name (CN) of the server does not have to match the hostname of the server.
This option is used only when connecting over HTTPS.
This option is mutually exclusive to `-TlsOption`.

Use this option only when the remote computer is trusted by using another mechanism.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: SimpleTls
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -SPNHostName

Override the hostname portion used for the Service Principal Name (SPN) requested by Kerberos.
By default the hostname of the connection is used.

The SPN is built in the form `$SPNService/$SPNHostName` where the `$SPNService` can be specified by `-SPNService`.

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

### -SPNService

Override the service portion used for the Service Principal Name (SPN) requested by Kerberos.
By default the service `host` is used.

The SPN is built in the form `$SPNService/$SPNHostName` where `$SPNHostName` can be specified by `-SPNHostName`.

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

### -TlsOption

The TLS options used on a HTTPS connection.
This option is mutually exclusive to `-SkipCACheck`, `-SkipCNCheck`, and `-ClientCertificate`.

This value controls the TLS handshake in more detail, like the protocols and cipher suites used, and can provide custom certificate validation.
The [New-RemoteCertificateValidationCallback](./New-RemoteCertificateValidationCallback.md) cmdlet creates a `RemoteCertificateValidationCallback` for it that runs a PowerShell scriptblock.

An explicit `-TlsOption` ignores the `-CertificateThumbprint` parameter of the cmdlet using the options.
Use the `ClientCertificates` property of the TLS options for certificate authentication, `AllowTlsResume` is then set to `$false` on the object as a resumed TLS session skips the client certificate exchange.

```yaml
Type: System.Net.Security.SslClientAuthenticationOptions
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: TlsOption
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -TracePath

The path of a file that the diagnostic messages of the connection are appended to, useful for troubleshooting connection and authentication problems.
A relative path is resolved against the current location when this cmdlet runs, or when the cmdlet using a hashtable of options runs.
The file is created if it does not exist and several connections can write to the same file.

It is only used by `New-WinRMSession` and the WinRS cmdlets, like `Invoke-WinRSCommand`.
The builtin remoting cmdlets, like `New-PSSession` and `Invoke-Command` after `Enable-PSWSMan`, ignore it and write the same messages to the `ClientTransport` trace source instead, use `Trace-Command -Name ClientTransport` to see them.

Every line starts with a timestamp that includes the UTC offset and the id of the thread that wrote it, like `2026-09-29T11:04:51.372+10:00 [19] `.
The messages include the WSMan operations sent and the HTTP responses.
For `New-WinRMSession` they also include every PowerShell remoting (OutOfProc) packet in full, each on its own line starting with `PSWSMan OutOfProc Packet [<runspace pool id>] Sent: ` for the packets PowerShell sent or `Received: ` for the ones it received, so they can be filtered in or out with `Select-String`.
Authentication tokens are not written but the packets contain the commands and output of the session, treat the file as sensitive and remove it once it is no longer needed.

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

### -UICulture

The UI culture to use for the remote session or shell, like `ja-JP` or `en-US`, or a `CultureInfo` object.
The default is the UI culture of the current thread.

```yaml
Type: System.Globalization.CultureInfo
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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### PSWSMan.WinRMSessionOption

The connection options, pass them to the `-SessionOption` parameter of `New-WinRMSession`, the WinRS cmdlets, or the builtin remoting cmdlets.

## NOTES

## RELATED LINKS

- [New-WinRMSession](./New-WinRMSession.md)
- [Invoke-WinRSCommand](./Invoke-WinRSCommand.md)
- [New-RemoteCertificateValidationCallback](./New-RemoteCertificateValidationCallback.md)
- [Enable-PSWSMan](./Enable-PSWSMan.md)
