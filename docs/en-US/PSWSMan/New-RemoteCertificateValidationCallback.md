---
document type: cmdlet
external help file: PSWSMan.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/PSWSMan/New-RemoteCertificateValidationCallback.md
Module Name: PSWSMan
ms.date: ''
PlatyPS schema version: 2024-05-01
---

# New-RemoteCertificateValidationCallback

## SYNOPSIS

Create a scriptblock delegate to validate certificates.

## SYNTAX

### __AllParameterSets

```
New-RemoteCertificateValidationCallback [-ScriptBlock] <scriptblock> [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

Creates a `RemoteCertificateValidationCallback` delegate that validates the certificate presented by a remote server with a PowerShell scriptblock.
.NET calls such a callback on whatever thread does the TLS handshake, where a scriptblock cannot normally run, so the scriptblock is run in a separate runspace each time the delegate is called and it is safe to call from any thread.
Because of that the scriptblock does not have access to the variables or module scope it was defined in, use the `$using:varName` syntax to pass in variables.

The delegate is not specific to PSWSMan, it can be used with any .NET API that takes a `RemoteCertificateValidationCallback`, like `System.Net.Security.SslStream` or `System.Net.Security.SslClientAuthenticationOptions`.
With PSWSMan it is set as the `RemoteCertificateValidationCallback` of the `-TlsOption` or `-CredSSPTlsOption` of `New-WinRMSessionOption`.

The last returned object must be a bool where `$true` will accept the certificate and `$false` does not.
If there is no output or the last object is not a `[bool]` then it will be treated as `$false`.
Anything else output before the last object is ignored.

## EXAMPLES

### Example 1: Create a callback that accepts all certificates

```powershell
PS C:\> $delegate = New-RemoteCertificateValidationCallback -ScriptBlock { $true }
PS C:\> $tlsOptions = [System.Net.Security.SslClientAuthenticationOptions]@{
>>     RemoteCertificateValidationCallback = $delegate
>>     TargetHost = 'host'
>> }
PS C:\> $pso = New-WinRMSessionOption -TlsOption $tlsOptions
```

Creates a WSMan session option that will accept any certificate essentially disabling cert verification.

### Example 2: Create a callback with param signature that rejects hosts in a list

```powershell
PS C:\> $denyHosts = @('CN=host1', 'CN=host2')
PS C:\> $delegate = New-RemoteCertificateValidationCallback -ScriptBlock {
>>     param (
>>         [System.Net.Security.SslStream]$Sender,
>>         [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,
>>         [System.Security.Cryptography.X509Certificates.X509Chain]$Chain,
>>         [System.Net.Security.SslPolicyErrors]$PolicyErrors
>>     )
>>
>>     # Delegate has access to the same host to display host messages
>>     Write-Host $Certificate.Subject
>>
>>     # Pulls in the $denyHosts variable
>>     $denyHosts = $using:denyHosts
>>
>>     # Returns $true if the subject is not one we want to deny
>>     $Certificate.Subject -notin $denyHosts
>> }
PS C:\> $tlsOptions = [System.Net.Security.SslClientAuthenticationOptions]@{
>>     RemoteCertificateValidationCallback = $delegate
>>     TargetHost = 'host1'
>> }
PS C:\> $pso = New-WinRMSessionOption -TlsOption $tlsOptions
```

Creates a WSMan session option with a callback that rejects certs with the subject `CN=host1` or `CN=host2`.

## PARAMETERS

### -ScriptBlock

The scriptblock to run as the delegate.
Variables outside the scriptblock can be accessed through the `$using:varName` syntax.
The last output object when the scriptblock is run will be used as the result for the validation.

The scriptblock is called with 4 positional arguments:

+ `[System.Net.Security.SslStream]$Sender` - The SslStream used for the connection

+ `[System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate` - The certificate of the server

+ `[System.Security.Cryptography.X509Certificates.X509Chain]$Chain` - The chain of certificate authorities associated with the remote certificate

+ `[System.Net.Security.SslPolicyErrors]$PolicyErrors` - One or more errors associated with the remote certificate

The scriptblock also has access to the `$host` variable and can perform any host actions like `Write-Host`.
The host is the same host that `New-RemoteCertificateValidationCallback` was associated with.

```yaml
Type: System.Management.Automation.ScriptBlock
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 1
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

### System.Net.Security.RemoteCertificateValidationCallback

The callback that can be used for the `RemoteCertificateValidationCallback` property on the `SslClientAuthenticationOptions`.

## NOTES

## RELATED LINKS

- [RemoteCertificateValidationCallback](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.remotecertificatevalidationcallback?view=net-6.0)
