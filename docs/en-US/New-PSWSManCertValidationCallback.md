---
external help file: PSWSMan.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/New-PSWSManCertValidationCallback.md
schema: 2.0.0
---

# New-PSWSManCertValidationCallback

## SYNOPSIS
Create a scriptblock delegate to validate certificates.

## SYNTAX

```
New-PSWSManCertValidationCallback [-ScriptBlock] <ScriptBlock> [<CommonParameters>]
```

## DESCRIPTION
Creates a delegate object that can be used as a delegate for `RemoteCertificateValidationCallback`.
This delegate is used to validate the certificates received by a remote server using a PowerShell scriptblock.
The scriptblock is run through a separate Runspace so will not have access to the same module scope from where it is run.
Use the `$using:varName` syntax to inject these variables in the delegate scope.

The last returned object must be a bool where `$true` will accept the certificate and `$false` does not.
If there is no output or the last object is not a `[bool]` then it will be treated as `$false`.
Anyything else outputted before the last object will be ignored.

## EXAMPLES

### Example 1: Create a callback that accepts all certificates
```powershell
PS C:\> $delegate = New-PSWSManCertValidationCallback -ScriptBlock { $true }
PS C:\> $tlsOptions = [System.Net.Security.SslClientAuthenticationOptions]@{
>>     RemoteCertificateValidationCallback = $delegate
>>     TargetHost = 'host'
>> }
PS C:\> $pso = New-PSWSManSessionOption -TlsOption $tlsOptions
```

Creates a WSMan session option that will accept any certificate essentially disabling cert verification.

### Example 2: Create a callback with param signature that rejects hosts in a list
```powershell
PS C:\> $denyHosts = @('CN=host1', 'CN=host2')
PS C:\> $delegate = New-PSWSManCertValidationCallback -ScriptBlock {
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
PS C:\> $pso = New-PSWSManSessionOption -TlsOption $tlsOptions
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
The host is the same host that `New-PSWSManCertValidationCallback` was associated with.

```yaml
Type: ScriptBlock
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.Net.Security.RemoteCertificateValidationCallback
The callback that can be used for the `RemoteCertificateValidationCallback` property on the `SslClientAuthenticationOptions`.

## NOTES

## RELATED LINKS

[RemoteCertificateValidationCallback](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.remotecertificatevalidationcallback?view=net-6.0)
