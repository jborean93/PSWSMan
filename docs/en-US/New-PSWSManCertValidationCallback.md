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

The last returned object is casted to a bool and used as the validation result where:

+ `$true` - The certificate is accepted

+ `$false` - The certificate is rejected

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

## PARAMETERS

### -ScriptBlock
The scriptblock to run as the delegate.
Variables outside the scriptblock can be accessed through the `$using:varName` syntax.
The last output object when the scriptblock is run will be used as the result for the validation.

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
