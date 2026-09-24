---
external help file: PSWSMan.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/Get-PSWSManAuth.md
schema: 2.0.0
---

# Get-PSWSManAuth

## SYNOPSIS
Gets the authentication settings used by PSWSMan.

## SYNTAX

```
Get-PSWSManAuth [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Gets the authentication settings that apply to new PSSessions created in the current runspace.
The settings are scoped to the runspace, a fresh runspace, such as a new `Start-ThreadJob` or `ForEach-Object -Parallel` job, starts with the default settings.

The `DefaultAuthProvider` property is the authentication provider used when `NTLM`, `Kerberos`, `Negotiate`, or `CredSSP` authentication is selected for a PSSession and no explicit provider is specified with `New-PSWSManSessionOption -AuthProvider`.
It is `System` unless changed with [Set-PSWSManAuth](./Set-PSWSManAuth.md).

The `GssapiLib` property is the GSSAPI library used by the `System` provider on Linux and macOS.
On Windows it is always `Default` as `SSPI` is used there.
It is `Default` unless changed with [Set-PSWSManAuth](./Set-PSWSManAuth.md), in which case it is the library name or path that was set.

## EXAMPLES

### Example 1: Get the current authentication settings
```powershell
PS C:\> Get-PSWSManAuth

DefaultAuthProvider GssapiLib
------------------- ---------
             System Default
```

Gets the authentication settings for the current runspace.

### Example 2: Check if Devolutions is the default provider
```powershell
PS C:\> (Get-PSWSManAuth).DefaultAuthProvider -eq 'Devolutions'
```

Checks whether the default authentication provider for the current runspace has been set to `Devolutions`.

## PARAMETERS

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
This function does not accept input from the pipeline.

## OUTPUTS

### PSWSMan.Commands.PSWSManAuthSettings
An object with the `DefaultAuthProvider` and `GssapiLib` properties containing the current settings.

## NOTES

## RELATED LINKS

[Set-PSWSManAuth](./Set-PSWSManAuth.md)

[New-PSWSManSessionOption](./New-PSWSManSessionOption.md)

[about_PSWSManAuthentication](./about_PSWSManAuthentication.md)
