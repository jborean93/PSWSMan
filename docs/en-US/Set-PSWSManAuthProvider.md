---
external help file: PSWSMan.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/Set-PSWSManAuthProvider.md
schema: 2.0.0
---

# Set-PSWSManAuthProvider

## SYNOPSIS
Sets the default authentication provider used by PSWSMan.

## SYNTAX

```
Set-PSWSManAuthProvider [-AuthProvider] <AuthenticationProvider> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Sets the authentication provider used when doing `NTLM`, `Kerberos`, `Negotiate`, or `CredSSP` authentication.

Using `System` will use the system provided authentication provider.
On Windows this is `SSPI`, on Linux this is `GSSAPI`, and on macOS this is `GSS.Framework`.

Using `Devolutions` will use the [sspi-rs](https://github.com/Devolutions/sspi-rs) provider from Devolutions which is a standalone Kerberos and NTLM implementation written in Rust.
The `Devolutions` package is bundled with PSWSMan but is not tested as thourougly as the `System` implementations.

The default authentication provider is used when `NTLM`, `Kerberos`, `Negotiate`, or `CredSSP` authentication is selected for a PSSession and no explicit provider is specified for the connection.

The default provider set is `System`.

## EXAMPLES

### Example 1: Set System as the default provider
```powershell
PS C:\> Set-PSWSManAuthProvider -AuthProvider System
```

Sets the default authentication provider to the use system libraries (SSPI/GSSAPI).

### Example 2: Set Devolutions as the default provider
```powershell
PS C:\> Set-PSWSManAuthProvider -AuthProvider Devolutions
```

Sets the default authentication provider to the use the bundles DevolutionsSspi library.

## PARAMETERS

### -AuthProvider
The authentication provider to set asthe PSWSMan default.
This must be either `System` or `Devolutions`.
Using `Default` will result in an error.

```yaml
Type: AuthenticationProvider
Parameter Sets: (All)
Aliases:
Accepted values: Default, System, Devolutions

Required: True
Position: 0
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

### None
This function does not accept input from the pipeline.

## OUTPUTS

### None
This function does not output to the pipeline.

## NOTES

## RELATED LINKS
