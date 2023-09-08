---
external help file: PSWSMan.Module.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/Get-PSWSManAuthProvider.md
schema: 2.0.0
---

# Get-PSWSManAuthProvider

## SYNOPSIS
Gets the default authentication provider used by PSWSMan.

## SYNTAX

```
Get-PSWSManAuthProvider [<CommonParameters>]
```

## DESCRIPTION
Gets the authentication provider used when doing `NTLM`, `Kerberos`, `Negotiate`, or `CredSSP` authentication.

Using `System` will use the system provided authentication provider.
On Windows this is `SSPI`, on Linux this is `GSSAPI`, and on macOS this is `GSS.Framework`.

Using `Devolutions` will use the [sspi-rs](https://github.com/Devolutions/sspi-rs) provider from Devolutions which is a standalone Kerberos and NTLM implementation written in Rust.
The `Devolutions` package is bundled with PSWSMan but is not tested as thoroughly as the `System` implementations.

The default authentication provider is used when `NTLM`, `Kerberos`, `Negotiate`, or `CredSSP` authentication is selected for a PSSession and no explicit provider is specified for the connection.

The default provider set is `System`.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-PSWSManAuthProvider
```

Gets the default authentication provider.

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
This function does not accept input from the pipeline.

## OUTPUTS

### PSWSMan.AuthenticationProvider
The current default authentication provider, either `System` or `Devolutions`.

## NOTES

## RELATED LINKS
