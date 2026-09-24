---
external help file: PSWSMan.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/Set-PSWSManAuth.md
schema: 2.0.0
---

# Set-PSWSManAuth

## SYNOPSIS
Sets the authentication settings used by PSWSMan.

## SYNTAX

```
Set-PSWSManAuth [-AuthProvider <AuthenticationProvider>] [-GssapiLib <String>]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Sets the authentication settings that apply to new PSSessions created in the current runspace.
The settings are scoped to the runspace, a fresh runspace, such as a new `Start-ThreadJob` or `ForEach-Object -Parallel` job, starts with the default settings.
Sessions that have already been created are not affected.

The `-AuthProvider` parameter sets the provider used when `NTLM`, `Kerberos`, `Negotiate`, or `CredSSP` authentication is selected for a PSSession and no explicit provider is specified with `New-PSWSManSessionOption -AuthProvider`.

Using `System` will use the system provided authentication provider.
On Windows this is `SSPI`, on Linux this is `GSSAPI`, and on macOS this is `GSS.Framework`.

Using `Devolutions` will use the [sspi-rs](https://github.com/Devolutions/sspi-rs) provider from Devolutions which is a standalone Kerberos and NTLM implementation written in Rust.
The `Devolutions` package is bundled with PSWSMan so is available in more scenarios but is not tested as thoroughly as the `System` implementations.

The `-GssapiLib` parameter sets the GSSAPI library the `System` provider loads on Linux and macOS.
This is useful when the desired library is not on the default library search path or when multiple GSSAPI implementations are installed.

Each requested value is checked before any setting is changed.
Setting `Devolutions` fails if the bundled library cannot be loaded, setting `System` on Linux or macOS fails if the GSSAPI library in effect cannot be loaded, and a `-GssapiLib` value fails if that library cannot be loaded or is missing a required GSSAPI export.
Setting `-GssapiLib` on Windows always fails as `SSPI` is used there and the library would never be loaded.
When a check fails an error is written and no setting is changed.
The error names the library and the reason from the OS loader, such as the file not existing or an export being missing, and keeps the loader's exception as the inner exception.
A library that passes the check is kept loaded and reused by every connection that uses the same setting.

Use [Get-PSWSManAuth](./Get-PSWSManAuth.md) to view the current settings.

## EXAMPLES

### Example 1: Set Devolutions as the default provider
```powershell
PS C:\> Set-PSWSManAuth -AuthProvider Devolutions
```

Sets the default authentication provider to the bundled DevolutionsSspi library.
Any PSSession created after this without an explicit `-AuthProvider` session option will use Devolutions for `NTLM`, `Kerberos`, `Negotiate`, and `CredSSP` authentication.

### Example 2: Use a specific GSSAPI library
```powershell
PS /home/user> Set-PSWSManAuth -GssapiLib /opt/heimdal/lib/libgssapi.so.3
```

Loads the Heimdal GSSAPI library from a custom install location instead of the system default.

### Example 3: Restore the default GSSAPI library
```powershell
PS /home/user> Set-PSWSManAuth -GssapiLib Default
```

Reverts to the GSSAPI library PSWSMan finds on its own, `GSS.Framework` on macOS and the first of MIT krb5 or Heimdal found on Linux.

## PARAMETERS

### -AuthProvider
The authentication provider to set as the default for the current runspace.
This must be either `System` or `Devolutions`.
Using `Default` will result in an error.

```yaml
Type: AuthenticationProvider
Parameter Sets: (All)
Aliases:
Accepted values: Default, System, Devolutions

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -GssapiLib
The name or path of the GSSAPI library to load for the `System` provider.
A bare name like `libgssapi_krb5.so.2` is resolved through the standard library search path while an absolute path loads that file directly.
Use `Default`, in any casing, to revert to the library PSWSMan picks on its own.
The library is loaded when the value is set and an error is written if it cannot be loaded.
Setting this on Windows results in an error as `SSPI` is always used there and a GSSAPI library would never be loaded.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

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
Only the parameters specified are changed, omitting a parameter leaves that setting as it was.
The provider and library checks run before `-WhatIf` is evaluated, so `-WhatIf` still reports an error for a value that cannot be loaded.
A runspace opened from a thread that has no default runspace, for example a host opening one from a thread pool thread, uses the built-in defaults as there is no runspace whose settings could have been changed.

## RELATED LINKS

[Get-PSWSManAuth](./Get-PSWSManAuth.md)

[New-PSWSManSessionOption](./New-PSWSManSessionOption.md)

[about_PSWSManAuthentication](./about_PSWSManAuthentication.md)
