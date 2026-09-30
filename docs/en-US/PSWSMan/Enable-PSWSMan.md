---
document type: cmdlet
external help file: PSWSMan.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/PSWSMan/Enable-PSWSMan.md
Module Name: PSWSMan
ms.date: ''
PlatyPS schema version: 2024-05-01
---

# Enable-PSWSMan

## SYNOPSIS

Enables PSWSMan as the transport method for WSMan based transports in PowerShell.

## SYNTAX

### __AllParameterSets

```
Enable-PSWSMan [-Force] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

The `Enable-PSWSMan` cmdlet injects itself into the PowerShell engine to force it to use the WSMan client it provides for WSMan transports.
It is used to remove the use of the C omi library that PowerShell ships with which has limited features and support.

On non-Windows platforms this cmdlet also hooks the `CimInstance` deserializer so those objects are returned as deserialized property bags without needing `libmi`.
They keep the same properties and formatting but are not a live `CimInstance`.

This operation is global to the process and is not reversible, once it has been enabled it cannot be disabled without restarting the process.

The hooks patch internal PowerShell methods at runtime, rewriting them in memory with MonoMod so they call this module's code.
This relies on implementation details of PowerShell and the .NET runtime that are not a supported API, so a new .NET release, including previews and other pre-releases, or a new PowerShell version can make this cmdlet fail or the builtin remoting cmdlets misbehave.
PSWSMan is updated for new releases once such a break is known, but there can be a gap before a fixed version is available.
Only the builtin remoting cmdlets depend on this patching of internal APIs, `New-WinRMSession` and the WinRS cmdlets like `Invoke-WinRSCommand` do not need this cmdlet, do not patch anything and are not affected by it.

## EXAMPLES

### Example 1: Enable PSWSMan can create a connection

```powershell
PS C:\> Enable-PSWSMan -Force
PS C:\> Invoke-Command -ComputerName Server01 -ScriptBlock { "hello world!" }
```

Enables PSWSMan in the PowerShell process so that any subsequent WSMan operations will use this module rather than the transport PowerShell provides.
If `-Force` is not specified, the cmdlet will prompt for confirmation that it should be enabled.

## PARAMETERS

### -Force

Do not prompt for confirmation before enabling PSWSMan injection.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

Once enabled the hooks cannot be undone.
The whole PowerShell process will need to be restarted to revert back to the build WSMan code.

The patching may not work on a .NET or PowerShell release newer than the ones this version of PSWSMan was tested with, use `New-WinRMSession` until an updated PSWSMan is available.

## RELATED LINKS

- [about_PSWSMan](./about_PSWSMan.md)
- [New-WinRMSession](./New-WinRMSession.md)
