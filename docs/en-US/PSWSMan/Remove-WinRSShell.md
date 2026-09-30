---
document type: cmdlet
external help file: PSWSMan.dll-Help.xml
HelpUri: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/PSWSMan/Remove-WinRSShell.md
Module Name: PSWSMan
ms.date: ''
PlatyPS schema version: 2024-05-01
---

# Remove-WinRSShell

## SYNOPSIS

Deletes WinRS shells created by New-WinRSShell.

## SYNTAX

### __AllParameterSets

```
Remove-WinRSShell [-Shell] <WinRSRemoteShell[]> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## ALIASES

## DESCRIPTION

The `Remove-WinRSShell` cmdlet deletes WinRS shells created by `New-WinRSShell` on the remote host and closes their connections.
Any process still running in a shell is terminated by the remote host when the shell is deleted.

The `State` of a removed shell is `Closed` and it can no longer be used with the WinRS cmdlets.
Removing a shell that has already been removed does nothing.
A shell the remote host has already deleted, for example after its idle timeout, is still closed locally and the failure to delete it is written as a non-terminating error.

## EXAMPLES

### Example 1: Remove a shell

```powershell
PS C:\> $shell = New-WinRSShell Server01
PS C:\> Invoke-WinRSCommand -Shell $shell 'hostname'
PS C:\> Remove-WinRSShell $shell
```

Creates a shell, runs a command in it and removes it.

### Example 2: Remove several shells from the pipeline

```powershell
PS C:\> $shells = 'Server01', 'Server02' | ForEach-Object { New-WinRSShell $_ }
PS C:\> $shells | Remove-WinRSShell
```

Removes every shell piped to the cmdlet.

## PARAMETERS

### -Confirm

Prompts you for confirmation before running the cmdlet.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: None
SupportsWildcards: false
Aliases:
- cf
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

### -Shell

The shells to remove.

```yaml
Type: PSWSMan.WinRSRemoteShell[]
DefaultValue: None
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 0
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -WhatIf

Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: None
SupportsWildcards: false
Aliases:
- wi
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

### PSWSMan.WinRSRemoteShell[]

The shells to remove.

## OUTPUTS

## NOTES

## RELATED LINKS

- [New-WinRSShell](./New-WinRSShell.md)
- [Get-WinRSShell](./Get-WinRSShell.md)
