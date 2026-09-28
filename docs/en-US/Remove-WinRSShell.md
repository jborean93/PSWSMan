---
external help file: PSWSMan.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/Remove-WinRSShell.md
schema: 2.0.0
---

# Remove-WinRSShell

## SYNOPSIS
Deletes WinRS shells created by New-WinRSShell.

## SYNTAX

```
Remove-WinRSShell [-Shell] <WinRSRemoteShell[]> [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

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

### -Shell
The shells to remove.

```yaml
Type: WinRSRemoteShell[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue)
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

### PSWSMan.WinRSRemoteShell[]
The shells to remove.

## OUTPUTS

### None
## NOTES

## RELATED LINKS

[New-WinRSShell](./New-WinRSShell.md)

[Get-WinRSShell](./Get-WinRSShell.md)
