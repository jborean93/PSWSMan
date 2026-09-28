---
external help file: PSWSMan.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/Get-WinRSShell.md
schema: 2.0.0
---

# Get-WinRSShell

## SYNOPSIS
Gets the WinRS shells created by New-WinRSShell in the current runspace.

## SYNTAX

```
Get-WinRSShell [[-ComputerName] <String[]>] [-ShellId <Guid[]>] [-ProgressAction <ActionPreference>]
 [<CommonParameters>]
```

## DESCRIPTION
The `Get-WinRSShell` cmdlet gets the WinRS shells that `New-WinRSShell` created in the current runspace and that have not been removed, oldest first.
Use it to find a shell again when the variable holding it was lost, or to remove every shell at once.

A shell is listed from when `New-WinRSShell` creates it until it is removed with `Remove-WinRSShell` or the runspace closes.
Shells created in another runspace, like a `ForEach-Object -Parallel` script block or a PowerShell job, are only listed in that runspace.

The list is kept on the client and nothing is sent to the remote host.
A shell the remote host has deleted on its own, for example after its idle timeout, is still listed with the `State` `Opened` until it is removed.

## EXAMPLES

### Example 1: List the shells
```powershell
PS C:\> $null = New-WinRSShell Server01
PS C:\> $null = New-WinRSShell Server02
PS C:\> Get-WinRSShell

ShellId                              ComputerName State  ConsoleEncoding
-------                              ------------ -----  ---------------
3f2a1e8c-5b0d-4c6e-9a47-1d2e3f4a5b6c Server01     Opened utf-8
8c7b6a59-4d3e-4f21-b0a9-8c7d6e5f4a3b Server02     Opened utf-8
```

Lists the two shells created in this runspace.

### Example 2: Run a command in a shell created earlier
```powershell
PS C:\> $shell = Get-WinRSShell Server01 | Select-Object -First 1
PS C:\> Invoke-WinRSCommand -Shell $shell 'hostname'
```

Gets the oldest shell to `Server01` and runs a command in it.

### Example 3: Remove every shell
```powershell
PS C:\> Get-WinRSShell | Remove-WinRSShell
```

Removes all the shells created in this runspace.

## PARAMETERS

### -ComputerName
Only gets the shells whose `ComputerName` matches one of these names.
Wildcards are supported and the match is case insensitive.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: Cn

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: True
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

### -ShellId
Only gets the shells with one of these shell ids.

```yaml
Type: Guid[]
Parameter Sets: (All)
Aliases:

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
## OUTPUTS

### PSWSMan.WinRSRemoteShell
The shells created in the current runspace that have not been removed.

## NOTES

## RELATED LINKS

[New-WinRSShell](./New-WinRSShell.md)

[Remove-WinRSShell](./Remove-WinRSShell.md)
