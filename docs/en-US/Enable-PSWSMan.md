---
external help file: PSWSMan.Module.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/Enable-PSWSMan.md
schema: 2.0.0
---

# Enable-PSWSMan

## SYNOPSIS
Enables PSWSMan as the transport method for WSMan based transports in PowerShell.

## SYNTAX

```
Enable-PSWSMan [-Force] [<CommonParameters>]
```

## DESCRIPTION
The `Enable-PSWSMan` cmdlet injects itself into the PowerShell engine to force it to use the WSMan client it provides for WSMan transports.
It is used to remove the use of the C omi library that PowerShell ships with which has limited features and support.

This operation is global to the process and is not reversible, once it has been enabled it cannot be disabled without restarting the process.

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
Type: SwitchParameter
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
This function does not accept input from the pipeline.

## OUTPUTS

### None
This function does not output to the pipeline.

## NOTES
Once enabled the hooks cannot be undone.
The whole PowerShell process will need to be restarted to revert back to the build WSMan code.

## RELATED LINKS
