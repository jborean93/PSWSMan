# PSWSMan
## about_PSWSMan

# SHORT DESCRIPTION
The PSWSMan module is a cross platform module for using WSMan/WinRM connections on non-Windows platforms.

# LONG DESCRIPTION
This module is designed to improve the availability and features available for WinRM based PSSessions, especially on platforms outside of Windows.
It implements the WSMan client in a pure C# codebase that significantly makes it easier to install and add new features.
It has been tested to work on the following platforms:

+ Linux

+ Windows

+ macOS

The module can be used in three ways, which all use the same WinRM client and authentication:

+ `Enable-PSWSMan` hooks PowerShell so the builtin remoting cmdlets, like `New-PSSession`, `Invoke-Command` and `Enter-PSSession`, use this client for WSMan connections. Their `-SessionOption` and `$PSSessionOption` take the output of `New-WinRMSessionOption`, which adds the PSWSMan specific options to the builtin ones. The hooks patch internal PowerShell methods at runtime so a new .NET release, including pre-releases, or a new PowerShell version can break them until PSWSMan is updated. Only this way uses the patching, the other two do not patch anything and are not affected.

+ `New-WinRMSession` creates a PSSession through PowerShell's public custom remoting transport API. It needs no hooks, the session works with the builtin cmdlets that take a `-Session`, and several hosts can be connected to in parallel. `Invoke-WinRMCommand` runs a command on hosts or in those sessions like `Invoke-Command` and `Enter-WinRMSession` is its interactive counterpart to `Enter-PSSession -ComputerName`. Its options come from `New-WinRMSessionOption` too, or a hashtable of the same options.

+ The WinRS cmdlets, like `Invoke-WinRSCommand` and `Send-WinRSFile`, run commands through `cmd.exe` and copy files without starting PowerShell on the remote host. They need no hooks either and take the same options as `New-WinRMSession`.

A list of the cmdlets in this module can be found at [PSWSMan](./PSWSMan.md).

The [about_PSWSManAuthentication](./about_PSWSManAuthentication.md) docs go into futher detail how authentication works with WinRM.

# TROUBLESHOOTING
How to see what the WinRM client is doing depends on how it is used.

For the builtin remoting cmdlets after `Enable-PSWSMan`, like `New-PSSession` and `Invoke-Command`, use [Trace-Command](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/trace-command) with the `ClientTransport` trace source:

```powershell
Trace-Command -PSHost -Name ClientTransport -Expression {
    Invoke-Command -ComputerName server { 'test' }
}
```

The `ClientTransport` trace source is internal to PowerShell and only the patched builtin cmdlets write to it.
`New-WinRMSession` and the WinRS cmdlets do not patch PowerShell, set `TracePath` in their session options to write their messages to a file instead.

```powershell
$so = New-WinRMSessionOption -TracePath ./winrm-trace.log
$session = New-WinRMSession -ComputerName server -SessionOption $so

Invoke-WinRSCommand -ComputerName server -Command hostname -SessionOption @{ TracePath = './winrs-trace.log' }
```

The `TracePath` option is ignored by the builtin remoting cmdlets.

Each line of the file starts with a timestamp, including the UTC offset, and the id of the thread that wrote it.
For `New-WinRMSession` the file also has every PowerShell remoting (OutOfProc) packet exchanged with PowerShell in full, one per line with the prefix `PSWSMan OutOfProc Packet [<runspace pool id>] Sent:` or `Received:`.
The packets are large, filter them out to see only the connection activity or keep only them to follow the remoting protocol:

```powershell
# Only the connection and WSMan activity
Select-String -Path ./winrm-trace.log -Pattern 'PSWSMan OutOfProc Packet' -NotMatch

# Only the packets PowerShell sent
Select-String -Path ./winrm-trace.log -Pattern 'PSWSMan OutOfProc Packet \[[^\]]+\] Sent:'
```

The packets contain the commands and output of the session, treat the trace as sensitive.
