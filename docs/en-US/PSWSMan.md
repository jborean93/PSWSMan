---
Module Name: PSWSMan
Module Guid: 92ec96bf-3ff4-41b2-8694-cd3ee636d3fd
Download Help Link: 
Help Version: 1.0.0.0
Locale: en-US
---

# PSWSMan Module
## Description
PowerShell module that adds support of WSMan on Linux, macOS, and Windows.

## PSWSMan Cmdlets
### [ConvertTo-WinRSCommandLine](ConvertTo-WinRSCommandLine.md)
Builds a command line for `Invoke-WinRSCommand` that runs an executable with an exact list of arguments.

### [Enable-PSWSMan](Enable-PSWSMan.md)
Enables PSWSMan as the transport method for WSMan based transports in PowerShell.

### [Get-PSWSManAuth](Get-PSWSManAuth.md)
Gets the authentication settings used by PSWSMan.

### [Get-WinRSShell](Get-WinRSShell.md)
Gets the WinRS shells created by New-WinRSShell in the current runspace.

### [Invoke-WinRSCommand](Invoke-WinRSCommand.md)
Runs a process on a remote host through a WinRS shell and outputs its stdout and stderr.

### [New-RemoteCertificateValidationCallback](New-RemoteCertificateValidationCallback.md)
Create a scriptblock delegate to validate certificates.

### [New-WinRMSession](New-WinRMSession.md)
Creates a PowerShell session over PSWSMan's WinRM client without hooking PowerShell.

### [New-WinRMSessionOption](New-WinRMSessionOption.md)
Creates the connection options for PSWSMan and the builtin remoting cmdlets.

### [New-WinRSShell](New-WinRSShell.md)
Creates a WinRS shell on a remote host that several WinRS commands can run in.

### [Receive-WinRSFile](Receive-WinRSFile.md)
Copies files from a remote host to the local host over a WinRS connection.

### [Remove-WinRSShell](Remove-WinRSShell.md)
Deletes WinRS shells created by New-WinRSShell.

### [Send-WinRSFile](Send-WinRSFile.md)
Copies local files to a remote host over a WinRS connection.

### [Set-PSWSManAuth](Set-PSWSManAuth.md)
Sets the authentication settings used by PSWSMan.

