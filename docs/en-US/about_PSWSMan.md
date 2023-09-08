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

+ macOS - Intel only

Support for macOS ARM is limited by [this issue on MonoMod](https://github.com/MonoMod/MonoMod/issues/90).

A list of the cmdlets in this module can be found at [PSWSMan](./PSWSMan.md).

The [about_PSWSManAuthentication](./about_PSWSManAuthentication.md) docs go into futher detail how authentication works with WinRM.

To debug some of the hook actions use [Trace-Command](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/trace-command?view=powershell-7.3) like so:

```powershell
Trace-Command -PSHost -Name ClientTransport -Expression {
    Invoke-Command -ComputerName server { 'test' }
}
```
