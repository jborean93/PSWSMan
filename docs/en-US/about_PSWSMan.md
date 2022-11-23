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

Due to missing features in a downstream package, support for PowerShell 7.3 is limited.
It may work on Linux or macOS but Windows most likely will not.
Follow [the issue on Harmony](https://github.com/pardeike/Harmony/issues/504) for more information.

Support for macOS ARM is limited by [this issue on Harmony](https://github.com/pardeike/Harmony/issues/424).

A list of the cmdlets in this module can be found at [PSWSMan](./PSWSMan.md).

The [about_PSWSManAuthentication](./about_PSWSManAuthentication.md) docs go into futher detail how authentication works with WinRM.
