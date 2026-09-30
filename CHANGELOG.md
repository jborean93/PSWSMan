# Changelog for PSWSMan

## v3.0.0 - TBD

This is a major change in the `PSWSMan` module away from shipping a custom `libmi` and `libpsrpclient` C library to a pure .NET WSMan client.
It is designed to hook the PowerShell WSMan client classes with its own mechanisms to avoid needing the C library altogether.
This opens up the possibility of introducing more features in the WSMan client that wasn't possible before like CredSSP authentication, better TLS validation, better error messages, etc.

As it is no longer required to replace the C libraries in the PowerShell directory, the module can be installed as any user and enabled by running `Enable-PSWSMan -Force` in the PowerShell process.
This will hook the WSMan APIs inside PowerShell to use the ones provided by this function.
Once enabled, simply use the same pwsh cmdlets like `Invoke-Command`, `Enter-PSSession`, `New-PSSession`, etc like normal.

### Breaking Changes

As this is a major shift away from the old PSWSMan module based on a fork of the `omi` C library, the following cmdlets have been removed:

+ `Install-WSMan` - no longer needed
+ `Get-WSManVersion` - no longer needed
+ `Disable-WSManCertVerification` and `Enable-WSManCertVerification`
  + Certificate verification can be enabled/disabled using the switch parameters `-SkipCACheck` and `-SkipCNCheck` on the `New-PSSessionOption` or [New-WinRMSessionOption](./docs/en-US/PSWSMan/New-WinRMSessionOption.md) cmdlets
+ `Register-TrustedCertificate`
  + The new PSWSMan uses .NET for TLS operations so relies on the behaviour of how .NET interacts with the system TLS library rather than directly linking to OpenSSL

If you still need anything that was removed then it is recommended to pin your dependencies to `2.3.1` to avoid pulling in any new incompatible changes.

### Changes

The following features have been introduced in this version

+ It is no longer required to run as root to install the libraries
+ It is no longer required to install the library after every PowerShell upgrade
+ Improved authentication support
  + CredSSP is now an authentication option
  + NTLM on macOS now works
  + Optional support for the [Devolutions/sspi-rs](https://github.com/Devolutions/sspi-rs) auth provider
  + Certificate auth works with TLS 1.3
+ Improved TLS support
  + Integrated into .NET for a more consistent validation support
  + Support for TLS 1.3
  + Custom certificate validation scriptblocks
  + This is exposed by `New-WinRMSessionOption -TlsOption ...`
+ It is possible to use this with Windows to bypass the builtin WSMan client and its rules
+ Encryption can be disabled for debugging outside Windows with `New-WinRMSessionOption -NoEncryption`
+ Kerberos delegation can be explicitly requested with `New-WinRMSessionOption -RequestKerberosDelegate`
+ A custom SPN can be used for Kerberos auth with `New-WinRMSessionOption -SPNHostName ... -SPNService ...`
+ CIM instances returned from a remote session are now returned as deserialized property bags (`Deserialized.Microsoft.Management.Infrastructure.CimInstance#...`) on Linux and macOS
  + PowerShell rebuilds a live `CimInstance` on the client through the `libmi` library from `omi`, which the old `omi` based module provided
  + `Enable-PSWSMan` now hooks the deserializer on non-Windows platforms so these objects no longer depend on `libmi` at all, they keep the same properties and formatting
  + They are no longer a `CimInstance` so `CimClass`, `CimSystemProperties` and `Invoke-CimMethod -InputObject` are not available on the client, and arrays are returned as `ArrayList`
  + Windows is unaffected as the MI library is part of the OS
+ `Enter-PSSession` can now be stopped with `Ctrl+C` while it is connecting, previously it ignored the stop until the connection failed
+ `Clear-Host` (`clear`/`cls`) in a remote session to a Windows host now clears the screen on non-Windows clients, previously it only moved the cursor to the top and failed with `The method or operation is not implemented`
  + This also applies to the sessions of `New-WinRMSession` and `Enter-WinRMSession`, without `Enable-PSWSMan`

The following cmdlets have been added:

+ Module setup and settings
  + [Enable-PSWSMan](./docs/en-US/PSWSMan/Enable-PSWSMan.md) - hooks the builtin remoting cmdlets like `New-PSSession` and `Invoke-Command` so they use this module's WSMan client
  + [Get-PSWSManAuth](./docs/en-US/PSWSMan/Get-PSWSManAuth.md) - gets the current authentication settings
  + [Set-PSWSManAuth](./docs/en-US/PSWSMan/Set-PSWSManAuth.md) - changes the default authentication provider and GSSAPI library
+ Custom WinRM transport sessions and options, these do not need `Enable-PSWSMan`
  + [New-WinRMSession](./docs/en-US/PSWSMan/New-WinRMSession.md) - creates PSSessions with PSWSMan's WinRM client through PowerShell's public custom remoting transport API
    + The sessions work with `Invoke-Command -Session`, `Enter-PSSession -Session` and the other builtin session cmdlets
    + Several hosts can be given or piped in and are opened in parallel up to `-ThrottleLimit`
  + [Enter-WinRMSession](./docs/en-US/PSWSMan/Enter-WinRMSession.md) - starts an interactive session like `Enter-PSSession -ComputerName` with PSWSMan's WinRM client, the session is closed when it is left
  + [Invoke-WinRMCommand](./docs/en-US/PSWSMan/Invoke-WinRMCommand.md) - runs a command on one or more hosts or sessions like `Invoke-Command` with PSWSMan's WinRM client, alias `iwcm`
    + `-ArgumentList` also takes a hashtable that is bound to the remote command by parameter name, like splatting
  + [New-WinRMSessionOption](./docs/en-US/PSWSMan/New-WinRMSessionOption.md) - creates the connection options for every way of connecting
    + Converts to a `PSSessionOption` for `-SessionOption` and `$PSSessionOption` of the builtin cmdlets like `New-PSSession` and `Invoke-Command`
    + Taken as is by `New-WinRMSession` and the WinRS cmdlets, whose `-SessionOption` also accepts a hashtable of the same options or a `PSSessionOption`, which is an error if it sets an option PSWSMan does not support
    + `-TracePath` writes the connection trace of `New-WinRMSession` and the WinRS cmdlets to a file
+ WinRS cmdlets, these run commands through `cmd.exe` without a PowerShell session on the remote host and do not need `Enable-PSWSMan`
  + [Invoke-WinRSCommand](./docs/en-US/PSWSMan/Invoke-WinRSCommand.md) - runs a command line on a remote host with a WinRS shell, pipeline input is written to its stdin, alias `irscm`
  + [ConvertTo-WinRSCommandLine](./docs/en-US/PSWSMan/ConvertTo-WinRSCommandLine.md) - builds an `Invoke-WinRSCommand` command line from an executable and a list of arguments, escaping them for `cmd.exe` so the process receives them exactly as given
  + [Send-WinRSFile](./docs/en-US/PSWSMan/Send-WinRSFile.md) and [Receive-WinRSFile](./docs/en-US/PSWSMan/Receive-WinRSFile.md) - copy files to and from a remote host without a PowerShell remoting session or file share, each copy is verified with a SHA256 hash before it replaces the destination
  + [New-WinRSShell](./docs/en-US/PSWSMan/New-WinRSShell.md), [Get-WinRSShell](./docs/en-US/PSWSMan/Get-WinRSShell.md) and [Remove-WinRSShell](./docs/en-US/PSWSMan/Remove-WinRSShell.md) - create, list and delete a WinRS shell that `Invoke-WinRSCommand`, `Send-WinRSFile` and `Receive-WinRSFile` can run their commands in with `-Shell`, rather than connecting and creating a shell on every call
+ Helpers
  + [New-RemoteCertificateValidationCallback](./docs/en-US/PSWSMan/New-RemoteCertificateValidationCallback.md) - creates a thread safe `RemoteCertificateValidationCallback` that validates a server certificate with a scriptblock, for the `-TlsOption` and `-CredSSPTlsOption` of `New-WinRMSessionOption`

## 2.3.1 - 2022-11-28

+ Fix Kerberos auth with username but no password set
+ Fix `Install-WSMan` on PowerShell 7.3.x for macOS

## 2.3.0 - 2021-11-12

+ Added universal build for macOS to work with both x86_64 and arm64 processes
+ Fixed up logic used to determine what OpenSSL library is used on macOS
+ Changed `PSWSMan` to be a hybrid module for more robust loading and unloading behaviour in the future

## 2.2.1 - 2021-07-14

+ Fixed up logic used to determine what library to use on unknown Linux distributions
  + https://github.com/jborean93/omi/issues/30
  + https://github.com/jborean93/omi/issues/31

## 2.2.0 - 2021-04-07

+ Created universal builds to be used across the various nix distributions
  + `glibc` is based on CentOS 7 and is designed for most GNU/Linux distributions, EL/Debian/Arch/etc
  + `musl` is based on Alpine 3 and is designed for busybox/Linux distributions, Alpine
  + `macOS` is based on macOS
  + These universal builds is designed to reduce the number of `libmi` builds being distributed and automatically support future distribution releases as they are made
+ Deprecated the `-Distribution` parameter of `Install-WSMan` as it no longer does anything
+ Removed support for Debian 8 and Fedora 31 due to the age of the distribution
+ Added initial support for OpenSSL 3.x for glibc, musl, and macOS based distributions
+ Added support for using OpenSSL installed from `port` if `brew` is not used on macOS
  + One of them must be installed but you are no longer limited to just `brew`
+ Use `@loader_path` on macOS instead of `@executable_path` for loading `libmi` to support relative paths from the library itself rather than `pwsh`
+ `Register-TrustedCertificate` will now create a file with a determinable name to avoid creating duplicate entries

## 2.1.0 - 2020-11-24

+ Added the following distributions
  + `fedora33`
  + `ubuntu20.04`
+ Make a backup of the original library files in the PowerShell dir before installing the forked copies
+ Merge in upstream changes to stay in sync
  + Upstream changes were based on server side configuration updates and logging and not something that affects PowerShell's WSMan client code

## 2.0.0 - 2020-10-17

### Breaking Changes

+ GitHub release artifacts are now a `.tar.gz` for each distribution containing `libmi` and `libpsrp`
+ Removed the script `tools/Get-OmiVersion.ps1` in favour of `Get-WSManVersion` that is included in the new `PSWSMan` module

### Changes

+ Created `PSWSMan` which is a PowerShell module uploaded to the PowerShell Gallery that can install and manage the OMI libraries for you
+ Build `libpsrpclient` as well and add it to the release artifacts
+ Added Alpine 3 to the build matrix
+ Added support for reading `New-PSSessionOption -SkipCACheck -SkipCNCheck` from PowerShell instead of relying on the env vars
  + Requires PowerShell v7.2.0
  + v7.2.0 and later do not need to have `-SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck)` set
  + Those options can now also control cert verification behaviour per session
  + Older versions must still set those session options and use the env vars to skip cert verification

## 1.2.1 - 2020-09-26

+ Fix build for macOS to link against OpenSSL 1.1 and not 1.0.2

## 1.2.0 - 2020-09-25

+ Added support for channel binding tokens to work with `Auth/CbtHardeningLevel = Strict`
+ Improved error messages displayed when dealing with OpenSSL errors
+ Turned on HTTPS certificate validation by default ignoring whatever is set from PowerShell
  + You still need to specify `-SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck)` when creating the session in PowerShell
  + These session options are ignored in this OMI library, to disable cert verification here, set the env vars `OMI_SKIP_CA_CHECK=1` and `OMI_SKIP_CN_CHECK=1`
  + A future version may respect the `-SessionOption` skip checks in the future but until that data is actually sent to the library we opt for a safer default by always checking unless our env vars are set

## 1.1.0 - 2020-09-01

+ Added Archlinux as a known distribution

## 1.0.1 - 2020-08-20

+ Increased password length limit to allow connecting with JWT tokens to Exchange Online that routinely exceed 1KiB in size.
+ Take back point about NTLM working on macOS, while it can work when you use HTTPS, it will fail with the message encryption due to a flaw in macOS NTLM through SPNEGO mechanism

## 1.0.0 - 2020-08-19

Initial release.
