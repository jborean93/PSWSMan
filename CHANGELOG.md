# Changelog for PSWSMan

## v3.0.0 - TBD

This is a major change in the `PSWSMan` module away from shipping the `libomi` and `libpsrpclient` C library with custom changes to a pure dotnet WSMan client.
It is designed to hook the PowerShell WSMan libraries with its own mechanisms to avoid needing the C library altogether.
This opens up the possibility of introducing more features in the WSMan client that wasn't possible before like CredSSP authentication, better TLS validation, better error messages, etc.

As it is no longer required to replace the C libraries in the PowerShell directory, the module can be installed as any user and enabled by running `Enable-PSWSMan -Force` in the PowerShell process.
This will hook the WSMan APIs inside PowerShell to use the ones provided by this function.
Once enabled, simply use the same pwsh cmdlets like `Invoke-Command`, `Enter-PSSession`, `New-PSSession`, etc like normal.

### Breaking Changes

As this is a major shift away from the old PSWSMan module based on a fork of the `omi` C library, the following cmdlets have been removed:

+ `Install-WSMan` - no longer needed
+ `Get-WSManVersion` - no longer needed
+ `Disable-WSManCertVerification` and `Enable-WSManCertVerification`
  + Certificate verification can be enabled/disabled using the `New-PSSessionOption` or [New-PSWSManSessionOption](./docs/en-US/New-PSWSManSessionOption.md) cmdlets
+ `Register-TrustedCertificate`
  + The new PSWSMan uses dotnet for TLS operations so relies on the behaviour of how it interacts with the system TLS library rather than directly linking to OpenSSL

The following platforms are current not supported

+ Linux on musl based libc like Alpine
  + While this may work it is currently experimental
+ Linux on aarch64
  + The underlying MonoMod.RuntimeDetour library currently does not support aarch64
+ macOS on aarch64/arm
  + The underlying MonoMod.RuntimeDetour library currently does not support aarch64
  + Running pwsh under Rosetta 2 should work though

If you still need anything that was removed then it is recommended to pin your dependencies to `2.3.1` to avoid pulling in any new incompatible changes.

### Changes

The following features have been introduced in this version

+ It is no longer required to run as root to install the libraries
+ It is no longer required to install the library after every PowerShell upgrade
+ Improved authentication support
  + CredSSP is now an authentication option
  + NTLM on macOS now works
  + Optional support for the [Devolutions/sspi-rs](https://github.com/Devolutions/sspi-rs) auth provider
  + Certificate auth works with TLS 1.3 (pwsh 7.3 or newer)
+ Improved TLS support
  + Integrated into dotnet for a more consistent validation support
  + Support for TLS 1.3
  + Custom certificate validation scriptblocks
  + This is exposed by `New-PSWSManSessionOption -TlsOption ...`
+ It is possible to use this with Windows to bypass the builtin WSMan client and its rules
+ Encryption can be disabled for debugging outside Windows with `New-PSWSManSessionOption -NoEncryption`
+ Kerberos delegation can be explicitly requested with `New-PSWSManSessionOption -RequestKerberosDelegate`
+ A custom SPN can be used for Kerberos auth with `New-PSWSManSessionOption -SPNHostName ... -SPNService ...`

The following cmdlets have been added:

+ [Enable-PSWSMan](./docs/en-US/Enable-PSWSMan.md) - enables this library
+ [Get-PSWSManAuthProvider](./docs/en-US/Get-PSWSManAuthProvider.md) - gets the current default authentication provider
+ [New-PSWSManCertValidationCallback](./docs/en-US/New-PSWSManCertValidationCallback.md) - creates a TLS cert validation callback from the scriptblock provided
+ [New-PSWSManSessionOption](./docs/en-US/New-PSWSManSessionOption.md) - exposes more session options that can be applied to `-SessionOption` on the builtin cmdlets
+ [Set-PSWSManAuthProvider](./docs/en-US/Set-PSWSManAuthProvider.md) - changes the default authentication provider

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
