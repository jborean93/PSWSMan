# PSWSMan

[![Test workflow](https://github.com/jborean93/PSWSMan/workflows/Test%20PSWSMan/badge.svg)](https://github.com/jborean93/PSWSMan/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/PSWSMan/branch/main/graph/badge.svg?token=b51IOhpLfQ)](https://codecov.io/gh/jborean93/PSWSMan)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/PSWSMan.svg)](https://www.powershellgallery.com/packages/PSWSMan)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/PSWSMan/blob/main/LICENSE)

> [!NOTE]
> This repository is for PSWSMan 3.0.0 and newer.
> PSWSMan before 3.0.0 is built from [jborean93/omi](https://github.com/jborean93/omi), which is based on a completely different stack and is no longer maintained.
> See the v3.0.0 notes in the [changelog](CHANGELOG.md) for the changes between 2.x and 3.0.0+.

See [about_PSWSMan](docs/en-US/PSWSMan/about_PSWSMan.md) for more details.

## Documentation

Documentation for this module and details on the cmdlets included can be found [here](docs/en-US/PSWSMan/PSWSMan.md).
This is currently an unreleased project and is meant to replace [my omi fork](https://github.com/jborean93/omi) as the way PowerShell uses WSMan as a client.

## Requirements

These cmdlets have the following requirements

* PowerShell v7.4 or newer

## Installing

The easiest way to install this module is through
[PowerShellGet](https://docs.microsoft.com/en-us/powershell/gallery/overview).

You can install this module by running;

```powershell
# Install for only the current user
Install-PSResource -Name PSWSMan -Scope CurrentUser

# Install for all users
Install-PSResource -Name PSWSMan -Scope AllUsers
```

## Ways to use PSWSMan

PSWSMan talks to a WinRM (WSMan) host in three ways.
All of them use the same WinRM client, authentication providers and TLS handling, they differ in what runs on the remote host and whether PowerShell itself is modified.

| Path | Cmdlets | Hooks PowerShell | Remote side |
| --- | --- | --- | --- |
| [Builtin remoting with Enable-PSWSMan](#powershell-remoting-with-enable-pswsman) | `Invoke-Command`, `Enter-PSSession`, `New-PSSession`, ... | Yes, `Enable-PSWSMan -Force` | PowerShell session |
| [WinRM sessions](#winrm-sessions) | `Invoke-WinRMCommand`, `Enter-WinRMSession`, `New-WinRMSession` (its PSSession also works with builtin cmdlets like `Invoke-Command -Session`) | No | PowerShell session |
| [WinRS cmdlets](#winrs-cmdlets) | `Invoke-WinRSCommand`, `Send-WinRSFile`, ... | No | `cmd.exe` commands, no PowerShell |

Use `Enable-PSWSMan` to keep using the builtin cmdlets and scripts unchanged, `Invoke-WinRMCommand`, `Enter-WinRMSession` and `New-WinRMSession` to run PowerShell remotely without modifying the PowerShell process, and the WinRS cmdlets to run native commands or copy files where no PowerShell session is needed.
`Enable-PSWSMan` patches PowerShell at runtime, which can stop working on a new .NET or PowerShell release until PSWSMan is updated, see [the warning below](#powershell-remoting-with-enable-pswsman).
Only this path patches PowerShell, the other two do not and are not affected by it.

## PowerShell Remoting with Enable-PSWSMan

PSWSMan replaces the WSMan client that PowerShell uses for its builtin remoting cmdlets like `New-PSSession`, `Invoke-Command`, and `Enter-PSSession`.
Run `Enable-PSWSMan -Force` once in the PowerShell process to hook the engine, any WSMan PSSession created after that uses this module's client instead of the one PowerShell ships with.

> [!WARNING]
> `Enable-PSWSMan` works by patching internal PowerShell methods at runtime, it redirects them to this module's code by rewriting them in memory with [MonoMod](https://github.com/MonoMod/MonoMod).
> This depends on implementation details of both PowerShell and the .NET runtime that are not a supported API.
> A new .NET release, including previews and other pre-releases, or a new PowerShell version can change those details so that `Enable-PSWSMan` fails or the builtin remoting cmdlets misbehave.
> PSWSMan is updated for new releases once such a break is known, but there can be a gap before a fixed version is available.
> Only the builtin remoting cmdlets depend on this patching of internal APIs, [New-WinRMSession](#winrm-sessions) and the [WinRS cmdlets](#winrs-cmdlets) do not patch anything and keep working in the meantime.

```powershell
Import-Module -Name PSWSMan
Enable-PSWSMan -Force

$cred = Get-Credential
Invoke-Command -ComputerName Server01 -Credential $cred -ScriptBlock { $env:COMPUTERNAME }

$session = New-PSSession -ComputerName Server01 -Credential $cred -UseSSL
Enter-PSSession -Session $session
```

The hooks apply to the whole process and cannot be undone, restart PowerShell to go back to the builtin client.
Add `Enable-PSWSMan -Force` to your PowerShell profile to have it enabled in every session.

The builtin cmdlets keep their own parameters, `-ComputerName`, `-Credential`, `-Authentication`, `-UseSSL`, and so on, and work as they normally do.
Use [New-WinRMSessionOption](docs/en-US/PSWSMan/New-WinRMSessionOption.md) in place of `New-PSSessionOption`, for `-SessionOption` or `$PSSessionOption`, to set the options that are specific to PSWSMan, like choosing the authentication provider, the Kerberos SPN, CredSSP settings, custom TLS options, or a client certificate that is not in a certificate store.

```powershell
$so = New-WinRMSessionOption -AuthMethod Kerberos -RequestKerberosDelegate
Invoke-Command -ComputerName Server01 -SessionOption $so -ScriptBlock { whoami }

$so = New-WinRMSessionOption -SkipCACheck -SkipCNCheck
Enter-PSSession -ComputerName 192.168.1.2 -UseSSL -Credential $cred -SessionOption $so
```

See [about_PSWSManAuthentication](docs/en-US/PSWSMan/about_PSWSManAuthentication.md) for details on the authentication methods and how to set them up on each platform.

## WinRM Sessions

PSWSMan has its own PowerShell remoting cmdlets that use its client through the public custom remoting transport API that PowerShell 7.3 added.
Nothing in PowerShell is hooked, so `Enable-PSWSMan` is not needed and the builtin WSMan client is left as is for every other session.

| Cmdlet | Builtin equivalent |
| --- | --- |
| [Invoke-WinRMCommand](docs/en-US/PSWSMan/Invoke-WinRMCommand.md) | `Invoke-Command`, its `-ArgumentList` also takes a hashtable of named parameters |
| [Enter-WinRMSession](docs/en-US/PSWSMan/Enter-WinRMSession.md) | `Enter-PSSession` |
| [New-WinRMSession](docs/en-US/PSWSMan/New-WinRMSession.md) | `New-PSSession`, the session works with the builtin cmdlets that take a `-Session`, like `Invoke-Command`, `Enter-PSSession`, `Import-PSSession`, `Copy-Item -ToSession`, and `Remove-PSSession` |

```powershell
Import-Module -Name PSWSMan
$cred = Get-Credential

# Runs on each host in parallel, a host that cannot be reached is written as an error
Invoke-WinRMCommand -ComputerName Server01, Server02 -Credential $cred -ScriptBlock { $env:COMPUTERNAME }

# A hashtable given to -ArgumentList is bound by parameter name like splatting
Invoke-WinRMCommand -ComputerName Server01 -Credential $cred -ScriptBlock {
    param ([string]$Name)
    Get-Service -Name $Name
} -ArgumentList @{ Name = 'WinRM' }

# Interactive session with a Kerberos ticket that can be delegated, closed again on exit
$so = New-WinRMSessionOption -AuthMethod Kerberos -RequestKerberosDelegate
Enter-WinRMSession -ComputerName Server01 -UseSSL -SessionOption $so

# A session managed by hand is reused across commands and works with the builtin -Session cmdlets
$session = New-WinRMSession -ComputerName Server01 -Credential $cred
Invoke-WinRMCommand -Session $session -ScriptBlock { $processes = Get-Process }
Invoke-WinRMCommand -Session $session -ScriptBlock { $processes.Count }
Copy-Item -Path ./setup.ps1 -Destination C:\Temp -ToSession $session
Remove-PSSession -Session $session
```

The connection parameters mirror the builtin cmdlets, including several hosts at once with `-ThrottleLimit`, and the options come from [New-WinRMSessionOption](docs/en-US/PSWSMan/New-WinRMSessionOption.md).
Unlike `New-PSSessionOption` it only has the options PSWSMan supports, and `-SessionOption` also takes a hashtable of the same names, like `-SessionOption @{ OperationTimeout = 30000; AuthProvider = 'Devolutions' }`.
A `PSSessionOption` from `New-PSSessionOption` is accepted too, but setting an option PSWSMan does not support in it, like `NoCompression` or a proxy, is an error rather than silently ignored.
The same `New-WinRMSessionOption` object works for all three paths, it converts to a `PSSessionOption` for the builtin cmdlets.
On every path an explicit `-Authentication` takes precedence over the `AuthMethod` of the options.

These sessions cannot be disconnected and reconnected with `Disconnect-PSSession` and `Connect-PSSession`.
To troubleshoot a connection set `-TracePath` on `New-WinRMSessionOption`, `Trace-Command` only works for the builtin cmdlets, see [about_PSWSMan](docs/en-US/PSWSMan/about_PSWSMan.md#troubleshooting).

## WinRS Cmdlets

PSWSMan also includes cmdlets that use WinRS (Windows Remote Shell), the protocol `winrs.exe` uses, to run commands on a Windows host over the same WinRM listener.

| Cmdlet | Purpose |
| --- | --- |
| [Invoke-WinRSCommand](docs/en-US/PSWSMan/Invoke-WinRSCommand.md) (`irscm`) | Runs a command line on the remote host and outputs its stdout and stderr. |
| [ConvertTo-WinRSCommandLine](docs/en-US/PSWSMan/ConvertTo-WinRSCommandLine.md) | Builds a safely quoted command line for `Invoke-WinRSCommand` from an executable and its arguments. |
| [Send-WinRSFile](docs/en-US/PSWSMan/Send-WinRSFile.md) | Copies local files to the remote host. |
| [Receive-WinRSFile](docs/en-US/PSWSMan/Receive-WinRSFile.md) | Copies files from the remote host to the local host. |
| [New-WinRSShell](docs/en-US/PSWSMan/New-WinRSShell.md), [Get-WinRSShell](docs/en-US/PSWSMan/Get-WinRSShell.md), [Remove-WinRSShell](docs/en-US/PSWSMan/Remove-WinRSShell.md) | Creates, lists, and removes a WinRS shell that several of the above commands can share. |

```powershell
$cred = Get-Credential
Invoke-WinRSCommand -ComputerName Server01 -Credential $cred -Command 'ipconfig /all'
$LASTEXITCODE

$cmd = ConvertTo-WinRSCommandLine 'C:\Program Files\7-Zip\7z.exe' l 'C:\temp\my archive.zip'
irscm Server01 $cmd -Credential $cred

Send-WinRSFile -ComputerName Server01 -Credential $cred -Path ./app.zip -Destination C:\temp
```

They differ from PowerShell remoting in a few ways:

* They do not need `Enable-PSWSMan`, they use this module's WSMan client directly and can be used without hooking the process
* No PowerShell session is started on the remote host, a command runs as `cmd.exe /C <command>` and only its raw output comes back as strings, like a local native command, rather than serialized objects
* `$LASTEXITCODE` is set to the exit code of the remote process and stderr lines are written to the error stream
* Each command runs in a new `cmd.exe` process, even in a shared shell, so a `cd` or `set` in one command is not seen by the next
* `Send-WinRSFile` and `Receive-WinRSFile` need Windows PowerShell 5.1 on the remote host but no PSSession or file share

The connection parameters, `-ComputerName`, `-ConnectionUri`, `-Credential`, `-Authentication`, `-UseSSL`, `-SessionOption`, and so on, are the same as `New-WinRMSession` and mean the same as they do for `Invoke-Command`.
`-SessionOption` takes the output of `New-WinRMSessionOption` or a hashtable, as described in [WinRM Sessions](#winrm-sessions).
Use them when you need to run a native program, work with a host that has no usable PowerShell endpoint, or want the exact output of a command without PowerShell's serialization.

## Contributing

Contributing is quite easy, fork this repo and submit a pull request with the changes.
To build this module run `.\build.ps1 -Task Build` in PowerShell.
To test a build run `.\build.ps1 -Task Test` in PowerShell.
This script will ensure all dependencies are installed before running the test suite.

### Testing against a WinRM server

The tests that connect to a real WinRM server read the servers to use from `test.settings.json` in the repository root.
They are skipped when that file does not exist or no entry matches what a test needs.
The file is git-ignored because it holds credentials, and `tests/settings.schema.json` describes it for editor completion.
The format only exists for the test suite and can change at any time without notice, check the schema after updating.

Each entry in `servers` is one way to connect: an endpoint URL, a credential, and facts about that endpoint.
The tests pick the entries they can use by those facts, so a single domain account entry is enough to run most of the suite.

```json
{
    "servers": [
        {
            "name": "http domain",
            "url": "http://server.domain.test:5985/wsman",
            "username": "user@DOMAIN.TEST",
            "password": "Password01",
            "auth": ["kerberos", "ntlm", "credssp"],
            "jea": "JEA",
            "trusted_for_delegation": true
        },
        {
            "name": "http local",
            "url": "http://server.domain.test:5985/wsman",
            "username": "local-user",
            "password": "Password01",
            "auth": ["basic", "ntlm", "credssp"]
        },
        {
            "name": "https domain",
            "url": "https://server.domain.test:5986/wsman",
            "username": "user@DOMAIN.TEST",
            "password": "Password01",
            "auth": ["kerberos", "ntlm", "credssp", "certificate"],
            "client_certificate": {
                "cert": "client_auth.pem",
                "key": "client_auth.key",
                "password": "password"
            }
        },
        {
            "name": "https untrusted",
            "url": "https://server.domain.test:29904/wsman",
            "username": "user@DOMAIN.TEST",
            "password": "Password01",
            "auth": ["kerberos"],
            "untrusted_certificate": true
        }
    ]
}
```

| Key | Purpose |
| --- | --- |
| `url` | The endpoint. The scheme selects HTTP or HTTPS, the port and path are taken from the URL. |
| `username`, `password` | The credential for this entry. List the same URL twice to test a second account. Use `user@REALM` for a domain account and the plain account name for a local account. Optional when `auth` only contains `certificate`. |
| `auth` | Which of `basic`, `kerberos`, `ntlm`, `credssp` and `certificate` work for this endpoint and credential. Tests only run the methods listed. |
| `untrusted_certificate` | The HTTPS certificate is not trusted by this machine. The tests disable certificate validation when connecting to the entry. |
| `client_certificate` | The client certificate for `certificate` auth. `cert` is either a `.pfx`/`.p12` file unlocked by `password`, or a PEM certificate with its PEM private key in `key` and the key `password` if encrypted. Relative paths are resolved from the directory containing the settings file. |
| `jea` | The name of a JEA session configuration on the endpoint. It must run as a virtual account and its role capability must expose a `Get-PSWSManJeaUserName` function returning `[Environment]::UserName`, `tools/SetupWinCI.ps1` shows how. Enables the JEA test. |
| `trusted_for_delegation` | The server is trusted for unconstrained delegation. Enables the delegation tests. |
| `name` | Optional label used in the test names. |

Tests that need any server take the first entry with a username, so put the most capable entry first.
Use the `user@REALM` form for domain accounts and the plain name for local accounts, the `DOMAIN\user` form is not supported by every authentication method outside Windows.
