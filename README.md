# PSWSMan

[![Test workflow](https://github.com/jborean93/PSWSMan/workflows/Test%20PSWSMan/badge.svg)](https://github.com/jborean93/PSWSMan/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/PSWSMan/branch/main/graph/badge.svg?token=b51IOhpLfQ)](https://codecov.io/gh/jborean93/PSWSMan)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/PSWSMan.svg)](https://www.powershellgallery.com/packages/PSWSMan)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/PSWSMan/blob/main/LICENSE)

See [about_PSWSMan](docs/en-US/about_PSWSMan.md) for more details.

## Documentation

Documentation for this module and details on the cmdlets included can be found [here](docs/en-US/PSWSMan.md).
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

Once installed, run `Enable-PSWSMan -Force` to enable the hooks needed for PowerShell to use this module.
Once enabled the builtin cmdlets will use this module for any WSMan transport operations.

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
