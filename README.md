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

* PowerShell v7.2 or newer

## Installing

The easiest way to install this module is through
[PowerShellGet](https://docs.microsoft.com/en-us/powershell/gallery/overview).

You can install this module by running;

```powershell
# Install for only the current user
Install-Module -Name PSWSMan -Scope CurrentUser

# Install for all users
Install-Module -Name PSWSMan -Scope AllUsers
```

Once installed, run `Enable-PSWSMan -Force` to enable the hooks needed for PowerShell to use this module.
Once enabled the builtin cmdlets will use this module for any WSMan transport operations.

## Contributing

Contributing is quite easy, fork this repo and submit a pull request with the changes.
To build this module run `.\build.ps1 -Task Build` in PowerShell.
To test a build run `.\build.ps1 -Task Test` in PowerShell.
This script will ensure all dependencies are installed before running the test suite.
