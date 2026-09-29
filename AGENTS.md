# AGENTS.md

Guidance for AI agents and other automation working in this repository.
Humans should read it too; it is the shortest accurate description of how the
project is built and tested.

## What this project is

PSWSMan is a cross platform PowerShell binary module that replaces the WSMan
(WinRM) client transport inside PowerShell 7.4+ with a pure C# implementation.
It hooks the internal `System.Management.Automation` (S.M.A) WSMan transport
classes at runtime using MonoMod detours, so the built-in remoting cmdlets
(`New-PSSession`, `Invoke-Command`, `Enter-PSSession`, ...) use this module's
client once `Enable-PSWSMan -Force` has been run.

The same client is also reachable without any hooks. `New-WinRMSession`
creates a PSSession through PowerShell's public custom remoting transport API
(`src/PSWSMan/CustomTransport/`), and the WinRS cmdlets (`Invoke-WinRSCommand`,
`Send-WinRSFile`, ...) run `cmd.exe` commands without a PowerShell session. Both
take their options as a `WinRMSessionOption`.

## Repository layout

| Path | Purpose |
| --- | --- |
| `build.ps1` | Entry point for every build and test action. Wraps InvokeBuild. |
| `manifest.psd1` | Pinned versions of the PowerShell build/test modules (InvokeBuild, Pester, platyPS, PSResourceGet, OpenAuthenticode) and the Python packages the authentication tests need. |
| `global.json` | Pins the .NET SDK (10.0.x) and selects `Microsoft.Testing.Platform` as the `dotnet test` runner. |
| `PSWSMan.slnx` | Solution file listing the three `src/` projects. |
| `src/PSWSMan/` | The PowerShell module assembly: cmdlets, S.M.A patches, authentication (GSSAPI, SSPI, CredSSP, Basic, certificate), TLS, PSRP session bridge (`WSManPSRPSession.cs`). Compiles against the S.M.A implementation assembly from the `System.Management.Automation` NuGet package. |
| `src/PSWSMan/Connection/` | The synchronous HTTP transport (`PSWSMan.Connection` namespace): one authenticated socket per `WSManHttpConnection`, a `WSManConnectionPool` handing them out under exclusive leases, and `WinRSShell`/`WinRSReceivePump` driving a WinRS shell with dedicated receive threads. Nothing in this folder may reference S.M.A types so it can be loaded by a plain unit test project. |
| `src/PSWSMan/CustomTransport/` | The hook-free PSSession behind `New-WinRMSession`: `WinRMConnectionInfo` and its transport manager plug into PowerShell's public custom transport API. The protocol work is done by `OutOfProcWSManTranslator` in `src/PSWSMan/Connection/`, which turns the OutOfProc packets PowerShell writes into WSMan shell operations through `IWSManShellOperations` and the Receive output back into packets, it has no S.M.A dependency so `PSWSMan.Connection.Tests` covers it with a fake shell. Only public or protected S.M.A members may be used here; the project compiles with `IgnoresAccessChecksTo` so the compiler will not catch a slip. The `TracePath` session option (`New-WinRMSessionOption -TracePath`) logs the translated traffic to a file. |
| `src/PSWSMan.Lib/` | Protocol-only library: WSMan/WinRS envelope building and response parsing. No PowerShell dependency, so it is unit testable with plain `dotnet test`. |
| `src/PSWSMan.Loader/` | Tiny `AssemblyLoadContext` used by `module/PSWSMan.psm1` to isolate the module's dependencies from the host process. |
| `src/Directory.Build.props` | Shared compiler settings (C# 12, nullable enabled, unsafe allowed). |
| `src/Directory.Packages.props` | Central package management. All NuGet versions live here; `.csproj` files reference packages without a `Version`. |
| `module/` | The `.psd1` manifest and `.psm1` loader script copied verbatim into the built module. `ModuleVersion` here is the single source of truth for the version. |
| `docs/en-US/` | platyPS markdown help. Compiled to MAML at build time. Edit these when cmdlet parameters or behaviour change. |
| `tests/*.Tests.ps1` | Pester tests that run against the built module. Most connection tests need a real WinRM server and skip without one. |
| `tests/data/` | Files the tests share. `WinRSCommandLine.json` holds the `ConvertTo-WinRSCommandLine` cases that both the `PSWSMan.Lib` unit tests and `tests/ConvertTo-WinRSCommandLine.Tests.ps1` run, and `print_argv.cs` is the argv printer the Pester test compiles on the WinRM host, at the relative `file_path` of the cases under the shell's working directory, to run each expected line verbatim. |
| `tests/common.ps1` | Dot-sourced by every Pester file. Imports the built module and runs `Enable-PSWSMan -Force`. |
| `tests/units/<Project>/` | .NET unit test projects (TUnit). Each directory is discovered and run automatically by the `Test` task. |
| `tests/units/PSWSMan.Authentication.Tests/` | Drives the module's authentication contexts (GSSAPI, Windows SSPI, Devolutions) against an independent acceptor, the pyspnego library, over stdin/stdout. `acceptor.py` is the Python side. These tests skip when Python with pyspnego is not available. |
| `tools/` | Scripts used by `build.ps1`. `InvokeBuild.ps1` defines the tasks; `common.ps1` holds the `Manifest` class and helpers. `UpdateDocs.ps1` regenerates the markdown help from the built module. `SetupWinCI.ps1` configures the Windows CI runner as a WinRM target (listeners, local user, certificate auth, JEA) and writes the matching `test.settings.json`. Run it under Windows PowerShell as an administrator. |
| `output/` | Git-ignored. Built module, nupkg, downloaded PowerShell versions, cached build modules, and test results all land here. Never commit or hand-edit it. |
| `CHANGELOG.md` | Update under the top (unreleased) heading for any user-visible change. |

## Prerequisites

- .NET SDK 10.0.x (see `global.json`; `rollForward` is `latestFeature`).
- PowerShell 7.4 or newer to run the module. The build scripts themselves only need 7.2.
- Network access on first run. The build script downloads the pinned
  PowerShell modules into `output/Modules` via ModuleFast, and `dotnet`
  restores NuGet packages, including `System.Management.Automation`, into the
  usual NuGet cache. Both are cached afterwards.
- Global dotnet tools `dotnet-coverage` and `dotnet-reportgenerator-globaltool`
  are installed automatically by the `Test` task if missing.

## The one command to know

The official way to build and test this project is `build.ps1`. It installs
any missing dependencies, builds the module, runs the tests with coverage, and
produces the same artifacts CI does.

```powershell
pwsh -File ./build.ps1 -Configuration Debug|Release -Task Build|Test
```

`-Configuration` defaults to `Debug` and `-Task` defaults to `Build`. The
faster per-project commands further down are for quick iteration only. Before
calling a change done, run `-Task Build` followed by `-Task Test` and report
the result.

## Building

```powershell
pwsh -File ./build.ps1 -Task Build                          # Debug build
pwsh -File ./build.ps1 -Task Build -Configuration Release   # Release build
```

The `Build` task runs, in order: `Clean`, `BuildManaged` (`dotnet publish` of
`src/PSWSMan` for each target framework with `-p:Version` taken from
`module/PSWSMan.psd1`), `BuildModule` (copy `module/`), `BuildDocs` (platyPS
MAML), `Sign` (no-op unless the Azure Trusted Signing env vars are set), and
`Package` (produces `output/PSWSMan.<version>.nupkg`).

The built module is at `output/PSWSMan/<version>/` and can be imported with
`Import-Module ./output/PSWSMan`.

Gotchas:

- `src/PSWSMan/PSWSMan.csproj` compiles against the implementation assembly
  under `runtimes/win/lib/<tfm>/` of the `System.Management.Automation` NuGet
  package rather than the reference assembly in `ref/`, because the module
  patches internal S.M.A types that the reference assembly omits. The package
  reference excludes every asset so none of its dependencies reach the
  published module. All projects build standalone with `dotnet build`.
- Binary modules cannot be unloaded. After rebuilding, always start a fresh
  `pwsh` process before importing the module again.
- Adding a NuGet dependency means adding a `PackageVersion` to
  `src/Directory.Packages.props` and an unversioned `PackageReference` in the
  `.csproj`. Do not put versions in `.csproj` files.
- Target frameworks are read from the `<TargetFrameworks>` element of
  `src/PSWSMan/PSWSMan.csproj` by the build script. Keep that element on the
  first `PropertyGroup`.

## Testing

`Test` does not build. Run `Build` first.

```powershell
pwsh -File ./build.ps1 -Task Build
pwsh -File ./build.ps1 -Task Test
```

The `Test` task runs, in order:

1. `TestSetup`: writes `output/TestResults/settings.json` restricting coverage
   to the module's own assemblies (those with a `.pdb`).
2. `PythonSetup`: creates a virtual environment at `output/python-venv` and
   installs the `PythonRequirements` pinned in `manifest.psd1`, with `uv`
   when it is on the PATH and otherwise with `python` and `pip`. Its
   interpreter is passed to the unit tests through `PSWSMAN_TEST_PYTHON`.
   Without either this warns and the tests needing it skip.
3. `UnitTests`: for every directory under `tests/units/`, runs `dotnet test
   --project <dir>` with coverage enabled. Output goes to
   `output/TestResults/Unit.<Project>.Coverage.cobertura.xml`.
4. `PesterTests`: launches a separate `pwsh` process (downloaded into
   `output/PowerShell-<version>-<arch>/` if it does not match the current one)
   under `dotnet-coverage collect`, running all `tests/*.Tests.ps1`. Results
   go to `output/TestResults/Pester.xml` and
   `output/TestResults/Integration.Coverage.cobertura.xml`.
5. `CoverageReport`: merges the cobertura files into
   `output/TestResults/Coverage.cobertura.xml`, writes an HTML report to
   `output/TestResults/CoverageReport/`, and prints a summary table of files
   with missing coverage.

Useful variations:

```powershell
# Test against a specific PowerShell version (downloads it if needed)
pwsh -File ./build.ps1 -Task Test -PowerShellVersion 7.4.0

# Test a nupkg produced elsewhere (this is what CI does)
pwsh -File ./build.ps1 -Task Test -ModuleNupkg output/*.nupkg
```

### Running a subset quickly

These shortcuts skip the dependency setup and coverage that `build.ps1`
provides. Use them while iterating, then run the full `-Task Test` before
finishing.

.NET unit tests do not need the module build at all:

```powershell
dotnet test --project tests/units/PSWSMan.Lib.Tests
# Filter to one test/class (Microsoft.Testing.Platform syntax)
dotnet test --project tests/units/PSWSMan.Lib.Tests -- --treenode-filter "/*/*/WSManClientTests/*"

# The authentication tests need pyspnego, point them at the venv the Test task made (absolute path)
PSWSMAN_TEST_PYTHON=$PWD/output/python-venv/bin/python dotnet test --project tests/units/PSWSMan.Authentication.Tests
```

Pester tests need a built module. Run them in a fresh process so a stale
assembly is never picked up. The Pester version pinned in `manifest.psd1` is
installed into `output/Modules` by the `Test` task; import it from there so
the pinned version is the one that runs.

```powershell
pwsh -NoProfile -Command {
    Import-Module ./output/Modules/Pester
    Invoke-Pester -Path ./tests/New-WinRMSessionOption.Tests.ps1 -Output Detailed
}
```

Coverage details for a single run:

```powershell
pwsh -File ./tools/CoverageReport.ps1 -Path ./output/TestResults/Coverage.cobertura.xml -Detailed
```

### Test conventions and gotchas

- Pester tests that need a real WinRM server are skipped, not failed, when no
  server is configured. A green local run therefore does not prove connection
  code works.
- `test.settings.json` in the repository root lists the servers those tests
  use, one entry per endpoint and credential with the auth methods and
  features that work there (schema in `tests/settings.schema.json`, field
  guide under "Testing against a WinRM server" in `README.md`). Tests select
  entries by capability through `Get-PSWSManTestServer` in `tests/common.ps1`
  and feed them to Pester's `-ForEach` (the entry is `$_` in the test), so a
  new connection test should filter on what it needs rather than assume a
  particular host. `Get-PSSessionSplat` turns an entry into the
  `New-PSSession` parameters and takes the `New-WinRMSessionOption`
  parameters as a hashtable, so it can disable certificate validation for
  entries marked `untrusted_certificate`.
- `cmd.exe` cannot write arbitrary bytes. `Get-RawOutputCommand` in
  `tests/common.ps1` builds an `Invoke-WinRSCommand -Command` that writes
  exact bytes, given as hex or a `byte[]`, to stdout or stderr with a
  chosen exit code. It fits about 4KB in the 8191 characters `cmd.exe`
  allows.
- `test.settings.json` is git-ignored and contains credentials. Never commit
  it or copy its contents into other files. When present, its servers and
  credentials are meant to be used for manual testing too, such as proving
  out a POC or a one-off check outside the Pester tests. Read them from the
  file at run time (e.g. `Get-PSWSManTestServer | Get-PSSessionSplat` after
  dot-sourcing `tests/common.ps1`, or parsing the JSON in the script) rather
  than pasting them into commands or scripts. Dot-sourcing `common.ps1` also
  runs `Enable-PSWSMan -Force`, so parse the JSON directly when checking
  behaviour without the S.M.A patches.
- Every Pester file must start with `BeforeDiscovery { . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1')) }`.
- Assertions use the Pester 6 `Should-*` commands (`Should-Be`, `Should-Throw -ExceptionMessage`, ...). The
  classic `Should -Be` form is disabled in the test run and fails.
- New .NET unit test projects go in `tests/units/<Name>/` using TUnit, with
  `<OutputType>Exe</OutputType>` and the shared `Directory.*.props` in
  `tests/units/`. Prefer referencing `PSWSMan.Lib`. `PSWSMan.Connection.Tests`
  references `PSWSMan` directly, which works only because the transport
  classes never touch S.M.A.
- Unit tests are for standalone logic (framing, parsing, pool bookkeeping).
  Do not add tests that stand up fake HTTP servers; connection behaviour is
  verified manually against a real WinRM host. The one process a unit test
  may spawn is the pyspnego acceptor in `PSWSMan.Authentication.Tests`, which
  checks the token exchange and message protection of each security library
  against an independent implementation without any HTTP involved. Tests
  needing it must go through `Acceptor.Start` so they skip cleanly. `Trace-Command -Name
  ClientTransport -FilePath ...` captures the transport and pump activity of the
  patched builtin cmdlets, `-SessionOption @{ TracePath = '...' }` that of
  `New-WinRMSession` and the WinRS cmdlets.
- `build.ps1 -Task Test` instruments the built module for coverage. Do not
  run it while another `pwsh` process has `output/PSWSMan` imported, that
  process can crash with `BadImageFormatException`.

## Continuous integration

`.github/workflows/ci.yml` builds once on Ubuntu, uploads the nupkg, then runs
`build.ps1 -Task Test -ModuleNupkg` on a matrix of PowerShell 7.4, 7.5 and 7.6
on Windows, Linux, and macOS on both Apple silicon and Intel. Each test job
sets up Python for the authentication tests, and the Linux jobs install
gss-ntlmssp so MIT krb5 can do NTLM. Coverage goes to Codecov. Pushes to `main` and
tagged releases (`v*`) build in `Release` configuration; pull requests build
`Debug`. Releases are signed with Azure Trusted Signing and published to the
PowerShell Gallery. CI has no WinRM server, so only the non-connection Pester
tests and the .NET unit tests actually execute there. Put protocol logic in
`PSWSMan.Lib` so it can be covered by unit tests.

## Code conventions

- C# 12, `Nullable` enabled, file-scoped namespaces, 4-space indent. Public
  API in `PSWSMan.Lib` has XML doc comments. Private static fields use the
  `s_` prefix.
- Line endings are LF everywhere (`.gitattributes` sets `text=auto`). Trim
  trailing whitespace and end files with a newline.
- Cmdlets live in `src/PSWSMan/Commands/`. Adding a cmdlet means also adding
  it to `CmdletsToExport` in `module/PSWSMan.psd1` and writing
  `docs/en-US/<Verb-Noun>.md`. Parameter changes must be reflected in the
  markdown help; `pwsh -File ./tools/UpdateDocs.ps1` (also the VS Code task
  "update docs") regenerates it from the built module with platyPS and
  rewrites the pages with LF line endings on non-Windows hosts.
- Add a line to `CHANGELOG.md` under the unreleased heading for anything a
  user would notice.
- Internal S.M.A members are only meant for the `Enable-PSWSMan` path
  (`src/PSWSMan/Patches/`, `WSManPSRPSession.cs` and the `Enable-PSWSMan`
  cmdlet). `IgnoresAccessChecksTo` is an assembly attribute and cannot be
  scoped to a namespace, so the compiler will not stop internal use anywhere
  else in `src/PSWSMan`. Outside that path prefer a public API; when there is
  none, mark the use with an `// Internal S.M.A API:` comment that says what
  it is, why no public API works and that it is a known risk. The current ones
  are `ErrorRecord.PreserveInvocationInfoOnce` (`Invoke-WinRSCommand`) and
  the `$using:` capture and `ScriptBlock` constructor behind
  `New-RemoteCertificateValidationCallback`. `src/PSWSMan/CustomTransport/` must
  never use one. To audit, build a copy of the project against
  `ref/<tfm>/System.Management.Automation.dll` of the NuGet package without
  `IgnoresAccessChecksTo` and without the `Enable-PSWSMan` path files, every
  compile error is an internal use.

### Verifying manually against a WinRM host

Connection behaviour is verified by hand, not by unit tests. The module must
be built, imported and enabled in a fresh process before any remoting cmdlet
goes through it. Without `Enable-PSWSMan -Force` the cmdlets use PowerShell's
own transport, and a stale process keeps the previously loaded assembly.

```powershell
pwsh -File ./build.ps1 -Task Build
pwsh -NoProfile -Command {
    Import-Module ./output/PSWSMan
    Enable-PSWSMan -Force
    $so = New-WinRMSessionOption -NoEncryption
    Invoke-Command -ComputerName host.example.test { hostname } -Credential $cred -SessionOption $so
}
```

Wrap scenarios that can stall (a remote command bouncing the network, a
black-holed host) in `timeout` and lower `-OperationTimeout` on the session
option, a lost `Receive` only surfaces once that timeout plus its grace
period elapses. Return plain properties rather than CIM instances from the
remote command, a pwsh install without `libmi` cannot deserialize them and
the failure looks like a transport error.

## Debugging

- `pwsh -NoExit -File ./tools/LaunchScript.ps1` imports the built module and
  enables it in an interactive session. `.vscode/launch.json` attaches the
  .NET debugger to that script.
- `Trace-Command -PSHost -Name ClientTransport -Expression { ... }` shows the
  transport-level hook activity of the patched builtin cmdlets from inside
  PowerShell.
- `New-WinRMSession` and the WinRS cmdlets do not write to that internal trace
  source. Pass `-SessionOption @{ TracePath = '...' }` to write their trace,
  including the OutOfProc packets of `New-WinRMSession`, to a file.
