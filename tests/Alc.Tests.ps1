using namespace System.IO
using namespace System.Runtime.Loader

BeforeDiscovery {
    . ([Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "Module loading" {
    BeforeAll {
        $moduleBase = (Get-Module PSWSMan).ModuleBase

        # Copies the built module to a new folder so a child process can change or import it without touching the
        # module this process loaded. Only one copy of the module can be loaded in a process.
        Function Copy-TestModule {
            param ([string]$Name)

            $destination = [Path]::Combine($TestDrive, $Name, 'PSWSMan')
            $null = New-Item $destination -ItemType Directory -Force
            Copy-Item -Path ([Path]::Combine($moduleBase, '*')) -Destination $destination -Recurse
            $destination
        }

        # Runs a script in a new pwsh process and returns its output parsed from JSON.
        Function Invoke-ChildPwsh {
            param ([string]$Script)

            $out = & ([Environment]::ProcessPath) -NoProfile -NonInteractive -Command $Script 2>&1
            $LASTEXITCODE | Should-Be 0 -Because ($out -join "`n")
            ($out -join "`n") | ConvertFrom-Json
        }
    }

    It "Loads the module assembly in the PSWSMan load context" {
        [AssemblyLoadContext]::GetLoadContext([PSWSMan.Commands.NewWinRMSessionOption].Assembly).Name |
            Should-Be PSWSMan
    }

    It "Loads the loader in the default load context" {
        $loader = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq 'PSWSMan.Loader' }

        $loader | Should-NotBeNull
        [AssemblyLoadContext]::GetLoadContext($loader) | Should-BeSame ([AssemblyLoadContext]::Default)
    }

    It "Loads MonoMod.RuntimeDetour in the module load context" {
        # common.ps1 ran Enable-PSWSMan -Force so the detour library is loaded.
        $asm = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq 'MonoMod.RuntimeDetour' }

        $asm | Should-NotBeNull
        [AssemblyLoadContext]::GetLoadContext($asm).Name | Should-Be PSWSMan
    }

    It "Resolves <_> from PSWSMan.deps.json" -ForEach 'PSWSMan.Lib', 'Devolutions.Sspi' {
        $moduleAsm = [PSWSMan.Commands.NewWinRMSessionOption].Assembly
        $alc = [AssemblyLoadContext]::GetLoadContext($moduleAsm)
        $asm = $alc.LoadFromAssemblyName([Reflection.AssemblyName]::new($_))

        [AssemblyLoadContext]::GetLoadContext($asm) | Should-BeSame $alc

        # The resolver returns the real path while the module path may go through a symlink, so compare the files.
        $expected = [Path]::Combine([Path]::GetDirectoryName($moduleAsm.Location), "$_.dll")
        (Get-FileHash -LiteralPath $asm.Location).Hash | Should-Be (Get-FileHash -LiteralPath $expected).Hash
    }

    It "Uses the System.Management.Automation of PowerShell" {
        # The module references it without bundling it, so the load context falls back to PowerShell's copy.
        $actual = [PSWSMan.Commands.NewWinRMSessionOption].BaseType.Assembly

        $actual | Should-BeSame ([PSObject].Assembly)
        [AssemblyLoadContext]::GetLoadContext($actual) | Should-BeSame ([AssemblyLoadContext]::Default)
    }

    It "Does not make dependency types resolvable by name" {
        'MonoMod.RuntimeDetour.Hook' -as [type] | Should-BeNull
    }

    It "Only loads dependencies listed in PSWSMan.deps.json" {
        # A file next to the module that is not a runtime asset in PSWSMan.deps.json must not be loaded. The build
        # puts PowerShell's System.Management.Automation.dll there for the coverage instrumenter, this one is not a
        # valid assembly so loading it from the module folder would fail.
        $copy = Copy-TestModule decoy
        [File]::WriteAllText([Path]::Combine($copy, 'bin', 'net8.0', 'System.Management.Automation.dll'), 'not an assembly')

        $actual = Invoke-ChildPwsh @"
`$ErrorActionPreference = 'Stop'
Import-Module '$copy'
`$so = New-WinRMSessionOption -OperationTimeout 1234
`$sma = [PSWSMan.Commands.NewWinRMSessionOption].BaseType.Assembly
[PSCustomObject]@{
    OperationTimeout = `$so.OperationTimeout.TotalMilliseconds
    SmaIsPwsh = [object]::ReferenceEquals(`$sma, [System.Management.Automation.PSObject].Assembly)
    SmaLocation = `$sma.Location
} | ConvertTo-Json
"@

        $actual.OperationTimeout | Should-Be 1234
        $actual.SmaIsPwsh | Should-BeTrue
        $actual.SmaLocation | Should-NotBeLikeString "$copy*"
    }

    It "Refuses to import a copy from another path in the same process" {
        $first = Copy-TestModule first
        $second = Copy-TestModule second

        $actual = Invoke-ChildPwsh @"
Import-Module '$first'
try {
    Import-Module '$second' -ErrorAction Stop
    `$errorId = `$null
}
catch {
    `$errorId = `$_.FullyQualifiedErrorId
}
[PSCustomObject]@{
    ErrorId = `$errorId
    Loaded = (Get-Module PSWSMan).ModuleBase
} | ConvertTo-Json
"@

        $actual.ErrorId | Should-BeLikeString 'ModuleAlreadyLoadedFromDifferentPath*'
        $actual.Loaded | Should-BeLikeString "$first*"
    }
}
