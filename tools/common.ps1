using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.IO
using namespace System.IO.Compression
using namespace System.Management.Automation
using namespace System.Net
using namespace System.Net.Http
using namespace System.Runtime.InteropServices

#Requires -Version 7.2

# Progress records are just a menace, especially in newer PowerShell versions
# so we just disable it.
$ProgressPreference = 'Ignore'

class Manifest {
    [PSModuleInfo]$Module

    [ValidateSet("Debug", "Release")]
    [string]$Configuration

    [string]$RepositoryPath
    [string]$DocsPath
    [string]$DotnetPath
    [string]$OutputPath
    [string]$PowerShellPath
    [string]$ReleasePath
    [string]$TestPath
    [string]$TestResultsPath
    [string]$TestSettingsPath

    [string]$DotnetProject
    [Hashtable[]]$BuildRequirements
    [Hashtable[]]$TestRequirements
    [string]$PesterVersion
    [string[]]$PythonRequirements
    [Version]$PowerShellVersion
    [Architecture]$PowerShellArch
    [string[]]$TargetFrameworks
    [string]$TestFramework

    Manifest(
        [string]$Configuration,
        [Version]$PowerShellVersion,
        [Architecture]$PowerShellArch,
        [string]$ManifestPath
    ) {
        $this.RepositoryPath = [Path]::GetFullPath([Path]::Combine($PSScriptRoot, ".."))
        $moduleManifestParams = @{
            Path = [Path]::Combine($this.RepositoryPath, "module", "*.psd1")
            # Can emit errors about invalid RootModule which don't matter here
            ErrorAction = 'Ignore'
            WarningAction = 'Ignore'
        }
        $this.Module = Test-ModuleManifest @moduleManifestParams

        $this.Configuration = $Configuration

        $raw = Import-PowerShellDataFile -LiteralPath $ManifestPath
        $this.DotnetProject = $raw.DotnetProject ?? $this.Module.Name

        $this.DocsPath = [Path]::Combine($this.RepositoryPath, "docs")
        $this.DotnetPath = [Path]::Combine($this.RepositoryPath, "src", $this.DotnetProject)
        $this.OutputPath = [Path]::Combine($this.RepositoryPath, "output")
        $this.PowerShellPath = [Path]::Combine($this.RepositoryPath, "module")
        $this.ReleasePath = [Path]::Combine($this.OutputPath, $this.Module.Name, $this.Module.Version)
        $this.TestPath = [Path]::Combine($this.RepositoryPath, "tests")
        $this.TestResultsPath = [Path]::Combine($this.OutputPath, "TestResults")
        $this.TestSettingsPath = [Path]::Combine($this.TestResultsPath, "settings.json")

        if (-not (Test-Path -LiteralPath $this.ReleasePath)) {
            New-Item -Path $this.ReleasePath -ItemType Directory -Force | Out-Null
        }

        if (-not (Test-Path -LiteralPath $this.TestResultsPath)) {
            New-Item -Path $this.TestResultsPath -ItemType Directory -Force | Out-Null
        }

        $invokeBuildReq = @{
            ModuleName = 'InvokeBuild'
            RequiredVersion = $raw.InvokeBuildVersion
        }
        $pesterReq = @{
            ModuleName = 'Pester'
            RequiredVersion = $raw.PesterVersion
        }
        $this.BuildRequirements = @(
            $invokeBuildReq
            $raw.BuildRequirements
        )
        $this.TestRequirements = @(
            $invokeBuildReq
            $pesterReq
            $raw.TestRequirements
        )
        $this.PesterVersion = $raw.PesterVersion
        $this.PythonRequirements = @($raw.PythonRequirements)

        if ($PowerShellVersion.Major -lt 6) {
            $this.PowerShellVersion = "5.1"
        }
        else {
            $build = $PowerShellVersion.Build
            if ($build -eq -1) {
                $build = 0
            }
            $this.PowerShellVersion = "$($PowerShellVersion.Major).$($PowerShellVersion.Minor).$build"
        }
        $this.PowerShellArch = $PowerShellArch

        $csProjPath = [Path]::Combine($this.DotnetPath, "*.csproj")
        [xml]$csharpProjectInfo = Get-Content $csProjPath
        $this.TargetFrameworks = @(
            @($csharpProjectInfo.Project.PropertyGroup)[0].TargetFrameworks.Split(
                ';', [StringSplitOptions]::RemoveEmptyEntries)
        )

        $availableFrameworks = @(
            if ($this.PowerShellVersion -eq '5.1') {
                'net48'
                foreach ($minor in '7', '6', '5') {
                    foreach ($build in '2', '1', '') {
                        "net4$minor$build"
                    }
                }
            }
            else {
                # Minor releases + 4 correspond to the highest framework
                # available. e.g. 7.1 runs on net5.0 or lower, 7.2, on net6.0
                # or lower, etc.
                $netFrameworks = @(
                    for ($i = 5; $i -le $this.PowerShellVersion.Minor + 4; $i++) {
                        "net$i.0"
                    }
                )
                [Array]::Reverse($netFrameworks)

                $netFrameworks
                'netstandard2.1'
            }

            # WinPS and PS are compatible with netstandard to 2.0
            '2.0', '1.6', '1.5', '1.4', '1.3', '1.2', '1.1', '1.0' |
                ForEach-Object { "netstandard$_" }
        )

        foreach ($framework in $availableFrameworks) {
            foreach ($actualFramework in $this.TargetFrameworks) {
                if ($actualFramework.StartsWith($framework)) {
                    $this.TestFramework = $actualFramework
                    break
                }
            }

            if ($this.TestFramework) {
                break
            }
        }
    }
}

function Assert-ModuleFast {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Version = 'latest'
    )

    $moduleName = 'ModuleFast'
    if (Get-Module $moduleName) {
        Write-Warning "Module $moduleName already loaded, skipping bootstrap."
        return
    }

    $ProgressPreference = 'Ignore'

    $attempt = 0
    while ($true) {
        try {
            $code = Invoke-WebRequest -Uri 'bit.ly/modulefast'
            break
        }
        catch {
            if ($attempt -ge 2) {
                throw "Failed to download bootstrap code for $moduleName after 3 attempts. Error: $_"
            }

            Write-Warning "Failed to download bootstrap code for $moduleName, attempt $($attempt + 1) of 3. Error: $_"
            $attempt++
        }
    }

    & ([scriptblock]::Create($code)) -Release $Version
}

function Assert-PowerShell {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Version]$Version,

        [Parameter()]
        [Architecture]
        $Arch = [RuntimeInformation]::ProcessArchitecture
    )

    $releaseArch = switch ($Arch) {
        X64 { 'x64' }
        X86 { 'x86' }
        ARM64 { 'arm64' }
        default {
            $err = [ErrorRecord]::new(
                [Exception]::new("Unsupported architecture requests '$_'"),
                "UnknownArch",
                [ErrorCategory]::InvalidArgument,
                $_
            )
            $PSCmdlet.ThrowTerminatingError($err)
        }
    }

    $osArch = [RuntimeInformation]::OSArchitecture
    $procArch = [RuntimeInformation]::ProcessArchitecture
    if ($Version -eq '5.1') {
        if ($IsCoreCLR -and -not $IsWindows) {
            $err = [ErrorRecord]::new(
                [Exception]::new("Cannot use PowerShell 5.1 on non-Windows hosts"),
                "WinPSNotAvailable",
                [ErrorCategory]::InvalidArgument,
                $Version
            )
            $PSCmdlet.ThrowTerminatingError($err)
        }

        $system32 = if ($Arch -eq [Architecture]::X64) {
            if ($osArch -ne [Architecture]::X64) {
                $err = [ErrorRecord]::new(
                    [Exception]::new("Cannot use PowerShell 5.1 $Arch on Windows $osArch"),
                    "WinPSNoAvailableArch",
                    [ErrorCategory]::InvalidArgument,
                    $Arch
                )
                $PSCmdlet.ThrowTerminatingError($err)
            }

            ($procArch -eq [Architecture]::X64) ? 'System32' : 'SystemNative'
        }
        else {
            ($procArch -eq [Architecture]::X86) ? 'System32' : 'SysWow64'
        }

        return [Path]::Combine($env:SystemRoot, $system32, "WindowsPowerShell", "v1.0", "powershell.exe")
    }
    elseif (
        $PSVersionTable.PSVersion.Major -eq $Version.Major -and
        $PSVersionTable.PSVersion.Minor -eq $Version.Minor -and
        $PSVersionTable.PSVersion.Patch -eq $Version.Build -and
        $procArch -eq $Arch
    ) {
        return [Environment]::GetCommandLineArgs()[0] -replace '\.dll$', ''
    }

    $targetFolder = $PSCmdlet.GetUnresolvedProviderPathFromPSPath(
        [Path]::Combine($PSScriptRoot, "..", "output", "PowerShell-$Version-$releaseArch"))
    $pwshExe = [Path]::Combine($targetFolder, "pwsh$nativeExt")

    if (Test-Path -LiteralPath $pwshExe) {
        return $pwshExe
    }

    if ($IsWindows) {
        $releasePath = "PowerShell-$Version-win-$releaseArch.zip"
        $fileName = "pwsh-$Version-$releaseArch.zip"
        $nativeExt = ".exe"
    }
    else {
        $os = $IsLinux ? "linux" : "osx"
        $releasePath = "powershell-$Version-$os-$releaseArch.tar.gz"
        $fileName = "pwsh-$Version-$releaseArch.tar.gz"
        $nativeExt = ""
    }
    $downloadUrl = "https://github.com/PowerShell/PowerShell/releases/download/v$Version/$releasePath"
    $downloadArchive = [Path]::Combine($targetFolder, $fileName)

    if (-not (Test-Path -LiteralPath $targetFolder)) {
        New-Item $targetFolder -ItemType Directory -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $downloadArchive)) {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadArchive
    }

    if (-not (Test-Path -LiteralPath $pwshExe)) {
        if ($IsWindows) {
            $oldPreference = $global:ProgressPreference
            try {
                $global:ProgressPreference = 'SilentlyContinue'
                Expand-Archive -LiteralPath $downloadArchive -DestinationPath $targetFolder -Force
            }
            finally {
                $global:ProgressPreference = $oldPreference
            }
        }
        else {
            tar -xf $downloadArchive --directory $targetFolder
            if ($LASTEXITCODE) {
                $err = [ErrorRecord]::new(
                    [Exception]::new("Failed to extract pwsh tar for $Version"),
                    "FailedToExtractTar",
                    [ErrorCategory]::NotSpecified,
                    $null
                )
                $PSCmdlet.ThrowTerminatingError($err)
            }

            chmod +x $pwshExe
            if ($LASTEXITCODE) {
                $err = [ErrorRecord]::new(
                    [Exception]::new("Failed to set pwsh as executable at '$pwshExe'"),
                    "FailedToSetPwshExecutable",
                    [ErrorCategory]::NotSpecified,
                    $null
                )
                $PSCmdlet.ThrowTerminatingError($err)
            }
        }
    }

    $pwshExe
}

function Expand-Nupkg {
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [string]
        $DestinationPath
    )

    $Path = (Resolve-Path -Path $Path).Path

    # WinPS doesn't support extracting from anything without a .zip extension
    # so it needs to be renamed there
    $renamed = $false
    try {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            $zipPath = $Path -replace '.nupkg$', '.zip'
            Move-Item -LiteralPath $Path -Destination $zipPath
            $renamed = $true
        }
        else {
            $zipPath = $Path
        }

        $oldPreference = $global:ProgressPreference
        try {
            $global:ProgressPreference = 'SilentlyContinue'
            Expand-Archive -LiteralPath $zipPath -DestinationPath $DestinationPath -Force
        }
        finally {
            $global:ProgressPreference = $oldPreference
        }
    }
    finally {
        if ($renamed) {
            Move-Item -LiteralPath $zipPath -Destination $Path
        }
    }

    '`[Content_Types`].xml', '*.nuspec', '_rels', 'package' | ForEach-Object -Process {
        $uneededPath = [Path]::Combine($DestinationPath, $_)
        Remove-Item -Path $uneededPath -Recurse -Force
    }
}

function Install-BuildDependencies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [IDictionary[]]
        $Requirements
    )

    begin {
        $specifications = [List[string]]::new()
        $modulePaths = [List[string]]::new()
        $modulePath = [Path]::Combine($PSScriptRoot, "..", "output", "Modules")
    }
    process {
        foreach ($dep in $Requirements) {
            # A requirement can name the PowerShell version it needs, it is
            # left out on an older host instead of failing the import.
            if ($dep.PowerShellVersion -and $PSVersionTable.PSVersion -lt [Version]$dep.PowerShellVersion) {
                Write-Warning "Skipping the module $($dep.ModuleName), it needs PowerShell $($dep.PowerShellVersion) or newer"
                continue
            }

            $currentModPath = [Path]::Combine($modulePath, $dep.ModuleName)
            if (-not (Test-Path -LiteralPath $currentModPath)) {
                # ModuleFast specification strings, a RequiredVersion with a
                # prerelease label cannot be given as a hashtable.
                $specifications.Add($dep.RequiredVersion ?
                    "$($dep.ModuleName):[$($dep.RequiredVersion)]" :
                    "$($dep.ModuleName)>=$($dep.ModuleVersion)")
            }
            $modulePaths.Add($currentModPath)
        }
    }
    end {
        if ($specifications) {
            Assert-ModuleFast -Version v0.6.1

            $installParams = @{
                Specification = $specifications
                Destination = $modulePath
                DestinationOnly = $true
                NoPSModulePathUpdate = $true
                NoProfileUpdate = $true
                Update = $true
            }
            if (-not (Test-Path -LiteralPath $installParams.Destination)) {
                New-Item -Path $installParams.Destination -ItemType Directory -Force | Out-Null
            }
            Install-ModuleFast @installParams
        }

        foreach ($path in $modulePaths) {
            Import-Module -Name $path
        }
    }
}

function Invoke-WithTestKdc {
    <#
    .SYNOPSIS
    Runs a scriptblock with a Kerberos realm for the authentication unit tests.

    .DESCRIPTION
    Starts an Obol KDC for the realm PSWSMAN.TEST and runs the scriptblock in
    its krb5 environment, so a child process such as dotnet test finds the KDC
    through KRB5_CONFIG and the service keytab through KRB5_KTNAME. On Windows
    the realm is also registered with Windows Kerberos for the whole machine
    the way ksetup does, SSPI ignores krb5.conf and a per-thread registration
    would not reach the test or acceptor processes. What the tests need to know
    is passed as JSON in the PSWSMAN_TEST_KERBEROS environment variable, see
    KerberosRealm in tests/units/PSWSMan.Authentication.Tests.

    The scriptblock runs without a realm, after a warning, when the Obol module
    is not loaded (it needs PowerShell 7.6) or the session is not elevated on
    Windows. The Kerberos tests then skip.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]
        $ScriptBlock
    )

    if (-not (Get-Command -Name Use-ObolKrb5Environment -ErrorAction Ignore)) {
        Write-Warning "The Obol module is not loaded, the Kerberos unit tests will skip"
        & $ScriptBlock
        return
    }

    if ($IsWindows) {
        $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Warning "Registering the test KDC with Windows Kerberos needs an elevated session, the Kerberos unit tests will skip"
            & $ScriptBlock
            return
        }
    }

    $realm = 'PSWSMAN.TEST'
    $user = 'user'
    $service = 'HTTP'
    $hostname = 'winrm.pswsman.test'
    $serviceAccount = 'svc-winrm'
    $userPassword = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(16))
    $servicePassword = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(16))

    # The SPN is an alias of an account, like an AD service account. The SSPI
    # acceptor on Windows does not read KRB5_KTNAME and logs on with the
    # account's password instead, and for an account name Windows derives the
    # same keys from it as the KDC did, which it does not for a name with a
    # slash in it.
    # NoAuthDataRequired leaves the PAC out of the service tickets, a Windows
    # acceptor without SeTcbPrivilege would otherwise ask a domain controller
    # to validate it. TrustedForDelegation sets OK-AS-DELEGATE on the tickets,
    # Windows only forwards a TGT to a service that has it.
    $servicePrincipal = "$service/$hostname"
    $serviceParams = @{
        Alias = $servicePrincipal
        Flag = 'NoAuthDataRequired', 'TrustedForDelegation'
        Password = ConvertTo-SecureString -AsPlainText -Force $servicePassword
    }
    $serviceSetting = New-ObolPrincipalSetting @serviceParams
    $kdcParams = @{
        Realm = $realm
        Principal = [ordered]@{
            $user = ConvertTo-SecureString -AsPlainText -Force $userPassword
            $serviceAccount = $serviceSetting
        }
        ServicePrincipal = $servicePrincipal
        # Windows Kerberos only contacts port 88, which needs no rights to bind
        # on Windows. Elsewhere any free port does.
        Port = $IsWindows ? 88 : 0
    }
    $settings = @{
        Realm = $realm
        Username = "$user@$realm"
        Password = $userPassword
        Service = $service
        Hostname = $hostname
        AcceptorUsername = "$serviceAccount@$realm"
        AcceptorPassword = $servicePassword
    } | ConvertTo-Json -Compress

    Use-ObolKrb5Environment @kdcParams {
        param ($kdc)

        Write-Host "Started the test KDC for $realm on $($kdc.Endpoint)" -ForegroundColor Cyan

        # MIT krb5 only forwards a TGT that is forwardable and does not ask for
        # one unless configured to, the delegation test needs it. KRB5_CONFIG is
        # a list of files, the extra one lives in the directory Obol removes
        # with the environment. Obol only restores a variable that still holds
        # the value it set, so the value is put back before it exits.
        $obolConfig = $env:KRB5_CONFIG
        $forwardableConfig = Join-Path -Path (Split-Path -Path $obolConfig -Parent) -ChildPath 'forwardable.conf'
        Set-Content -LiteralPath $forwardableConfig -Value "[libdefaults]`n    forwardable = true`n" -NoNewline
        $env:KRB5_CONFIG = "$obolConfig$([Path]::PathSeparator)$forwardableConfig"
        $env:PSWSMAN_TEST_KERBEROS = $settings
        try {
            if ($IsWindows) {
                # MitRealm registers the realm and its KDC in the registry like
                # ksetup /addkdc, machine wide, so the test process, the
                # acceptor processes and the Devolutions provider, which reads
                # the same key, all find it. DcLocator would do the same
                # through DNS and an LDAP ping responder, more moving parts for
                # no difference the tests can see as the tickets have no PAC.
                Use-ObolSspiEnvironment -Kdc $kdc -Scope MitRealm -ScriptBlock $ScriptBlock
            }
            else {
                & $ScriptBlock
            }
        }
        finally {
            Remove-Item -LiteralPath Env:PSWSMAN_TEST_KERBEROS -ErrorAction Ignore
            $env:KRB5_CONFIG = $obolConfig
        }
    }
}
