using namespace System.Collections
using namespace System.IO

#Requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [Manifest]
    $Manifest
)

#region Build

task Clean {
    if (Test-Path -LiteralPath $Manifest.ReleasePath) {
        Remove-Item -LiteralPath $Manifest.ReleasePath -Recurse -Force
    }
    New-Item -Path $Manifest.ReleasePath -ItemType Directory | Out-Null
}

task BuildManaged {
    $arguments = @(
        'publish'
        '--configuration', $Manifest.Configuration
        '--verbosity', 'quiet'
        '-nologo'
        "-p:Version=$($Manifest.Module.Version)"
    )

    $csproj = (Get-Item -Path "$($Manifest.DotnetPath)/*.csproj").FullName
    foreach ($framework in $Manifest.TargetFrameworks) {
        Write-Host "Compiling for $framework" -ForegroundColor Cyan
        $outputDir = [Path]::Combine($Manifest.ReleasePath, "bin", $framework)
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        dotnet @arguments --framework $framework --output $outputDir $csproj

        if ($LASTEXITCODE) {
            throw "Failed to compiled code for $framework"
        }

        # RID specific assets stay next to PSWSMan.deps.json so the loader's
        # AssemblyDependencyResolver can find them. Prune RIDs PowerShell
        # does not run on.
        $runtimesDir = [Path]::Combine($outputDir, 'runtimes')
        foreach ($rid in 'android*', 'ios*', 'osx-universal') {
            Remove-Item ([Path]::Combine($runtimesDir, $rid)) -Recurse -Force -ErrorAction Ignore
        }
    }
}

task BuildModule {
    $copyParams = @{
        Path = [Path]::Combine($Manifest.PowerShellPath, '*')
        Destination = $Manifest.ReleasePath
        Recurse = $true
        Force = $true
    }
    Copy-Item @copyParams
}

task BuildDocs {
    Get-ChildItem -LiteralPath $Manifest.DocsPath -Directory | ForEach-Object {
        Write-Host "Building docs for $($_.Name)" -ForegroundColor Cyan
        $outputPath = [Path]::Combine($Manifest.ReleasePath, $_.Name)
        New-Item -Path $outputPath -ItemType Directory -Force | Out-Null

        $moduleDocs = [Path]::Combine($_.FullName, $Manifest.Module.Name)
        $commandFiles = Measure-PlatyPSMarkdown -Path ([Path]::Combine($moduleDocs, '*.md')) |
            Where-Object { $_.FileType -band 'CommandHelp' } |
            Select-Object -ExpandProperty FilePath
        $commandHelp = Import-MarkdownCommandHelp -Path $commandFiles

        # Export-MamlCommandHelp writes to a sub folder named after the
        # module, stage it and move the xml into the culture folder.
        $stagingPath = [Path]::Combine($Manifest.OutputPath, 'maml', $_.Name)
        if (Test-Path -LiteralPath $stagingPath) {
            Remove-Item -LiteralPath $stagingPath -Recurse -Force
        }
        Export-MamlCommandHelp -CommandHelp $commandHelp -OutputFolder $stagingPath -Force |
            Move-Item -Destination $outputPath -Force

        # PlatyPS no longer converts about topics, the help system reads the
        # markdown as plain text just fine.
        Get-ChildItem -LiteralPath $moduleDocs -Filter 'about_*.md' -File | ForEach-Object {
            $dest = [Path]::Combine($outputPath, "$($_.BaseName).help.txt")
            Copy-Item -LiteralPath $_.FullName -Destination $dest
        }
    }
}

task Sign {
    $accountName = $env:AZURE_TS_NAME
    $profileName = $env:AZURE_TS_PROFILE
    $endpoint = $env:AZURE_TS_ENDPOINT
    if (-not $accountName -or -not $profileName -or -not $endpoint) {
        return
    }

    Write-Host "Authenticating with Azure TrustedSigning $accountName $profileName for signing" -ForegroundColor Cyan
    $keyParams = @{
        AccountName = $accountName
        ProfileName = $profileName
        Endpoint = $endpoint
    }
    $key = Get-OpenAuthenticodeAzTrustedSigner @keyParams
    $signParams = @{
        Key = $key
        TimeStampServer = 'http://timestamp.acs.microsoft.com'
    }

    $toSign = Get-ChildItem -LiteralPath $Manifest.ReleasePath -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension -in ".ps1", ".psm1", ".psd1", ".ps1xml" -or (
                $_.Extension -eq ".dll" -and $_.BaseName -like "$($Manifest.Module.Name)*"
            )
        } |
        ForEach-Object -Process {
            Write-Host "Signing '$($_.FullName)'"
            $_.FullName
        }

    Set-OpenAuthenticodeSignature -LiteralPath $toSign @signParams
}

task Package {
    $repoParams = @{
        Name = "$($Manifest.Module.Name)-Local"
        Uri = $Manifest.OutputPath
        Trusted = $true
        Force = $true
    }
    Register-PSResourceRepository @repoParams
    try {
        Publish-PSResource -Path $Manifest.ReleasePath -Repository $repoParams.Name -SkipModuleManifestValidate
    }
    finally {
        Unregister-PSResourceRepository -Name $repoParams.Name
    }
}

#endregion Build

#region Test

task TestSetup {
    $wildcardBase = ".*$([regex]::Escape([Path]::DirectorySeparatorChar))"
    $watchFolder = [Path]::Combine($Manifest.ReleasePath, 'bin', $Manifest.TestFramework)

    # This is used in unit tests to restrict the coverage collector to only the
    # module assemblies. Only the dlls with a pdb file are generated by us. We
    # cannot rely on the default in case external pdbs are found by dotnet.
    # The integration tests ignore this option as PesterTests instruments the
    # same assemblies explicitly.
    # The Loader is ALC boilerplate and is excluded from coverage.
    $includedAssemblies = @(
        Get-ChildItem -LiteralPath $watchFolder -Filter "*.pdb" |
            Where-Object BaseName -NE "$($Manifest.Module.Name).Loader" |
            ForEach-Object {
                "$wildcardBase$([regex]::Escape($_.BaseName))\.dll$"
            }
    )

    $config = @{
        codeCoverage = @{
            Configuration = @{
                Format = 'cobertura'
                DeterministicReport = $env:GITHUB_ACTIONS -eq 'true'
                # Treats the code after a call to a [DoesNotReturn] method in
                # another assembly, like Cmdlet.ThrowTerminatingError, as
                # unreachable. The default only looks in the same assembly.
                DoesNotReturnAttribute = 'AllAssemblies'
                CodeCoverage = @{
                    ModulePaths = @{
                        Include = $includedAssemblies
                    }
                }
            }
        }
    }
    $configJson = $config | ConvertTo-Json -Depth 5
    Set-Content -Path $Manifest.TestSettingsPath -Value $configJson -Encoding UTF8
}

task PythonSetup {
    if (-not $Manifest.PythonRequirements) {
        return
    }

    $venvPath = [Path]::Combine($Manifest.OutputPath, 'python-venv')
    $venvSubPath = $IsWindows ? 'Scripts\python.exe' : 'bin/python'
    $venvPython = [Path]::Combine($venvPath, $venvSubPath)

    # Prefer uv if available, otherwise fallback to python
    $uv = Get-Command -Name uv -CommandType Application -ErrorAction Ignore | Select-Object -First 1
    $python = Get-Command -Name python -CommandType Application -ErrorAction Ignore | Select-Object -First 1

    if (-not (Test-Path -LiteralPath $venvPython)) {
        if ($uv) {
            Write-Host "Creating Python virtual environment at '$venvPath' with uv" -ForegroundColor Cyan
            & $uv.Source venv --quiet $venvPath
            if ($LASTEXITCODE) {
                throw "Failed to create Python virtual environment with uv"
            }
        }
        elseif ($python) {
            Write-Host "Creating Python virtual environment at '$venvPath'" -ForegroundColor Cyan
            & $python.Source -m venv $venvPath
            if ($LASTEXITCODE) {
                throw "Failed to create Python virtual environment with '$python'"
            }
        }
        else {
            Write-Warning "Neither uv nor python was found, unit tests that need Python will be skipped"
            return
        }
    }

    Write-Host "Installing Python requirements $($Manifest.PythonRequirements -join ', ')" -ForegroundColor Cyan
    if ($uv) {
        & $uv.Source pip install --quiet --python $venvPython $Manifest.PythonRequirements
    }
    else {
        & $venvPython -m pip install --disable-pip-version-check --quiet $Manifest.PythonRequirements
    }
    if ($LASTEXITCODE) {
        throw "Failed to install Python requirements"
    }

    # Consumed by PSWSMan.Authentication.Tests to find the pyspnego acceptor.
    $env:PSWSMAN_TEST_PYTHON = $venvPython
}

task UnitTests {
    $testsPath = [Path]::Combine($Manifest.TestPath, 'units')
    if (-not (Test-Path -LiteralPath $testsPath)) {
        Write-Host "No unit tests found, skipping" -ForegroundColor Yellow
        return
    }

    # The authentication tests need a KDC, it runs for the whole unit test run.
    Invoke-WithTestKdc {
        Get-ChildItem -LiteralPath $testsPath -Directory | ForEach-Object {
            Write-Host "Running unit tests for $($_.Name)" -ForegroundColor Cyan

            $coveragePath = [Path]::Combine($Manifest.TestResultsPath, "Unit.$($_.Name).Coverage.cobertura.xml")
            $arguments = @(
                'test'
                '--project', $_.FullName
                '--configuration', $Manifest.Configuration
                '--results-directory', $Manifest.TestResultsPath
                '--coverage'
                '--coverage-output', $coveragePath
                '--coverage-settings', $Manifest.TestSettingsPath
            )

            dotnet @arguments
            if ($LASTEXITCODE) {
                throw "Unit tests $($_.Name) failed"
            }
        }
    }
}

task PesterTests {
    $testsPath = [Path]::Combine($Manifest.TestPath, '*.tests.ps1')
    if (-not (Test-Path -Path $testsPath)) {
        Write-Host "No Pester tests found, skipping" -ForegroundColor Yellow
        return
    }

    $dotnetTools = @(dotnet tool list --global) -join "`n"
    if (-not $dotnetTools.Contains('dotnet-coverage')) {
        Write-Host 'Installing dotnet tool dotnet-coverage' -ForegroundColor Yellow
        dotnet tool install --global dotnet-coverage
    }

    $pwsh = Assert-PowerShell -Version $Manifest.PowerShellVersion -Arch $Manifest.PowerShellArch
    $resultsFile = [Path]::Combine($Manifest.TestResultsPath, 'Pester.xml')
    if (Test-Path -LiteralPath $resultsFile) {
        Remove-Item $resultsFile -ErrorAction Stop -Force
    }
    $pesterScript = [Path]::Combine($PSScriptRoot, 'PesterTest.ps1')
    $pwshArguments = @(
        '-NoProfile'
        '-NonInteractive'
        if ($IsWindows) {
            '-ExecutionPolicy', 'Bypass'
        }
        '-File', $pesterScript
        '-TestPath', $Manifest.TestPath
        '-OutputFile', $resultsFile
        '-PesterVersion', $Manifest.PesterVersion
    )

    $watchFolder = [Path]::Combine($Manifest.ReleasePath, 'bin', $Manifest.TestFramework)
    $coveragePath = [Path]::Combine($Manifest.TestResultsPath, "Integration.Coverage.cobertura.xml")
    $pwshHome = Split-Path -Path $pwsh -Parent

    # Our assemblies are the ones with a pdb, the Loader is ALC boilerplate
    # and is excluded. dotnet-coverage collect instruments them for the run
    # with --include-files.
    $includeFiles = @(
        Get-ChildItem -LiteralPath $watchFolder -Filter "*.pdb" |
            Where-Object BaseName -NE "$($Manifest.Module.Name).Loader" |
            ForEach-Object {
                [Path]::Combine($watchFolder, "$($_.BaseName).dll")
            }
    )

    # DoesNotReturnAttribute = AllAssemblies needs the instrumenter to resolve
    # S.M.A next to our assemblies to see any pwsh [DoesNotReturn] attribute,
    # for example Cmdlet.ThrowTerminatingError, and not include the return
    # path as a missed coverage branch. The S.M.A of the pwsh under test is
    # copied there for the run. The module still uses the pwsh copy as the
    # loader only resolves the assemblies in PSWSMan.deps.json, see
    # tests/Alc.Tests.ps1.
    $smaPath = [Path]::Combine($watchFolder, 'System.Management.Automation.dll')

    $arguments = @(
        'collect'
        $pwsh
        $pwshArguments
        '--output', $coveragePath
        '--settings', $Manifest.TestSettingsPath
        foreach ($file in $includeFiles) {
            '--include-files', $file
        }
    )

    $origEnv = $env:PSModulePath
    $origCCache = $env:KRB5CCNAME
    # The Kerberos tests run kinit and kdestroy, a credential cache of their own keeps them away from the user's
    # tickets. Windows keeps its tickets in LSA and the tests do not touch them there.
    $ccachePath = [Path]::Combine($Manifest.TestResultsPath, 'krb5cc')
    try {
        $pwshSma = [Path]::Combine(
            $pwshHome,
            'System.Management.Automation.dll')
        Copy-Item -LiteralPath $pwshSma -Destination $smaPath

        $env:PSModulePath = @(
            [Path]::Combine($pwshHome, "Modules")
            [Path]::Combine($Manifest.OutputPath, "Modules")
        ) -join ([Path]::PathSeparator)
        if (-not $IsWindows) {
            Remove-Item -LiteralPath $ccachePath -Force -ErrorAction Ignore
            $env:KRB5CCNAME = "FILE:$ccachePath"
        }

        dotnet-coverage @arguments
    }
    finally {
        Remove-Item -LiteralPath $smaPath -Force -ErrorAction Ignore
        $env:PSModulePath = $origEnv
        if (-not $IsWindows) {
            $env:KRB5CCNAME = $origCCache
            Remove-Item -LiteralPath $ccachePath -Force -ErrorAction Ignore
        }
    }

    if ($LASTEXITCODE) {
        throw "Pester failed tests"
    }
}

task CoverageReport {
    $dotnetTools = @(dotnet tool list --global) -join "`n"
    if (-not $dotnetTools.Contains('dotnet-reportgenerator-globaltool')) {
        Write-Host 'Installing dotnet tool dotnet-reportgenerator-globaltool' -ForegroundColor Yellow
        dotnet tool install --global dotnet-reportgenerator-globaltool
    }

    $mergedCoveragePath = [Path]::Combine($Manifest.TestResultsPath, "Coverage.cobertura.xml")
    if (Test-Path -LiteralPath $mergedCoveragePath) {
        Remove-Item $mergedCoveragePath -Force
    }

    # ReportGenerator merges the unit test and Pester reports by file and
    # line, keeping the line and branch coverage of both.
    $coverageFiles = Get-ChildItem -Path $Manifest.TestResultsPath -Filter "*.Coverage.cobertura.xml"
    $reportPath = [Path]::Combine($Manifest.TestResultsPath, "CoverageReport")
    $reportArgs = @(
        "-reports:$($coverageFiles.FullName -join ';')"
        "-sourcedirs:$($Manifest.RepositoryPath)/src"
        "-targetdir:$reportPath"
        '-filefilters:-*.g.cs'  # Filter out source generated files
        '-reporttypes:Html_Dark;JsonSummary;Cobertura'
    )
    reportgenerator @reportArgs
    if ($LASTEXITCODE) {
        throw "reportgenerator failed with RC of $LASTEXITCODE"
    }

    $mergedReport = [Path]::Combine($reportPath, 'Cobertura.xml')
    Copy-Item -LiteralPath $mergedReport -Destination $mergedCoveragePath

    $coverageScript = [Path]::Combine($PSScriptRoot, 'CoverageReport.ps1')
    & $coverageScript -Path $mergedCoveragePath
}

#endregion Test

task Build -Jobs Clean, BuildManaged, BuildModule, BuildDocs, Sign, Package

task Test -Jobs TestSetup, PythonSetup, UnitTests, PesterTests, CoverageReport
