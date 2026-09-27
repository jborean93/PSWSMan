BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

    # Shared with the PSWSMan.Lib unit tests, running each line here checks their expected values are right.
    $sharedCases = Get-Content -LiteralPath ([IO.Path]::Combine($PSScriptRoot, 'data', 'WinRSCommandLine.json')) -Raw |
        ConvertFrom-Json -AsHashtable
    $commandLineCases = foreach ($case in $sharedCases.cases) {
        $case + @{ file_path = $sharedCases.file_path }
    }
}

Describe "ConvertTo-WinRSCommandLine" {
    Context "Shared cases" {
        It "Builds <name>" -ForEach $commandLineCases {
            $actual = ConvertTo-WinRSCommandLine -FilePath $file_path -ArgumentList $arguments

            $actual | Should-Be $expected
        }
    }

    Context "Parameters" {
        It "Takes the file path and arguments by position" {
            $actual = ConvertTo-WinRSCommandLine app.exe 'a b', c

            $actual | Should-Be '"^"app.exe^" ^"a b^" c"'
        }

        It "Takes the remaining arguments as the argument list" {
            $actual = ConvertTo-WinRSCommandLine app.exe 'a b' c -x /y

            $actual | Should-Be '"^"app.exe^" ^"a b^" c -x /y"'
        }

        It "Builds the line without arguments" {
            $actual = ConvertTo-WinRSCommandLine app.exe

            $actual | Should-Be '"^"app.exe^""'
        }

        It "Accepts an empty argument list" {
            $actual = ConvertTo-WinRSCommandLine app.exe -ArgumentList @()

            $actual | Should-Be '"^"app.exe^""'
        }

        It "Skips null arguments and keeps empty strings" {
            $actual = ConvertTo-WinRSCommandLine app.exe -ArgumentList @('arg1', '', $null, "")

            $actual | Should-Be '"^"app.exe^" arg1 ^"^" ^"^""'
        }

        It "Skips a null remaining argument" {
            $actual = ConvertTo-WinRSCommandLine app.exe a $(if ($false) { '-v' }) b

            $actual | Should-Be '"^"app.exe^" a b"'
        }

        It "Builds the line without arguments when every argument is null" {
            $actual = ConvertTo-WinRSCommandLine app.exe -ArgumentList $null

            $actual | Should-Be '"^"app.exe^""'
        }

        It "Converts non-string arguments to strings" {
            $actual = ConvertTo-WinRSCommandLine app.exe 1 $true

            $actual | Should-Be '"^"app.exe^" 1 True"'
        }

        It "Rejects a file path with <Name>" -ForEach @(
            @{ Name = 'a double quote'; Value = 'C:\a"b.exe' }
            @{ Name = 'a line feed'; Value = "app`n.exe" }
        ) {
            { ConvertTo-WinRSCommandLine -FilePath $Value } |
                Should-Throw -ExceptionMessage '*The file path must not contain*' -ExceptionType ([ArgumentException])
        }

        It "Rejects an argument with <Name>" -ForEach @(
            @{ Name = 'a carriage return'; Value = "a`rb" }
            @{ Name = 'a line feed'; Value = "a`nb" }
            @{ Name = 'a null character'; Value = "a`0b" }
        ) {
            $err = { ConvertTo-WinRSCommandLine app.exe ok $Value } |
                Should-Throw -ExceptionMessage '*An argument must not contain*' -ExceptionType ([ArgumentException])
            $err.FullyQualifiedErrorId | Should-Be 'WinRSCommandLineInvalidArgument,PSWSMan.Commands.ConvertToWinRSCommandLine'
        }
    }

    Context "Running the command line on <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
        BeforeAll {
            $server = $_
            $exePath = (Get-Content -LiteralPath ([IO.Path]::Combine($PSScriptRoot, 'data', 'WinRSCommandLine.json')) -Raw |
                ConvertFrom-Json).file_path
            $exeCreated = $false
            $params = @{}

            if ($server.Uri) {
                $params = $server | Get-PSSessionSplat

                # The shared cases use a path relative to the working directory of the shell, the user profile, so
                # the exact expected line including the escaped file path runs here. Its directory name has
                # characters cmd.exe interprets outside of quotes.
                $source = Get-Content -LiteralPath ([IO.Path]::Combine($PSScriptRoot, 'data', 'print_argv.cs')) -Raw
                $pathB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($exePath))
                $script = @"
`$ErrorActionPreference = 'Stop'
`$exe = Join-Path (Get-Location).ProviderPath ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$pathB64')))
`$null = New-Item -ItemType Directory -Path (Split-Path -LiteralPath `$exe) -Force
`$source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($source)))'))
Add-Type -OutputType ConsoleApplication -OutputAssembly `$exe -TypeDefinition `$source
"@
                Invoke-WinRSCommand @params -Command (Get-PowerShellCommand -Script $script)
                $exeCreated = $true
            }
        }

        AfterAll {
            if ($exeCreated) {
                $dirB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($exePath.Substring(0, $exePath.LastIndexOf('\'))))
                $script = "Remove-Item -LiteralPath ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$dirB64'))) -Recurse -Force"
                Invoke-WinRSCommand @params -Command (Get-PowerShellCommand -Script $script)
            }
        }

        It "Gives the process the arguments of <name>" -ForEach $commandLineCases {
            $null = $server | Get-PSSessionSplat
            $actual = (Invoke-WinRSCommand @params -Command $expected) -join "`n" | ConvertFrom-Json

            $expectedJson = ConvertTo-Json -InputObject ([string[]]$arguments) -Compress
            ConvertTo-Json -InputObject ([string[]]$actual.Args) -Compress | Should-Be $expectedJson -Because '.NET argv'
            ConvertTo-Json -InputObject ([string[]]$actual.Argv) -Compress | Should-Be $expectedJson -Because 'CommandLineToArgvW'
        }
    }
}
