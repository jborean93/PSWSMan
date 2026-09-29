BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "New-WinRSShell and Remove-WinRSShell" {
    Context "Shells on <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
        BeforeAll {
            # Get-PSSessionSplat skips the test when no server is configured, so each test calls it itself.
            $server = $_

            Function Get-RemoteProcessCount {
                param ($Shell, [string]$Marker)

                # Remote powershell.exe writes its progress to stderr, which the full test run treats as an error.
                $check = "`$ProgressPreference = 'SilentlyContinue'; @(Get-CimInstance Win32_Process -Filter `"Name='powershell.exe'`" | Where-Object CommandLine -like '*$Marker*').Count"
                $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($check))
                Invoke-WinRSCommand -Shell $Shell "powershell.exe -NoProfile -EncodedCommand $encoded" -ErrorAction SilentlyContinue
            }
        }

        It "Creates and removes a shell" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            try {
                $shell | Should-HaveType ([PSWSMan.WinRSRemoteShell])
                $shell.State | Should-Be ([PSWSMan.WinRSShellState]::Opened)
                $shell.ShellId | Should-NotBe ([Guid]::Empty)
                $shell.ComputerName | Should-Be $params.ComputerName
                $shell.ConsoleEncoding.CodePage | Should-Be 65001
            }
            finally {
                Remove-WinRSShell $shell
            }

            $shell.State | Should-Be ([PSWSMan.WinRSShellState]::Closed)
        }

        It "Runs several commands in the same shell" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            try {
                Invoke-WinRSCommand -Shell $shell 'echo first' | Should-Be 'first'
                # WinRS sometimes reports 0 for a process that exits while the stdin close is arriving.
                # We use powershell to ensure stdin is fully closed by the time exit is called.
                Invoke-WinRSCommand -Shell $shell -Command 'powershell.exe -NoProfile -Command "$input | Out-Null; exit 3"'
                $LASTEXITCODE | Should-Be 3
                Invoke-WinRSCommand -Shell $shell 'echo second' | Should-Be 'second'
                $LASTEXITCODE | Should-Be 0
                'input' | Invoke-WinRSCommand -Shell $shell 'findstr .' | Should-Be 'input'
            }
            finally {
                Remove-WinRSShell $shell
            }
        }

        It "Takes the shell as the first positional argument" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            try {
                Invoke-WinRSCommand $shell 'echo positional' | Should-Be 'positional'
            }
            finally {
                Remove-WinRSShell $shell
            }
        }

        It "Runs each command in its own cmd.exe process" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            try {
                Invoke-WinRSCommand -Shell $shell 'set PSWSMAN_TEST=value'

                Invoke-WinRSCommand -Shell $shell 'echo %PSWSMAN_TEST%' | Should-Be '%PSWSMAN_TEST%'
            }
            finally {
                Remove-WinRSShell $shell
            }
        }

        It "Runs commands in parallel in the same shell" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            try {
                $modulePath = [IO.Path]::Combine((Get-Module -Name PSWSMan).ModuleBase, 'PSWSMan.psd1')
                $actual = 1..4 | ForEach-Object -ThrottleLimit 4 -Parallel {
                    Import-Module -Name $using:modulePath
                    Invoke-WinRSCommand -Shell $using:shell "echo $_"
                }

                $actual | Sort-Object | Should-BeCollection @('1', '2', '3', '4')
            }
            finally {
                Remove-WinRSShell $shell
            }
        }

        It "Uses the console encoding of the shell by default" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params -ConsoleEncoding 437
            try {
                $shell.ConsoleEncoding.CodePage | Should-Be 437

                Invoke-WinRSCommand -Shell $shell 'chcp' | Should-BeLikeString '*437*'
            }
            finally {
                Remove-WinRSShell $shell
            }
        }

        It "Copies a file there and back through the shell" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            $remoteName = "PSWSMan-$([Guid]::NewGuid().ToString('N')).txt"
            try {
                $source = Join-Path $TestDrive 'source.txt'
                $back = Join-Path $TestDrive 'back.txt'
                Set-Content -LiteralPath $source -Value 'shell file'

                Send-WinRSFile -Shell $shell $source $remoteName
                Receive-WinRSFile -Shell $shell $remoteName $back

                Get-Content -LiteralPath $back | Should-Be 'shell file'
            }
            finally {
                Invoke-WinRSCommand -Shell $shell "del $remoteName"
                Remove-WinRSShell $shell
            }
        }

        It "Terminates a stopped command and keeps the shell open" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            try {
                # A .NET sleep ignores ctrl_c so the command is only ended by the terminate once the grace period
                # is over.
                $marker = "pswsman-$([Guid]::NewGuid())"
                $sleepCommand = "powershell.exe -NoProfile -Command `"'started'; [Threading.Thread]::Sleep(60000) # $marker`""

                $actual = Invoke-WinRSCommand -Shell $shell $sleepCommand | Select-Object -First 1

                $actual | Should-Be 'started'
                $shell.State | Should-Be ([PSWSMan.WinRSShellState]::Opened)
                $remaining = $null
                foreach ($attempt in 1..10) {
                    $remaining = Get-RemoteProcessCount $shell $marker
                    if ($remaining -eq '0') {
                        break
                    }
                    Start-Sleep -Seconds 1
                }
                $remaining | Should-Be '0'
            }
            finally {
                Remove-WinRSShell $shell
            }
        }

        It "Removes shells from the pipeline" {
            $params = $server | Get-PSSessionSplat
            $shells = 1..2 | ForEach-Object { New-WinRSShell @params }

            $shells | Remove-WinRSShell

            $shells.State | Should-BeCollection @([PSWSMan.WinRSShellState]::Closed, [PSWSMan.WinRSShellState]::Closed)
        }

        It "Does nothing when removing a shell twice" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            Remove-WinRSShell $shell

            Remove-WinRSShell $shell -ErrorVariable err

            $err | Should-BeNull
        }

        It "Does not remove the shell with WhatIf" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            try {
                Remove-WinRSShell $shell -WhatIf

                $shell.State | Should-Be ([PSWSMan.WinRSShellState]::Opened)
            }
            finally {
                Remove-WinRSShell $shell
            }
        }

        It "Fails to use a removed shell with <_>" -ForEach @('Invoke-WinRSCommand', 'Send-WinRSFile', 'Receive-WinRSFile') {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            Remove-WinRSShell $shell
            $cmd = switch ($_) {
                'Invoke-WinRSCommand' { { Invoke-WinRSCommand -Shell $shell 'echo hi' } }
                'Send-WinRSFile' { { Send-WinRSFile -Shell $shell $PSCommandPath 'file.txt' } }
                'Receive-WinRSFile' { { Receive-WinRSFile -Shell $shell 'file.txt' $TestDrive } }
            }

            $err = $cmd | Should-Throw -ExceptionMessage '*has been closed*'
            $err.FullyQualifiedErrorId | Should-BeLikeString "WinRSCommandInvalidParameter,*"
        }

        It "Lists a shell until it is removed" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            try {
                $actual = Get-WinRSShell -ShellId $shell.ShellId

                $actual | Should-BeSame $shell
                @(Get-WinRSShell) | Should-ContainCollection @($shell)
                Get-WinRSShell -ShellId ([Guid]::NewGuid()) | Should-BeNull
            }
            finally {
                Remove-WinRSShell $shell
            }

            Get-WinRSShell -ShellId $shell.ShellId | Should-BeNull
            @(Get-WinRSShell) -contains $shell | Should-BeFalse
        }

        It "Lists shells oldest first" {
            $params = $server | Get-PSSessionSplat
            $shells = 1..2 | ForEach-Object { New-WinRSShell @params }
            try {
                $actual = Get-WinRSShell -ShellId $shells[1].ShellId, $shells[0].ShellId

                $actual.ShellId | Should-BeCollection @($shells[0].ShellId, $shells[1].ShellId)
            }
            finally {
                $shells | Remove-WinRSShell
            }
        }

        It "Filters by computer name" {
            $params = $server | Get-PSSessionSplat
            $shell = New-WinRSShell @params
            try {
                $pattern = $params.ComputerName.Substring(0, 3).ToUpperInvariant() + '*'

                Get-WinRSShell $pattern -ShellId $shell.ShellId | Should-BeSame $shell
                Get-WinRSShell -ComputerName 'pswsman.invalid', $params.ComputerName -ShellId $shell.ShellId | Should-BeSame $shell
                Get-WinRSShell -ComputerName 'pswsman.invalid' -ShellId $shell.ShellId | Should-BeNull
            }
            finally {
                Remove-WinRSShell $shell
            }
        }

        It "Removes the listed shells from the pipeline" {
            $params = $server | Get-PSSessionSplat
            $shells = 1..2 | ForEach-Object { New-WinRSShell @params }

            Get-WinRSShell -ShellId $shells.ShellId | Remove-WinRSShell

            $shells.State | Should-BeCollection @([PSWSMan.WinRSShellState]::Closed, [PSWSMan.WinRSShellState]::Closed)
            Get-WinRSShell -ShellId $shells.ShellId | Should-BeNull
        }

        It "Removes the shell when the runspace that created it closes" {
            $params = $server | Get-PSSessionSplat
            $modulePath = [IO.Path]::Combine((Get-Module -Name PSWSMan).ModuleBase, 'PSWSMan.psd1')
            $ps = [PowerShell]::Create()
            try {
                $null = $ps.AddCommand('Import-Module').AddParameter('Name', $modulePath).AddStatement()
                $null = $ps.AddCommand('New-WinRSShell').AddParameters($params)
                $shell = $ps.Invoke()[0]
                $shell.State | Should-Be ([PSWSMan.WinRSShellState]::Opened)

                # Only listed in the runspace that created it.
                Get-WinRSShell -ShellId $shell.ShellId | Should-BeNull
                $ps.Commands.Clear()
                $listed = $ps.AddCommand('Get-WinRSShell').AddParameter('ShellId', $shell.ShellId).Invoke()
                $listed | Should-BeSame $shell
            }
            finally {
                $ps.Runspace.Dispose()
                $ps.Dispose()
            }

            $shell.State | Should-Be ([PSWSMan.WinRSShellState]::Closed)
        }
    }

    Context "Parameter validation" {
        It "Has the shell at position 0 like the host of the other sets for <_>" -ForEach @('Invoke-WinRSCommand', 'Send-WinRSFile', 'Receive-WinRSFile') {
            $positions = (Get-Command -Name $_).ParameterSets | ForEach-Object {
                $first = $_.Parameters | Where-Object Position -EQ 0
                "$($_.Name)=$($first.Name)"
            }

            $positions | Should-BeCollection @('ComputerName=ComputerName', 'Shell=Shell', 'ConnectionUri=ConnectionUri')
        }

        It "Only takes the shell in the Shell parameter set of <_>" -ForEach @('Invoke-WinRSCommand', 'Send-WinRSFile', 'Receive-WinRSFile') {
            $set = (Get-Command -Name $_).ParameterSets | Where-Object Name -EQ Shell

            $set.Parameters | Where-Object Name -In @('Shell', 'ComputerName', 'ConnectionUri', 'Credential', 'SessionOption', 'Authentication', 'CertificateThumbprint') |
                ForEach-Object Name |
                Should-BeCollection @('Shell')
        }

        It "Lists nothing when no shell matches" {
            Get-WinRSShell -ComputerName 'pswsman.invalid' | Should-BeNull
        }

        It "Fails with a terminating error when the host cannot be reached" {
            $err = { New-WinRSShell -ComputerName 'pswsman.invalid' -ErrorAction Stop } | Should-Throw
            $err.FullyQualifiedErrorId | Should-Be 'WinRSCommandFailed,PSWSMan.Commands.NewWinRSShell'
            $err.TargetObject | Should-Be 'pswsman.invalid'
        }

        It "Fails with a ConnectionUri that is not an absolute http or https URI" {
            $err = { New-WinRSShell -ConnectionUri 'ftp://pswsman.invalid' } | Should-Throw -ExceptionMessage '*must be an absolute http or https URI*'
            $err.FullyQualifiedErrorId | Should-Be 'WinRSCommandInvalidParameter,PSWSMan.Commands.NewWinRSShell'
        }
    }
}
