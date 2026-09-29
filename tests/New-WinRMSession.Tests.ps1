BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "New-WinRMSession" {
    Context "Sessions on each server" {
        It "Opens a session, runs a command and removes it - <_.Name>" -ForEach (Get-PSWSManTestServer) {
            $params = $_ | Get-PSSessionSplat
            $session = New-WinRMSession @params
            try {
                $session | Should-HaveType ([System.Management.Automation.Runspaces.PSSession])
                $session.State | Should-Be Opened
                $session.Transport | Should-Be PSWSMan
                $session.Runspace.ConnectionInfo | Should-HaveType ([PSWSMan.CustomTransport.WinRMConnectionInfo])

                $actual = Invoke-Command -Session $session -ScriptBlock { hostname.exe }
                [string]::IsNullOrWhiteSpace($actual) | Should-BeFalse
            }
            finally {
                Remove-PSSession -Session $session
            }

            $session.State | Should-Be Closed
        }
    }

    Context "Session behaviour on <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
        BeforeAll {
            # Get-PSSessionSplat skips the test when no server is configured, so each test calls it itself.
            $server = $_
        }

        It "Sets the session name" {
            $params = $server | Get-PSSessionSplat
            $session = New-WinRMSession @params -Name winrm-test
            try {
                $session.Name | Should-Be winrm-test
                (Get-PSSession -Name winrm-test).Id | Should-Be $session.Id
            }
            finally {
                Remove-PSSession -Session $session
            }
        }

        It "Sends application arguments larger than one envelope" {
            $params = $server | Get-PSSessionSplat -SessionOption @{
                ApplicationArguments = @{ Big = 'a' * 300000 }
            }
            $session = New-WinRMSession @params
            try {
                $actual = Invoke-Command -Session $session -ScriptBlock { $PSSenderInfo.ApplicationArguments.Big.Length }
                $actual | Should-Be 300000
            }
            finally {
                Remove-PSSession -Session $session
            }
        }

        It "Sends and receives data larger than one envelope" {
            $params = $server | Get-PSSessionSplat
            $session = New-WinRMSession @params
            try {
                $actual = Invoke-Command -Session $session -ScriptBlock { param ($Value) $Value.Length } -ArgumentList ('b' * 1000000)
                $actual | Should-Be 1000000

                $actual = Invoke-Command -Session $session -ScriptBlock { 'c' * 2000000 }
                $actual.Length | Should-Be 2000000

                $actual = 1..5 | Invoke-Command -Session $session -ScriptBlock { $input | Measure-Object -Sum | ForEach-Object Sum }
                $actual | Should-Be 15
            }
            finally {
                Remove-PSSession -Session $session
            }
        }

        It "Copies files to and from the session" {
            # Copy-Item drives the session through its own remote helper functions and streams the file content in
            # chunks, a different path through the transport than a plain command. The large file spans many
            # envelopes in both directions.
            $params = $server | Get-PSSessionSplat
            $session = New-WinRMSession @params
            $remotePath = $null
            try {
                # $TestDrive rather than TestDrive: as the .NET file APIs need the file system path.
                $source = Join-Path $TestDrive copy-source
                $null = New-Item -ItemType Directory -Path (Join-Path $source nested) -Force
                [IO.File]::WriteAllText((Join-Path $source small.txt), 'small text')
                $bytes = [byte[]]::new(3MB)
                [Random]::new(0).NextBytes($bytes)
                [IO.File]::WriteAllBytes((Join-Path $source nested/large.bin), $bytes)

                $remotePath = Invoke-Command -Session $session -ScriptBlock {
                    Join-Path $env:TEMP "pswsman-copy-$([Guid]::NewGuid())"
                }
                Copy-Item -LiteralPath $source -Destination $remotePath -ToSession $session -Recurse

                $remoteFiles = Invoke-Command -Session $session -ScriptBlock {
                    Get-ChildItem -LiteralPath $using:remotePath -Recurse -File |
                        Sort-Object -Property Name |
                        ForEach-Object { "$($_.Name) $($_.Length)" }
                }
                $remoteFiles | Should-BeCollection @('large.bin 3145728', 'small.txt 10')

                $destination = Join-Path $TestDrive copy-destination
                Copy-Item -LiteralPath $remotePath -Destination $destination -FromSession $session -Recurse

                foreach ($relative in 'small.txt', 'nested/large.bin') {
                    $expected = (Get-FileHash -LiteralPath (Join-Path $source $relative)).Hash
                    (Get-FileHash -LiteralPath (Join-Path $destination $relative)).Hash | Should-Be $expected
                }
            }
            finally {
                if ($remotePath) {
                    Invoke-Command -Session $session -ScriptBlock {
                        Remove-Item -LiteralPath $using:remotePath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
                Remove-PSSession -Session $session
            }
        }

        It "Applies the culture options" {
            $params = $server | Get-PSSessionSplat
            $params.SessionOption = @{ Culture = 'de-DE'; UICulture = 'fr-FR' }
            if ($server.UntrustedCertificate) {
                $params.SessionOption.SkipCACheck = $true
                $params.SessionOption.SkipCNCheck = $true
            }
            $session = New-WinRMSession @params
            try {
                $actual = Invoke-Command -Session $session -ScriptBlock { "$((Get-Culture).Name) $((Get-UICulture).Name)" }
                $actual | Should-Be 'de-DE fr-FR'
            }
            finally {
                Remove-PSSession -Session $session
            }
        }

        It "Stops a running command and keeps the session usable" {
            $params = $server | Get-PSSessionSplat
            $session = New-WinRMSession @params
            try {
                $job = Invoke-Command -Session $session -ScriptBlock { Start-Sleep -Seconds 60 } -AsJob
                Start-Sleep -Seconds 2
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $job | Stop-Job
                $sw.Elapsed.TotalSeconds | Should-BeLessThan 30
                $job | Remove-Job -Force

                Invoke-Command -Session $session -ScriptBlock { 'after stop' } | Should-Be 'after stop'
            }
            finally {
                Remove-PSSession -Session $session
            }
        }

        It "Prefers -Authentication over the session option AuthMethod" {
            $params = $server | Get-PSSessionSplat -SessionOption @{ AuthMethod = 'Basic' }
            $session = New-WinRMSession @params -Authentication Negotiate
            try {
                # The server reports the authentication it accepted, Negotiate shows as the protocol it picked.
                $actual = Invoke-Command -Session $session -ScriptBlock { $PSSenderInfo.UserInfo.Identity.AuthenticationType }
                $actual -in 'Kerberos', 'NTLM' | Should-BeTrue -Because "the server reported '$actual'"
            }
            finally {
                Remove-PSSession -Session $session
            }
        }

        It "Supports implicit remoting with Import-PSSession" {
            # Implicit remoting, like Enter-PSSession, opens a command with GET_COMMAND_METADATA rather than
            # CREATE_PIPELINE. It runs in its own runspace so a regression fails the test rather than hanging the run.
            $params = $server | Get-PSSessionSplat
            $session = New-WinRMSession @params
            $ps = [PowerShell]::Create()
            try {
                $null = $ps.AddScript({
                        param ($Session)
                        $null = Import-PSSession -Session $Session -CommandName Get-Date -Prefix PSWSManRemote -AllowClobber
                        (Get-PSWSManRemoteDate).GetType().Name
                    }).AddArgument($session)
                $task = $ps.BeginInvoke()
                $completed = $task.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(60))
                if (-not $completed) {
                    $ps.Stop()
                }

                $completed | Should-BeTrue
                $ps.Streams.Error | Should-BeNull
                $ps.EndInvoke($task) | Should-Be 'DateTime'
            }
            finally {
                $ps.Dispose()
                Remove-PSSession -Session $session
            }
        }

        It "Writes the connection trace to the TracePath file" {
            $tracePath = Join-Path TestDrive: winrm-trace.log
            $params = $server | Get-PSSessionSplat
            $params.SessionOption = [PSWSMan.WinRMSessionOptionTransformAttribute]::new().Transform($null, $params.SessionOption ?? @{})
            $params.SessionOption.TracePath = $tracePath

            $session = New-WinRMSession @params
            try {
                Invoke-Command -Session $session -ScriptBlock { 'traced' } | Should-Be 'traced'
            }
            finally {
                Remove-PSSession -Session $session
            }

            $lines = Get-Content -LiteralPath $tracePath
            $lines.Count | Should-BeGreaterThan 0
            # The line format is documented for filtering, the message text is not.
            $lines | Where-Object { $_ -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2} \[\d+\] ' } | Should-BeNull
            $packets = $lines | Where-Object { $_ -match 'PSWSMan OutOfProc Packet \[[^\]]+\] (Sent|Received): <' }
            @($packets).Count | Should-BeGreaterThan 0
        }

        It "Handles a remote Clear-Host when the host <Name>" -TestCases @(
            @{ Name = 'does not implement SetBufferContents'; ThrowOnClear = $true }
            @{ Name = 'implements SetBufferContents'; ThrowOnClear = $false }
        ) {
            # Get-PSSessionSplat skips the test when no server is configured, the child process reads the settings
            # file itself and would fail instead.
            $null = $server | Get-PSSessionSplat

            # This process has Enable-PSWSMan, whose patch also turns the not implemented failure into a clear, so the
            # session runs in a child process without it. Its stdout is captured so Console.Clear() is skipped there.
            $script = {
                param ($ModulePath, $StubPath, $SettingsPath, $ServerName, $ThrowOnClear)

                $ErrorActionPreference = 'Stop'
                Add-Type -Path $StubPath
                $entry = (Get-Content -LiteralPath $SettingsPath -Raw | ConvertFrom-Json).servers |
                    Where-Object name -EQ $ServerName
                $cred = [PSCredential]::new($entry.username,
                    (ConvertTo-SecureString -AsPlainText -Force $entry.password))
                # The same as Get-PSSessionSplat does for an entry marked untrusted_certificate.
                $sessionOption = @{}
                if ($entry.untrusted_certificate) {
                    $sessionOption.SkipCACheck = $true
                    $sessionOption.SkipCNCheck = $true
                }

                $stub = [PSWSManTests.RecordingHost]::new($ThrowOnClear)
                $rs = [RunspaceFactory]::CreateRunspace($stub)
                $rs.Open()
                $ps = [PowerShell]::Create()
                $ps.Runspace = $rs
                $null = $ps.AddScript({
                        param ($ModulePath, $Uri, $Credential, $SessionOption)
                        Import-Module -Name $ModulePath
                        $session = New-WinRMSession -ConnectionUri $Uri -Credential $Credential -SessionOption $SessionOption
                        try {
                            $remote = [PowerShell]::Create()
                            $remote.Runspace = $session.Runspace
                            [PSCustomObject]@{
                                Output = @($remote.AddScript('Clear-Host; "cleared"').Invoke())
                                Errors = @($remote.Streams.Error | ForEach-Object ToString)
                            }
                            $remote.Dispose()
                        }
                        finally {
                            Remove-PSSession -Session $session
                        }
                    }).AddArgument($ModulePath).AddArgument($entry.url).AddArgument($cred).AddArgument($sessionOption)
                $result = $ps.Invoke()

                [PSCustomObject]@{
                    Output = $result.Output
                    Errors = @($result.Errors) + @($ps.Streams.Error | ForEach-Object ToString)
                    Cleared = @($stub.Calls -like 'SetBufferContents(-1,-1,-1,-1,*')
                }
            }
            $modulePath = [IO.Path]::Combine((Get-Module -Name PSWSMan).ModuleBase, 'PSWSMan.psd1')
            $stubPath = [IO.Path]::Combine($PSScriptRoot, 'data', 'RecordingHost.cs')
            $settingsPath = [IO.Path]::Combine($PSScriptRoot, '..', 'test.settings.json')

            # A scriptblock is sent as -EncodedCommand, the arguments and output go between the processes as CLIXML.
            # It only works with the scriptblock and -args written out, not splatted.
            $actual = & ([Environment]::ProcessPath) -NoProfile -NonInteractive $script -args $modulePath, $stubPath, $settingsPath, $server.Name, $ThrowOnClear
            $LASTEXITCODE | Should-Be 0

            $actual.Errors | Should-BeNull
            $actual.Output | Should-Be 'cleared'
            @($actual.Cleared).Count | Should-Be 1
        }

        It "Fails to open an unknown configuration" {
            $params = $server | Get-PSSessionSplat
            $err = { New-WinRMSession @params -ConfigurationName PSWSMan.Missing -ErrorAction Stop } | Should-Throw
            $err.FullyQualifiedErrorId | Should-Be 'WinRMSessionOpenFailed,PSWSMan.Commands.NewWinRMSession'
        }
    }

    Context "Multiple sessions on <_.Name>" -ForEach (Get-PSWSManTestServer -Auth NTLM -First) {
        BeforeAll {
            $server = $_
        }

        It "Opens a session for each host and reports the ones that fail" {
            # The name and the IP address are two hosts as far as the cmdlet is concerned, Negotiate falls back to
            # NTLM for the address.
            $byName = $server | Get-PSSessionSplat
            $params = $server | Get-PSSessionSplat -UseIPAddress
            $params.ComputerName = $byName.ComputerName, $params.ComputerName, 'pswsman.invalid'

            $sessions = New-WinRMSession @params -Name first, second, third -ErrorAction SilentlyContinue -ErrorVariable err
            try {
                $sessions.Count | Should-Be 2
                ($sessions | Sort-Object Name).Name | Should-BeCollection first, second
                $err.Count | Should-Be 1
                $err[0].FullyQualifiedErrorId | Should-Be 'WinRMSessionOpenFailed,PSWSMan.Commands.NewWinRMSession'
                $err[0].TargetObject | Should-Be 'pswsman.invalid'

                $actual = Invoke-Command -Session $sessions -ScriptBlock { $env:COMPUTERNAME }
                $actual.Count | Should-Be 2
            }
            finally {
                $sessions | Remove-PSSession
            }
        }

        It "Takes the hosts from the pipeline with a throttle limit of 1" {
            $byName = $server | Get-PSSessionSplat
            $params = $server | Get-PSSessionSplat -UseIPAddress
            $computerNames = $byName.ComputerName, $params.ComputerName
            $params.Remove('ComputerName')

            $sessions = $computerNames | New-WinRMSession @params -ThrottleLimit 1
            try {
                $sessions.Count | Should-Be 2
                $sessions.State | Should-BeCollection Opened, Opened
            }
            finally {
                $sessions | Remove-PSSession
            }
        }
    }

    Context "Parameter validation" {
        It "Writes an error when the host cannot be reached" {
            $actual = New-WinRMSession -ComputerName pswsman.invalid -ErrorAction SilentlyContinue -ErrorVariable err
            $actual | Should-BeNull
            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRMSessionOpenFailed,PSWSMan.Commands.NewWinRMSession'
            $err[0].TargetObject | Should-Be 'pswsman.invalid'
        }

        It "Reports why the connection could not be set up" {
            # The options are rejected before anything is sent, the reason is the error message rather than a
            # generic PowerShell error with the reason in an inner exception.
            $cred = [PSCredential]::new('user', (ConvertTo-SecureString -AsPlainText -Force 'pass'))
            $actual = New-WinRMSession -ComputerName pswsman.invalid -Authentication Basic -Credential $cred -ErrorAction SilentlyContinue -ErrorVariable err

            $actual | Should-BeNull
            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRMSessionOpenFailed,PSWSMan.Commands.NewWinRMSession'
            $err[0].Exception | Should-HaveType ([System.Management.Automation.Remoting.PSRemotingTransportException])
            $err[0].Exception.Message | Should-BeLikeString '*does not support message encryption*'
            $err[0].Exception.InnerException | Should-HaveType ([ArgumentException])
        }

        It "Writes an error for a ConnectionUri that is not http or https" {
            $actual = New-WinRMSession -ConnectionUri 'ftp://pswsman.invalid/wsman' -ErrorAction SilentlyContinue -ErrorVariable err
            $actual | Should-BeNull
            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRMSessionInvalidParameter,PSWSMan.Commands.NewWinRMSession'
        }

        It "Stops a connection that is still being made" {
            # A listener that never accepts is a black hole on every host: the OS completes the TCP handshake from
            # its backlog so the first request goes out and then waits for a response that never comes. A remote
            # address is not reliable for this, some networks reject it straight away. Basic auth with a dummy
            # credential sends the request without needing Kerberos or NTLM on the host.
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $ps = [PowerShell]::Create()
            try {
                $uri = "http://127.0.0.1:$($listener.LocalEndpoint.Port)/wsman"
                $cred = [PSCredential]::new('user', (ConvertTo-SecureString -AsPlainText -Force 'pass'))
                $null = $ps.AddScript({
                        param ($ModulePath, $Uri, $Credential)
                        Import-Module -Name $ModulePath
                        'starting'
                        New-WinRMSession -ConnectionUri $Uri -Authentication Basic -Credential $Credential -SessionOption @{ NoEncryption = $true }
                    }).AddArgument([IO.Path]::Combine((Get-Module -Name PSWSMan).ModuleBase, 'PSWSMan.psd1')).
                    AddArgument($uri).AddArgument($cred)
                $output = [System.Management.Automation.PSDataCollection[PSObject]]::new()
                $task = $ps.BeginInvoke([System.Management.Automation.PSDataCollection[PSObject]]$null, $output)

                # Importing the module in the new runspace can take a while on a slow or instrumented host, only
                # the connection itself should be running when it is stopped.
                $wait = [System.Diagnostics.Stopwatch]::StartNew()
                while ($output.Count -eq 0 -and -not $task.IsCompleted -and $wait.Elapsed.TotalSeconds -lt 60) {
                    Start-Sleep -Milliseconds 50
                }
                $output[0] | Should-Be 'starting'
                Start-Sleep -Seconds 2
                # Still waiting for the server, otherwise the stop below has nothing to interrupt.
                $task.IsCompleted | Should-BeFalse

                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $ps.Stop()
                $null = $task.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(60))
                $sw.Elapsed.TotalSeconds | Should-BeLessThan 30
                $task.IsCompleted | Should-BeTrue
                $ps.InvocationStateInfo.State | Should-Be Stopped
            }
            finally {
                $ps.Dispose()
                $listener.Stop()
            }
        }

        It "Rejects a credential with a certificate thumbprint" {
            $cred = [PSCredential]::new('user', (ConvertTo-SecureString -AsPlainText -Force 'pass'))
            $err = { New-WinRMSession -ComputerName pswsman.invalid -UseSSL -Credential $cred -CertificateThumbprint abc } | Should-Throw
            $err.FullyQualifiedErrorId | Should-Be 'WinRMSessionInvalidParameter,PSWSMan.Commands.NewWinRMSession'
        }
    }
}
