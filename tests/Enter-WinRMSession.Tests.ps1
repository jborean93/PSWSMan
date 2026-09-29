BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

BeforeAll {
    if (-not ('PSWSManTests.RecordingHost' -as [type])) {
        Add-Type -Path ([IO.Path]::Combine($PSScriptRoot, 'data', 'RecordingHost.cs'))
    }
}

Describe "Enter-WinRMSession" {
    Context "Entering a session on <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
        BeforeAll {
            $server = $_
        }

        It "Pushes the session and closes it on Exit-PSSession" {
            $params = $server | Get-PSSessionSplat
            $pushed = $null
            try {
                Enter-WinRMSession @params
                $Host.IsRunspacePushed | Should-BeTrue
                $pushed = $Host.Runspace
                $pushed.RunspaceStateInfo.State | Should-Be Opened
                $pushed.ConnectionInfo | Should-HaveType ([PSWSMan.CustomTransport.WinRMConnectionInfo])

                # Exit-PSSession runs in the remote session like it does when typed at the remote prompt, the pop
                # comes back as a host call that closes the runspace Enter-WinRMSession created.
                $ps = [PowerShell]::Create()
                try {
                    $ps.Runspace = $pushed
                    $actual = $ps.AddScript('hostname.exe; Exit-PSSession').Invoke()
                    [string]::IsNullOrWhiteSpace($actual) | Should-BeFalse
                }
                finally {
                    $ps.Dispose()
                }

                # The pop and close are handled on the thread that received the host call, which can still be
                # closing the runspace when Invoke returns.
                $wait = [System.Diagnostics.Stopwatch]::StartNew()
                while ($pushed.RunspaceStateInfo.State -ne 'Closed' -and $wait.Elapsed.TotalSeconds -lt 30) {
                    Start-Sleep -Milliseconds 50
                }
                $Host.IsRunspacePushed | Should-BeFalse
                $pushed.RunspaceStateInfo.State | Should-Be Closed
            }
            finally {
                if ($Host.IsRunspacePushed) {
                    $Host.PopRunspace()
                }
                if ($pushed) {
                    $pushed.Dispose()
                }
            }
        }

        It "Closes the session when the host fails to push it" {
            $params = $server | Get-PSSessionSplat
            $inner = [PSWSManTests.RecordingHost]::new()
            $inner.PushException = [InvalidOperationException]::new('push failed')
            $rs = [RunspaceFactory]::CreateRunspace($inner)
            $rs.Open()
            $ps = [PowerShell]::Create()
            $ps.Runspace = $rs
            try {
                $null = $ps.AddScript({
                        param ($ModulePath, $Params)
                        Import-Module -Name $ModulePath
                        Enter-WinRMSession @Params
                    }).AddArgument([IO.Path]::Combine((Get-Module -Name PSWSMan).ModuleBase, 'PSWSMan.psd1')).
                    AddArgument($params)
                $null = $ps.Invoke()

                $ps.Streams.Error.Count | Should-Be 1
                $ps.Streams.Error[0].Exception.GetBaseException().Message | Should-Be 'push failed'
                $inner.PushedRunspace.ConnectionInfo | Should-HaveType ([PSWSMan.CustomTransport.WinRMConnectionInfo])
                $inner.PushedRunspace.RunspaceStateInfo.State | Should-Be Closed
            }
            finally {
                $ps.Dispose()
                $rs.Dispose()
            }
        }

        It "Writes an error for an unknown configuration" {
            $params = $server | Get-PSSessionSplat
            Enter-WinRMSession @params -ConfigurationName PSWSMan.Missing -ErrorAction SilentlyContinue -ErrorVariable err

            $Host.IsRunspacePushed | Should-BeFalse
            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRMSessionOpenFailed,PSWSMan.Commands.EnterWinRMSession'
            $err[0].TargetObject | Should-Be $params.ComputerName
        }
    }

    Context "Parameter validation" {
        It "Fails before connecting when the host cannot enter a session" {
            # A PowerShell instance without a runspace of its own gets the default host, which cannot push one.
            $ps = [PowerShell]::Create()
            try {
                $null = $ps.AddScript({
                        param ($ModulePath)
                        Import-Module -Name $ModulePath
                        Enter-WinRMSession -ComputerName pswsman.invalid
                    }).AddArgument([IO.Path]::Combine((Get-Module -Name PSWSMan).ModuleBase, 'PSWSMan.psd1'))

                $null = $ps.Invoke()

                # Only the host error, a connection attempt to the invalid host would add an open failure.
                $ps.Streams.Error.Count | Should-Be 1
                $ps.Streams.Error[0].FullyQualifiedErrorId |
                    Should-Be 'HostDoesNotSupportPushRunspace,PSWSMan.Commands.EnterWinRMSession'
            }
            finally {
                $ps.Dispose()
            }
        }

        It "Fails before connecting from a nested prompt" {
            # Entering a nested prompt sets $NestedPromptLevel, which is what the cmdlet checks.
            $err = {
                $NestedPromptLevel = 1
                Enter-WinRMSession -ComputerName pswsman.invalid
            } | Should-Throw

            $err.FullyQualifiedErrorId | Should-Be 'HostInNestedPrompt,PSWSMan.Commands.EnterWinRMSession'
            $Host.IsRunspacePushed | Should-BeFalse
        }

        It "Writes an error when the host cannot be reached" {
            Enter-WinRMSession -ComputerName pswsman.invalid -ErrorAction SilentlyContinue -ErrorVariable err

            $Host.IsRunspacePushed | Should-BeFalse
            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRMSessionOpenFailed,PSWSMan.Commands.EnterWinRMSession'
            $err[0].TargetObject | Should-Be 'pswsman.invalid'
        }

        It "Writes an error for a ConnectionUri that is not http or https" {
            Enter-WinRMSession -ConnectionUri 'ftp://pswsman.invalid/wsman' -ErrorAction SilentlyContinue -ErrorVariable err

            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRMSessionInvalidParameter,PSWSMan.Commands.EnterWinRMSession'
        }

        It "Rejects a credential with a certificate thumbprint" {
            $cred = [PSCredential]::new('user', (ConvertTo-SecureString -AsPlainText -Force 'pass'))
            $err = { Enter-WinRMSession -ComputerName pswsman.invalid -UseSSL -Credential $cred -CertificateThumbprint abc } | Should-Throw
            $err.FullyQualifiedErrorId | Should-Be 'WinRMSessionInvalidParameter,PSWSMan.Commands.EnterWinRMSession'
        }

        It "Stops a connection that is still being made" {
            # See the New-WinRMSession test of the same name for why a loopback listener that never accepts is used.
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $rs = [RunspaceFactory]::CreateRunspace($Host)
            $rs.Open()
            $ps = [PowerShell]::Create()
            $ps.Runspace = $rs
            try {
                $uri = "http://127.0.0.1:$($listener.LocalEndpoint.Port)/wsman"
                $cred = [PSCredential]::new('user', (ConvertTo-SecureString -AsPlainText -Force 'pass'))
                $null = $ps.AddScript({
                        param ($ModulePath, $Uri, $Credential)
                        Import-Module -Name $ModulePath
                        'starting'
                        Enter-WinRMSession -ConnectionUri $Uri -Authentication Basic -Credential $Credential -SessionOption @{ NoEncryption = $true }
                    }).AddArgument([IO.Path]::Combine((Get-Module -Name PSWSMan).ModuleBase, 'PSWSMan.psd1')).
                    AddArgument($uri).AddArgument($cred)
                $output = [System.Management.Automation.PSDataCollection[PSObject]]::new()
                $task = $ps.BeginInvoke([System.Management.Automation.PSDataCollection[PSObject]]$null, $output)

                $wait = [System.Diagnostics.Stopwatch]::StartNew()
                while ($output.Count -eq 0 -and -not $task.IsCompleted -and $wait.Elapsed.TotalSeconds -lt 60) {
                    Start-Sleep -Milliseconds 50
                }
                $output[0] | Should-Be 'starting'
                Start-Sleep -Seconds 2
                $task.IsCompleted | Should-BeFalse

                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $ps.Stop()
                $null = $task.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(60))
                $sw.Elapsed.TotalSeconds | Should-BeLessThan 30
                $task.IsCompleted | Should-BeTrue
                $ps.InvocationStateInfo.State | Should-Be Stopped
                $Host.IsRunspacePushed | Should-BeFalse
            }
            finally {
                $ps.Dispose()
                $rs.Dispose()
                $listener.Stop()
            }
        }
    }
}
