BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "Invoke-WinRMCommand" {
    Context "ArgumentList transform" {
        BeforeAll {
            $transformer = [PSWSMan.ArgumentsOrParametersTransformAttribute]::new()
        }

        It "Uses an array as positional arguments" {
            $actual = $transformer.Transform($null, @('one', 2, $null))

            $actual.Arguments | Should-BeCollection @('one', 2, $null)
            $actual.Parameters.Count | Should-Be 0
        }

        It "Uses a dictionary as named parameters in its order" {
            $actual = $transformer.Transform($null, [ordered]@{ Second = 2; First = 'one' })

            $actual.Arguments.Count | Should-Be 0
            $actual.Parameters.Key | Should-BeCollection @('Second', 'First')
            $actual.Parameters.Value | Should-BeCollection @(2, 'one')
        }

        It "Uses a single value as one positional argument" {
            $actual = $transformer.Transform($null, 'scalar')

            $actual.Arguments | Should-BeCollection @('scalar')
        }

        It "Uses a dictionary inside an array as a positional argument" {
            $actual = $transformer.Transform($null, [PSObject](, @{ Key = 'value' }))

            $actual.Arguments.Count | Should-Be 1
            $actual.Arguments[0] | Should-HaveType ([hashtable])
            $actual.Parameters.Count | Should-Be 0
        }

        It "Keeps null as no arguments" {
            $transformer.Transform($null, $null) | Should-BeNull
        }
    }

    Context "Parameter validation" {
        It "Has a FilePath variant of each target" {
            $sets = (Get-Command -Name Invoke-WinRMCommand).ParameterSets
            $sets.Name | Should-BeCollection @(
                'ComputerName', 'FilePathComputerName', 'ConnectionUri', 'FilePathConnectionUri', 'Session', 'FilePathSession'
            )
            ($sets | Where-Object Name -EQ FilePathComputerName).Parameters.Name | Should-ContainCollection @('Credential', 'Port', 'UseSSL')
            ($sets | Where-Object Name -EQ FilePathSession).Parameters.Name | Should-NotContainCollection @('Credential', 'ConfigurationName')
        }

        It "Writes an error when the host cannot be reached" {
            $actual = Invoke-WinRMCommand -ComputerName pswsman.invalid -ScriptBlock { 1 } -ErrorAction SilentlyContinue -ErrorVariable err

            $actual | Should-BeNull
            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRMCommandOpenFailed,PSWSMan.Commands.InvokeWinRMCommand'
            $err[0].TargetObject | Should-Be 'pswsman.invalid'
        }

        It "Writes an error for a ConnectionUri that is not http or https" {
            Invoke-WinRMCommand -ConnectionUri 'ftp://pswsman.invalid/wsman' -ScriptBlock { 1 } -ErrorAction SilentlyContinue -ErrorVariable err

            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRMCommandInvalidParameter,PSWSMan.Commands.InvokeWinRMCommand'
        }

        It "Requires UseSSL for a certificate thumbprint with <Name>" -TestCases @(
            @{ Name = 'ScriptBlock'; Params = @{ ScriptBlock = { 1 } } }
            @{ Name = 'FilePath'; Params = @{ FilePath = $PSCommandPath } }
        ) {
            $err = { Invoke-WinRMCommand -ComputerName pswsman.invalid -CertificateThumbprint abc @Params } | Should-Throw

            $err.FullyQualifiedErrorId | Should-Be 'WinRMCommandInvalidParameter,PSWSMan.Commands.InvokeWinRMCommand'
        }

        It "Fails for a FilePath that does not exist" {
            $path = Join-Path TestDrive: missing.ps1
            $err = { Invoke-WinRMCommand -ComputerName pswsman.invalid -FilePath $path } | Should-Throw

            $err.FullyQualifiedErrorId | Should-Be 'WinRMCommandFilePathNotFound,PSWSMan.Commands.InvokeWinRMCommand'
        }

        It "Fails for a FilePath that is not on the file system" {
            $err = { Invoke-WinRMCommand -ComputerName pswsman.invalid -FilePath Env:PATH } | Should-Throw

            $err.FullyQualifiedErrorId | Should-Be 'WinRMCommandFilePathNotFileSystem,PSWSMan.Commands.InvokeWinRMCommand'
        }

        It "Fails for a FilePath with a syntax error" {
            $path = Join-Path TestDrive: invalid.ps1
            Set-Content -LiteralPath $path -Value 'if ('
            $err = { Invoke-WinRMCommand -ComputerName pswsman.invalid -FilePath $path } | Should-Throw

            $err.FullyQualifiedErrorId | Should-Be 'WinRMCommandFilePathParseError,PSWSMan.Commands.InvokeWinRMCommand'
        }

        It "Fails before connecting for an undefined using variable" {
            $err = { Invoke-WinRMCommand -ComputerName pswsman.invalid -ScriptBlock { $using:undefinedVariable } } | Should-Throw

            $err.FullyQualifiedErrorId | Should-Be 'UsingVariableIsUndefined,PSWSMan.Commands.InvokeWinRMCommand'
        }

        It "Stops a connection that is still being made" {
            # See the New-WinRMSession test of the same name for why a loopback listener that never accepts is used.
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
                        Invoke-WinRMCommand -ConnectionUri $Uri -Authentication Basic -Credential $Credential -SessionOption @{ NoEncryption = $true } -ScriptBlock { 1 }
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
            }
            finally {
                $ps.Dispose()
                $listener.Stop()
            }
        }
    }

    Context "Commands on <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
        BeforeAll {
            $server = $_
        }

        It "Outputs the result with the properties Invoke-Command adds" {
            $params = $server | Get-PSSessionSplat
            $actual = Invoke-WinRMCommand @params -ScriptBlock { $env:COMPUTERNAME }

            $actual | Should-Be ([string]$actual)
            [string]::IsNullOrWhiteSpace($actual) | Should-BeFalse
            $actual.PSComputerName | Should-Be $params.ComputerName
            $actual.PSShowComputerName | Should-BeTrue
            $actual.RunspaceId | Should-HaveType ([guid])
        }

        It "Hides the computer name" {
            $params = $server | Get-PSSessionSplat
            $actual = Invoke-WinRMCommand @params -ScriptBlock { 1 } -HideComputerName

            $actual.PSShowComputerName | Should-BeFalse
            $actual.PSComputerName | Should-Be $params.ComputerName
        }

        It "Passes <Name>" -TestCases @(
            @{ Name = 'positional arguments'; ArgumentList = @('one', 'two'); Expected = 'one|two|' }
            @{ Name = 'named parameters'; ArgumentList = @{ Second = 'two'; First = 'one' }; Expected = 'one|two|' }
            @{ Name = 'a single value'; ArgumentList = 'one'; Expected = 'one||' }
        ) {
            $params = $server | Get-PSSessionSplat
            $actual = Invoke-WinRMCommand @params -ArgumentList $ArgumentList -ScriptBlock {
                param ($First, $Second, [switch]$Force)

                "$First|$Second|$(if ($Force) { $Force })"
            }

            $actual | Should-Be $Expected
        }

        It "Binds a switch parameter from <Name> like splatting" -TestCases @(
            @{ Name = '$true'; ArgumentList = @{ Force = $true }; Expected = 'IsPresent=True Bound=True' }
            @{ Name = '$false'; ArgumentList = @{ Force = $false }; Expected = 'IsPresent=False Bound=True' }
            @{ Name = '[switch]::Present'; ArgumentList = @{ Force = [switch]::Present }; Expected = 'IsPresent=True Bound=True' }
            @{ Name = '[switch]$false'; ArgumentList = @{ Force = [switch]$false }; Expected = 'IsPresent=False Bound=True' }
            @{ Name = 'an omitted key'; ArgumentList = @{ Name = 'other' }; Expected = 'IsPresent=False Bound=False' }
        ) {
            $params = $server | Get-PSSessionSplat
            $actual = Invoke-WinRMCommand @params -ArgumentList $ArgumentList -ScriptBlock {
                param ([string]$Name, [switch]$Force)

                "IsPresent=$($Force.IsPresent) Bound=$($PSBoundParameters.ContainsKey('Force'))"
            }

            $actual | Should-Be $Expected
        }

        It "Passes a dictionary inside an array as a positional argument" {
            $params = $server | Get-PSSessionSplat
            $actual = Invoke-WinRMCommand @params -ArgumentList @(@{ Key = 'value' }) -ScriptBlock {
                param ($Value)

                "$($Value.GetType().Name) $($Value.Key)"
            }

            $actual | Should-Be 'Hashtable value'
        }

        It "Sends using values" {
            $params = $server | Get-PSSessionSplat
            $value = 'using value'
            $obj = [PSCustomObject]@{ Member = 'member value' }
            $list = 'first', 'second'

            $actual = Invoke-WinRMCommand @params -ScriptBlock {
                $using:value
                $using:obj.Member
                $using:list[1]
            }

            $actual | Should-BeCollection @('using value', 'member value', 'second')
        }

        It "Sends pipeline input" {
            $params = $server | Get-PSSessionSplat
            $actual = 1..3 | Invoke-WinRMCommand @params -ScriptBlock { $input | ForEach-Object { $_ * 10 } }

            $actual | Should-BeCollection @(10, 20, 30)
        }

        It "Sends InputObject as one object" {
            $params = $server | Get-PSSessionSplat
            $actual = Invoke-WinRMCommand @params -InputObject (1, 2, 3) -ScriptBlock { @($input).Count }

            $actual | Should-Be 1
        }

        It "Ends the input when there is none" {
            $params = $server | Get-PSSessionSplat
            $actual = Invoke-WinRMCommand @params -ScriptBlock { @($input).Count }

            $actual | Should-Be 0
        }

        It "Writes remote errors with the host they came from" {
            $params = $server | Get-PSSessionSplat
            $actual = Invoke-WinRMCommand @params -ScriptBlock {
                Write-Error 'remote error'
                'after error'
            } -ErrorAction SilentlyContinue -ErrorVariable err

            $actual | Should-Be 'after error'
            $err.Count | Should-Be 1
            $err[0] | Should-HaveType ([System.Management.Automation.Runspaces.RemotingErrorRecord])
            [string]$err[0] | Should-Be 'remote error'
            $err[0].OriginInfo.PSComputerName | Should-Be $params.ComputerName
        }

        It "Rethrows a remote throw statement for a single <Name>" -TestCases @(
            @{ Name = 'host' }
            @{ Name = 'session' }
        ) {
            # Like Invoke-Command a remote throw ends the calling script when there is one target, -ErrorAction does
            # not apply to it.
            $params = $server | Get-PSSessionSplat
            $session = $null
            if ($Name -eq 'session') {
                $session = New-WinRMSession @params
                $params = @{ Session = $session }
            }
            try {
                $output = [System.Collections.Generic.List[object]]::new()
                $err = {
                    Invoke-WinRMCommand @params -ErrorAction SilentlyContinue -ScriptBlock {
                        'before'
                        throw 'remote throw'
                        'after'
                    } | ForEach-Object { $output.Add($_) }
                } | Should-Throw

                $output | Should-BeCollection @('before')
                $err.Exception | Should-HaveType ([System.Management.Automation.RemoteException])
                $err.Exception.Message | Should-Be 'remote throw'
                $err.Exception.WasThrownFromThrowStatement | Should-BeTrue
            }
            finally {
                if ($session) {
                    Remove-PSSession -Session $session
                }
            }
        }

        It "Writes a remote terminating error that is not a throw statement as an error" {
            $params = $server | Get-PSSessionSplat
            $actual = Invoke-WinRMCommand @params -ScriptBlock {
                'before'
                Get-Item -LiteralPath C:\pswsman-missing -ErrorAction Stop
                'after'
            } -ErrorAction SilentlyContinue -ErrorVariable err

            $actual | Should-Be 'before'
            $err.Count | Should-Be 1
            $err[0] | Should-HaveType ([System.Management.Automation.Runspaces.RemotingErrorRecord])
            $err[0].OriginInfo.PSComputerName | Should-Be $params.ComputerName
        }

        It "Adds remote warnings to WarningVariable" {
            $params = $server | Get-PSSessionSplat
            $null = Invoke-WinRMCommand @params -ScriptBlock { Write-Warning 'first' } -WarningVariable warnings
            $null = Invoke-WinRMCommand @params -ScriptBlock { Write-Warning 'second' } -WarningVariable +warnings

            $warnings.Count | Should-Be 2
            $warnings[0] | Should-HaveType ([System.Management.Automation.WarningRecord])
            $warnings.Message | Should-BeCollection @('first', 'second')
        }

        It "Writes remote information records once" {
            $params = $server | Get-PSSessionSplat
            $null = Invoke-WinRMCommand @params -ScriptBlock {
                Write-Host 'host message'
                Write-Information 'information message'
            } -InformationVariable info -InformationAction SilentlyContinue

            $info.Count | Should-Be 2
            $info[0] | Should-HaveType ([System.Management.Automation.Runspaces.RemotingInformationRecord])
            [string]$info[0].MessageData | Should-Be 'host message'
            # The host already showed Write-Host through the remote host call, the tag keeps it from showing again.
            $info[0].Tags | Should-ContainCollection @('PSHOST', 'FORWARDED')
            [string]$info[1].MessageData | Should-Be 'information message'
            $info[1].OriginInfo.PSComputerName | Should-Be $params.ComputerName
        }

        It "Runs a script from FilePath with arguments and using values" {
            $params = $server | Get-PSSessionSplat
            $path = Join-Path TestDrive: remote.ps1
            Set-Content -LiteralPath $path -Value 'param ($Name) "$Name $using:value"'
            $value = 'using value'

            $actual = Invoke-WinRMCommand @params -FilePath $path -ArgumentList @{ Name = 'named' }

            $actual | Should-Be 'named using value'
        }

        It "Runs the command in a session and keeps its state" {
            $params = $server | Get-PSSessionSplat
            $session = New-WinRMSession @params
            try {
                Invoke-WinRMCommand -Session $session -ScriptBlock { $global:pswsmanTest = 'kept' }
                $actual = Invoke-WinRMCommand -Session $session -ScriptBlock { $global:pswsmanTest }

                $actual | Should-Be 'kept'
                $actual.PSComputerName | Should-Be $session.ComputerName
                $actual.RunspaceId | Should-Be $session.Runspace.InstanceId
            }
            finally {
                Remove-PSSession -Session $session
            }

            Invoke-WinRMCommand -Session $session -ScriptBlock { 1 } -ErrorAction SilentlyContinue -ErrorVariable err
            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRMCommandSessionNotOpen,PSWSMan.Commands.InvokeWinRMCommand'
        }

        It "Stops a running command and keeps the session usable" {
            $params = $server | Get-PSSessionSplat
            $session = New-WinRMSession @params
            $rs = [RunspaceFactory]::CreateRunspace($Host)
            $rs.Open()
            $ps = [PowerShell]::Create()
            $ps.Runspace = $rs
            try {
                $null = $ps.AddScript({
                        param ($ModulePath, $Session)
                        Import-Module -Name $ModulePath
                        Invoke-WinRMCommand -Session $Session -ScriptBlock { 'started'; Start-Sleep -Seconds 60; 'finished' }
                    }).AddArgument([IO.Path]::Combine((Get-Module -Name PSWSMan).ModuleBase, 'PSWSMan.psd1')).
                    AddArgument($session)
                $output = [System.Management.Automation.PSDataCollection[PSObject]]::new()
                $task = $ps.BeginInvoke([System.Management.Automation.PSDataCollection[PSObject]]$null, $output)

                # Enumerating the output would block until the command finishes, only its count is checked.
                $wait = [System.Diagnostics.Stopwatch]::StartNew()
                while ($output.Count -eq 0 -and -not $task.IsCompleted -and $wait.Elapsed.TotalSeconds -lt 60) {
                    Start-Sleep -Milliseconds 50
                }
                $output.Count | Should-Be 1
                $output[0] | Should-Be 'started'

                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $ps.Stop()
                $null = $task.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(60))
                $sw.Elapsed.TotalSeconds | Should-BeLessThan 30
                $ps.InvocationStateInfo.State | Should-Be Stopped
                # Nothing after the stop, the remote command never reached 'finished'.
                $output.Count | Should-Be 1

                Invoke-WinRMCommand -Session $session -ScriptBlock { 'after stop' } | Should-Be 'after stop'
            }
            finally {
                $ps.Dispose()
                $rs.Dispose()
                Remove-PSSession -Session $session
            }
        }
    }

    Context "Commands on several hosts through <_.Name>" -ForEach (Get-PSWSManTestServer -Auth NTLM -First) {
        BeforeAll {
            $server = $_
        }

        It "Runs the command on each host with a throttle limit of <ThrottleLimit> and reports the ones that fail" -TestCases @(
            @{ ThrottleLimit = 32 }
            @{ ThrottleLimit = 1 }
        ) {
            # The name and the IP address are two hosts as far as the cmdlet is concerned, Negotiate falls back to
            # NTLM for the address.
            $byName = $server | Get-PSSessionSplat
            $params = $server | Get-PSSessionSplat -UseIPAddress
            $params.ComputerName = $byName.ComputerName, $params.ComputerName, 'pswsman.invalid'

            $actual = Invoke-WinRMCommand @params -ThrottleLimit $ThrottleLimit -ScriptBlock { $env:COMPUTERNAME } -ErrorAction SilentlyContinue -ErrorVariable err

            $actual.Count | Should-Be 2
            ($actual.PSComputerName | Sort-Object) | Should-BeCollection (@($byName.ComputerName, $params.ComputerName[1]) | Sort-Object)
            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRMCommandOpenFailed,PSWSMan.Commands.InvokeWinRMCommand'
            $err[0].TargetObject | Should-Be 'pswsman.invalid'
        }

        It "Writes a remote throw statement as an error of each host" {
            $byName = $server | Get-PSSessionSplat
            $params = $server | Get-PSSessionSplat -UseIPAddress
            $params.ComputerName = $byName.ComputerName, $params.ComputerName

            $actual = Invoke-WinRMCommand @params -ScriptBlock {
                'before'
                throw 'remote throw'
            } -ErrorAction SilentlyContinue -ErrorVariable err

            $actual | Should-BeCollection @('before', 'before')
            $err.Count | Should-Be 2
            $err | ForEach-Object { [string]$_ | Should-Be 'remote throw' }
            ($err.OriginInfo.PSComputerName | Sort-Object) | Should-BeCollection ($params.ComputerName | Sort-Object)
        }
    }
}
