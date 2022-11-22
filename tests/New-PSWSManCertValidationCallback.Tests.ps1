BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

BeforeAll {
    if ($PSWSManSettings.CACert) {
        $location = if ($IsWindows) {
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        }
        else {
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        }
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            $location,
            [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try {
            $store.Add($PSWSManSettings.CACert)
        }
        finally {
            $store.Dispose()
        }
    }
}

AfterAll {
    if ($PSWSManSettings.CACert) {
        $location = if ($IsWindows) {
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        }
        else {
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        }
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            $location,
            [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try {
            $store.Remove($PSWSManSettings.CACert)
        }
        finally {
            $store.Dispose()
        }
    }
}

Describe "New-PSWSManCertValidationCallback" -Skip:(-not $PSWSManSettings.GetScenarioServer("https_trusted")) {

    It "Connects over HTTPS with success delegate" {
        $server = $PSWSManSettings.GetScenarioServer('https_trusted')

        $state = @{}
        $delegate = New-PSWSManCertValidationCallback -ScriptBlock {
            $state = $using:state
            $state['args'] = $args

            $true
        }
        $tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
            TargetHost                          = $server.HostName
            RemoteCertificateValidationCallback = $delegate
        }

        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_trusted')
        $sessionParams.UseSSL = $true
        $sessionParams.SessionOption = New-PSWSManSessionOption -TlsOption $tlsOption

        $actual = Invoke-Command @sessionParams -ScriptBlock { 'test' }
        $actual | Should -Be test

        $state['args'].Count | Should -Be 4
        $state['args'][0] | Should -BeOfType ([System.Net.Security.SslStream])
        $state['args'][0].TargetHostName | Should -Be $server.HostName
        $state['args'][1] | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Certificate])
        $state['args'][2] | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Chain])
        $state['args'][3] | Should -Be ([System.Net.Security.SslPolicyErrors]::None)
    }

    It "Connects over HTTPS with false delegate" {
        $server = $PSWSManSettings.GetScenarioServer('https_trusted')

        $state = @{}
        $delegate = New-PSWSManCertValidationCallback -ScriptBlock {
            $state = $using:state
            $state['args'] = $args

            $false
        }
        $tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
            TargetHost                          = $server.HostName
            RemoteCertificateValidationCallback = $delegate
        }

        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_trusted')
        $sessionParams.UseSSL = $true
        $sessionParams.SessionOption = New-PSWSManSessionOption -TlsOption $tlsOption

        $out = Invoke-Command @sessionParams -ScriptBlock { 'test' } -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -Be $null
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*The remote certificate was rejected by the provided RemoteCertificateValidationCallback*'

        $state['args'].Count | Should -Be 4
        $state['args'][0] | Should -BeOfType ([System.Net.Security.SslStream])
        $state['args'][0].TargetHostName | Should -Be $server.HostName
        $state['args'][1] | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Certificate])
        $state['args'][2] | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Chain])
        $state['args'][3] | Should -Be ([System.Net.Security.SslPolicyErrors]::None)
    }

    It "Treats no output as a failed check" {
        $server = $PSWSManSettings.GetScenarioServer('https_trusted')

        $state = @{}
        $delegate = New-PSWSManCertValidationCallback -ScriptBlock {
            $state = $using:state
            $state['args'] = $args
        }
        $tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
            TargetHost                          = $server.HostName
            RemoteCertificateValidationCallback = $delegate
        }

        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_trusted')
        $sessionParams.UseSSL = $true
        $sessionParams.SessionOption = New-PSWSManSessionOption -TlsOption $tlsOption

        $out = Invoke-Command @sessionParams -ScriptBlock { 'test' } -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -Be $null
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*The remote certificate was rejected by the provided RemoteCertificateValidationCallback*'

        $state['args'].Count | Should -Be 4
        $state['args'][0] | Should -BeOfType ([System.Net.Security.SslStream])
        $state['args'][0].TargetHostName | Should -Be $server.HostName
        $state['args'][1] | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Certificate])
        $state['args'][2] | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Chain])
        $state['args'][3] | Should -Be ([System.Net.Security.SslPolicyErrors]::None)
    }

    It "Fails to cast the last output to a bool and fail the delegate" {
        $server = $PSWSManSettings.GetScenarioServer('https_trusted')

        $state = @{}
        $delegate = New-PSWSManCertValidationCallback -ScriptBlock {
            $state = $using:state
            $state['args'] = $args

            # Only the last output is used and is considered $false if it's not a bool
            $true
            "will fail"
        }
        $tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
            TargetHost                          = $server.HostName
            RemoteCertificateValidationCallback = $delegate
        }

        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_trusted')
        $sessionParams.UseSSL = $true
        $sessionParams.SessionOption = New-PSWSManSessionOption -TlsOption $tlsOption

        $out = Invoke-Command @sessionParams -ScriptBlock { 'test' } -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -Be $null
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*The remote certificate was rejected by the provided RemoteCertificateValidationCallback*'

        $state['args'].Count | Should -Be 4
        $state['args'][0] | Should -BeOfType ([System.Net.Security.SslStream])
        $state['args'][0].TargetHostName | Should -Be $server.HostName
        $state['args'][1] | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Certificate])
        $state['args'][2] | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Chain])
        $state['args'][3] | Should -Be ([System.Net.Security.SslPolicyErrors]::None)
    }
}
