. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "PSWSMan Connection tests" -Skip:(-not $PSWSManSettings.GetScenarioServer('default')) {
    It "Connects over HTTP with <AuthMethod>" -TestCases @(
        @{AuthMethod = "Negotiate" }
        @{AuthMethod = "Ntlm" }
        @{AuthMethod = "CredSSP" }
    ) {
        param ($AuthMethod)

        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('default')
        $sessionParams.SessionOption = New-PSWSManSessionOption -AuthMethod $AuthMethod

        $s = New-PSSession @sessionParams
        try {
            $s.ComputerName | Should -Be $sessionParams.ComputerName
            $s.State | Should -Be 'Opened'
            $s.ConfigurationName | Should -Be 'Microsoft.PowerShell'
        }
        finally {
            $s | Remove-PSSession
        }

        $s.State | Should -Be 'Closed'
    }

    It "Fails to connect over HTTP with Basic without -NoEncryption" {
        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('default')
        $sessionParams.SessionOption = New-PSWSManSessionOption -AuthMethod Basic

        { New-PSSession @sessionParams } | Should -Throw '*Cannot perform encryption for BasicAuthProvider*'
    }

    It "Connects over HTTP with Basic" -Skip:(-not $PSWSManSettings.GetScenarioServer('local_auth')) {
        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('local_auth')
        $sessionParams.SessionOption = New-PSWSManSessionOption -AuthMethod Basic -NoEncryption

        $s = New-PSSession @sessionParams
        try {
            $s.ComputerName | Should -Be $sessionParams.ComputerName
            $s.State | Should -Be 'Opened'
            $s.ConfigurationName | Should -Be 'Microsoft.PowerShell'
        }
        finally {
            $s | Remove-PSSession
        }

        $s.State | Should -Be 'Closed'
    }

    It "Connects over HTTP with Kerberos" -Skip:(-not $PSWSManSettings.GetScenarioServer('domain_auth')) {
        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('domain_auth')
        $sessionParams.Authentication = 'Kerberos'

        $s = New-PSSession @sessionParams -Authentication Kerberos
        try {
            $s.ComputerName | Should -Be $sessionParams.ComputerName
            $s.State | Should -Be 'Opened'
            $s.ConfigurationName | Should -Be 'Microsoft.PowerShell'
        }
        finally {
            $s | Remove-PSSession
        }

        $s.State | Should -Be 'Closed'
    }

    It "Connects over CredSSP with handshake failure" {

    }

    It "Connects with invalid credential" {

    }

    It "Connects with invalid hostname and timeout" {

    }

    It "Connects over HTTPS with <AuthMethod>" -Skip:(-not $PSWSManSettings.GetScenarioServer('https_trusted')) -TestCases @(
        @{AuthMethod = "Negotiate" }
        @{AuthMethod = "Ntlm" }
        @{AuthMethod = "CredSSP" }
    ) {
        param ($AuthMethod)

    }

    It "Connects over HTTPS with CBT has <HashType>" -TestCases @(
        @{HashType = "sha256" }
    ) {
        param ($HashType)
    }

    It "Connects over HTTPS with invalid cert - <Method>" -Skip:(-not $PSWSManSettings.GetScenarioServer('https_untrusted')) -TestCases @(
        @{Method = "Skip" }
        @{Method = "TlsOption" }
    ) {
        param ($Method)

        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_untrusted')

        $psoParams = @{}
        if ($Method -eq 'Skip') {
            $psoParams.SkipCACheck = $true
            $psoParams.SkipCNCheck = $true
        }
        else {
            $tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
                TargetHost                          = $sessionParams.ComputerName
                RemoteCertificateValidationCallback = New-PSWSManCertValidationCallback { $true }
            }
            $psoParams.TlsOption = $tlsOption
        }
        $sessionParams.SessionOption = New-PSWSManSessionOption @psoParams
        $sessionParams.UseSSL = $true

        $s = New-PSSession @sessionParams
        try {
            $s.ComputerName | Should -Be $sessionParams.ComputerName
            $s.State | Should -Be 'Opened'
            $s.ConfigurationName | Should -Be 'Microsoft.PowerShell'
        }
        finally {
            $s | Remove-PSSession
        }

        $s.State | Should -Be 'Closed'
    }

    It "Connects over HTTPS with handshake failure" {

    }
}

Describe "PSWSMan Kerberos tests" -Skip:(-not $PSWSManSettings.GetScenarioServer('default')) {
    It "Connects with implicit credential" {

    }

    It "Connects with default - no delegation" {

    }

    It "Connects with delegation - implicit cred" {

    }

    It "Connects with delegate - explicit cred" {

    }
}

Describe "PSWSMan Exchange Online tests" -Skip:(-not $PSWSManSettings.GetScenarioServer('default')) {
    It "Connects using client secret" {

    }

    It "Connects using certificate" {

    }

    It "Connects with invalid credential and handles bad response" {

    }
}

Describe "PSWSMan PSRemoting tests" -Skip:(-not $PSWSManSettings.GetScenarioServer('default')) {
    It "Connects to JEA configuration" {

    }

    It "Connects with large ApplicationArguments data" {

    }

    It "Runs command with large Command data" {

    }
}
