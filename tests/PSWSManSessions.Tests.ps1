BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

BeforeAll {
    if ($PSWSManSettings.CACert) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser,
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
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser,
            [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try {
            $store.Remove($PSWSManSettings.CACert)
        }
        finally {
            $store.Dispose()
        }
    }
}

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
        $tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
            EnabledSslProtocols                 = 'Ssl3'
            TargetHost                          = $sessionParams.ComputerName
            RemoteCertificateValidationCallback = New-PSWSManCertValidationCallback { $true }
        }

        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('default')
        $sessionParams.Authentication = 'Credssp'
        $sessionParams.SessionOption = New-PSWSManSessionOption -CredSSPTlsOption $tlsOption

        $out = New-PSSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*CredSSP server did not response to token during the stage TlsHandshake*'
    }

    It "Connects with invalid credential" {
        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('default')
        $sessionParams.Authentication = 'Basic'
        $sessionParams.Credential = [PSCredential]::new('fake', (ConvertTo-SecureString -AsPlainText -Force -String 'fake'))
        $sessionParams.SessionOption = New-PSWSManSessionOption -NoEncryption

        $out = New-PSSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*WinRM authentication failure*'
    }

    It "Connects with invalid hostname and timeout" {
        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('default')
        $sessionParams.Port = 12658
        $sessionParams.SessionOption = New-PSWSManSessionOption -OpenTimeout 1 -NoEncryption
        $out = New-PSSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*A connection could not be established within the configured ConnectTimeout*'
    }

    It "Connects over HTTPS with <AuthMethod>" -Skip:(-not $PSWSManSettings.GetScenarioServer('https_trusted')) -TestCases @(
        @{AuthMethod = "Negotiate" }
        @{AuthMethod = "Ntlm" }
        @{AuthMethod = "CredSSP" }
    ) {
        param ($AuthMethod)

        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_trusted')
        $sessionParams.UseSSL = $true
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

    It "Connects over HTTP with Basic" -Skip:(-not $PSWSManSettings.GetScenarioServer('https_local_auth')) {
        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_local_auth')
        $sessionParams.UseSSL = $true
        $sessionParams.Authentication = 'Basic'

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

    It "Connects over HTTP with Kerberos" -Skip:(-not $PSWSManSettings.GetScenarioServer('https_domain_auth')) {
        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_domain_auth')
        $sessionParams.UseSSL = $true
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

    It "Connects over HTTPS with CBT has <HashType>" -TestCases @(
        @{HashType = "sha1" }
        @{HashType = "sha256" }
        @{HashType = "sha256_pss" }
        @{HashType = "sha384" }
        @{HashType = "sha512" }
        @{HashType = "sha512_pss" }
    ) {
        param ($HashType)

        $server = $PSWSManSettings.GetScenarioServer("https_$HashType")
        if (-not $server) {
            Set-ItResult -Skipped -Because "scenario host for https_$HashType not defined in settings"
        }

        $sessionParams = Get-PSSessionSplat -Server $server
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

    It "Connects over HTTPS with invalid cert - <Method>" -Skip:(-not $PSWSManSettings.GetScenarioServer('https_untrusted')) -TestCases @(
        @{Method = "Skip" }
        @{Method = "TlsOption" }
    ) {
        param ($Method)

        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_untrusted')
        $sessionParams.UseSSL = $true

        $out = New-PSSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*The remote certificate is invalid because of errors in the certificate chain: UntrustedRoot*'

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

    It "Connects over HTTPS with Certificate auth by thumbprint" -Skip:(
        -not $PSWSManSettings.GetScenarioServer('https_trusted') -or
        -not $PSWSManSettings.ClientCertificate
    ) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser,
            [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try {
            $store.Add($PSWSManSettings.ClientCertificate)

            $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_trusted')
            $sessionParams.Remove('Credential')
            $sessionParams.UseSSL = $true
            $sessionParams.CertificateThumbprint = $PSWSManSettings.ClientCertificate.Thumbprint

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
        finally {
            $store.Remove($PSWSManSettings.ClientCertificate)
            $store.Dispose()
        }
    }

    It "Failed to find certificate thumbprint" {
        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('default')
        $sessionParams.Remove('Credential')
        $sessionParams.UseSSL = $true
        $sessionParams.CertificateThumbprint = '0000000000000000000000000000000000000000'

        {
            New-PSSession @sessionParams
        } | Should -Throw "*WinRM failed to find certificate with the thumbprint requested '0000000000000000000000000000000000000000'*"
    }

    It "Connects over HTTPS with Certificate auth by cert object" -Skip:(
        -not $PSWSManSettings.GetScenarioServer('https_trusted') -or
        -not $PSWSManSettings.ClientCertificate
    ) {
        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_trusted')
        $sessionParams.Remove('Credential')
        $sessionParams.UseSSL = $true
        $sessionParams.SessionOption = New-PSWSManSessionOption -ClientCertificate $PSWSManSettings.ClientCertificate

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
        $tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
            EnabledSslProtocols                 = 'Ssl3'
            TargetHost                          = $sessionParams.ComputerName
            RemoteCertificateValidationCallback = New-PSWSManCertValidationCallback { $true }
        }

        $sessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('https_untrusted')
        $sessionParams.UseSSL = $true
        $sessionParams.SessionOption = New-PSWSManSessionOption -TlsOption $tlsOption

        $out = New-PSSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*Authentication failed, see inner exception*'

        # Unfortunately the true error is hidden deep within the stack, nothing we can do about that
        $err[0].Exception.InnerException.InnerException.InnerException.Message | Should -BeLike '*SSL Handshake failed*'
    }
}

Describe "PSWSMan Kerberos tests" -Skip:(-not $PSWSManSettings.GetScenarioServer('domain_auth')) {
    It "Connects with implicit credential" {

    }

    It "Connects with default - no delegation" {

    }

    It "Connects with delegation - implicit cred" {

    }

    It "Connects with delegate - explicit cred" {

    }
}

Describe "PSWSMan Exchange Online tests" -Skip {
    # It "Connects using client secret" {

    # }

    # It "Connects using certificate" {

    # }

    # It "Connects with invalid credential and handles bad response" {

    # }
}

Describe "PSWSMan PSRemoting tests" -Skip:(-not $PSWSManSettings.GetScenarioServer('default')) {
    BeforeEach {
        $SessionParams = Get-PSSessionSplat -Server $PSWSManSettings.GetScenarioServer('default')
    }

    It "Connects to JEA configuration" -Skip:(-not $PSWSManSettings.JEAConfiguration) {
        $SessionParams.ConfigurationName = $PSWSManSettings.JEAConfiguration.Name

        $s = New-PSSession @SessionParams
        try {
            $s.ComputerName | Should -Be $SessionParams.ComputerName
            $s.State | Should -Be 'Opened'
            $s.ConfigurationName | Should -Be $PSWSManSettings.JEAConfiguration.Name
            $out = Invoke-Command -Session $s -ScriptBlock { [Environment]::UserName }
            $out | Should -Be $PSWSManSettings.JEAConfiguration.ExpectedUserName
        }
        finally {
            $s | Remove-PSSession
        }

        $s.State | Should -Be 'Closed'
    }

    It "Connects with large ApplicationArguments data" {
        $appArgs = @{Key = 'a' * 1MB }

        $SessionParams.SessionOption = New-PSWSManSessionOption -ApplicationArguments $appArgs
        $actual = Invoke-Command @sessionparams -ScriptBlock { $PSSenderInfo.ApplicationArguments }

        $actual.Key | Should -Be ('a' * 1MB)
    }

    It "Runs command with large Command data" {

    }

    It "Pipes data into command" {

    }

    It "Responds to user events" {

    }

    It "Exchanges SecureString" {

    }

    It "Sets max runspaces" {

    }

    It "Sets min runspaces" {

    }

    It "Resets runspace" {

    }

    It "Stops a pipeline" {

    }

    It "Gets command metadata" {

    }
}
