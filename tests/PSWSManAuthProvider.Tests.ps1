BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "Get and Set-PSWSManAuthProvider" {
    It "Gets the default auth provider" {
        $actual = Get-PSWSManAuthProvider
        $actual | Should -Be ([PSWSMan.Shared.AuthenticationProvider]::System)
    }

    It "Sets the default auth provider with WhatIf" {
        Set-PSWSManAuthProvider -AuthProvider Devolutions -WhatIf
        $actual = Get-PSWSManAuthProvider
        $actual | Should -Be ([PSWSMan.Shared.AuthenticationProvider]::System)
    }

    It "Sets the default auth provider" {
        Set-PSWSManAuthProvider -AuthProvider Devolutions
        try {
            $actual = Get-PSWSManAuthProvider
            $actual | Should -Be ([PSWSMan.Shared.AuthenticationProvider]::Devolutions)
        }
        finally {
            Set-PSWSManAuthProvider -AuthProvider System
        }

        $actual = Get-PSWSManAuthProvider
        $actual | Should -Be ([PSWSMan.Shared.AuthenticationProvider]::System)
    }

    It "Fails to set the default auth provider to Default" {
        $out = Set-PSWSManAuthProvider -AuthProvider Default -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*AuthProvider cannot be set to Default, must be System or Devolutions*'
    }
}
