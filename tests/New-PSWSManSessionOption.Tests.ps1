BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "New-PSWSManSessionOption" {
    It "Gets a default session object" {
        $actual = New-PSWSManSessionOption
        $actual | Should -BeOfType ([System.Management.Automation.Remoting.PSSessionOption])
        $actual._PSWSManSessionOption | Should -BeOfType ([PSWSMan.PSWSManSessionOption])
    }
}
