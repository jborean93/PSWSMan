BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "New-PSWSManSessionOption" {
    It "Gets a default session object" {
        $actual = New-PSWSManSessionOption
        $actual | Should-HaveType ([System.Management.Automation.Remoting.PSSessionOption])
        $actual._PSWSManSessionOption | Should-HaveType ([PSWSMan.PSWSManSessionOption])
    }
}
