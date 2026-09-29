BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "New-WinRMSessionOption" {
    It "Gets the default options" {
        $actual = New-WinRMSessionOption

        $actual | Should-HaveType ([PSWSMan.WinRMSessionOption])
        $actual.OpenTimeout | Should-Be ([TimeSpan]::FromMinutes(3))
        $actual.OperationTimeout | Should-Be ([TimeSpan]::FromMinutes(3))
        $actual.CancelTimeout | Should-Be ([TimeSpan]::FromMinutes(1))
        $actual.MaxConnectionRetryCount | Should-Be 5
        $actual.Culture | Should-BeNull
        $actual.SkipCACheck | Should-BeFalse
        $actual.AuthMethod | Should-Be ([PSWSMan.AuthenticationMethod]::Default)
    }

    It "Sets the timeouts in milliseconds" {
        $actual = New-WinRMSessionOption -OpenTimeout 1000 -OperationTimeoutMSec 2000 -CancelTimeout 3000

        $actual.OpenTimeout | Should-Be ([TimeSpan]::FromSeconds(1))
        $actual.OperationTimeout | Should-Be ([TimeSpan]::FromSeconds(2))
        $actual.CancelTimeout | Should-Be ([TimeSpan]::FromSeconds(3))
    }

    It "Sets the PSWSMan options" {
        $actual = New-WinRMSessionOption -AuthMethod NTLM -AuthProvider Devolutions -SPNService HTTP -SkipCACheck -RequestKerberosDelegate

        $actual.AuthMethod | Should-Be ([PSWSMan.AuthenticationMethod]::NTLM)
        $actual.AuthProvider | Should-Be ([PSWSMan.AuthenticationProvider]::Devolutions)
        $actual.SPNService | Should-Be HTTP
        $actual.SkipCACheck | Should-BeTrue
        $actual.RequestKerberosDelegate | Should-BeTrue
    }

    It "Resolves a relative TracePath against the current location" {
        Push-Location -LiteralPath TestDrive:\
        try {
            $actual = New-WinRMSessionOption -TracePath trace.log
        }
        finally {
            Pop-Location
        }

        $actual.TracePath | Should-Be ([IO.Path]::Combine((Get-PSDrive -Name TestDrive).Root, 'trace.log'))
    }

    It "Cannot combine TlsOption with the simple TLS options" {
        { New-WinRMSessionOption -TlsOption ([System.Net.Security.SslClientAuthenticationOptions]::new()) -SkipCACheck } |
            Should-Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
    }
}

Describe "WinRMSessionOption conversion to PSSessionOption" {
    It "Converts to a PSSessionOption with the PSWSMan options attached" {
        $option = New-WinRMSessionOption -OperationTimeout 20000 -NoEncryption -Culture en-AU -AuthMethod Kerberos -SPNHostName other.test
        $option.ApplicationArguments = @{ Key = 'value' }

        $actual = [System.Management.Automation.Remoting.PSSessionOption]$option

        $actual | Should-HaveType ([System.Management.Automation.Remoting.PSSessionOption])
        $actual.OperationTimeout | Should-Be ([TimeSpan]::FromSeconds(20))
        $actual.NoEncryption | Should-BeTrue
        $actual.Culture.Name | Should-Be 'en-AU'
        $actual.ApplicationArguments.Key | Should-Be 'value'
        $actual._WinRMSessionOption | Should-HaveType ([PSWSMan.WinRMSessionOption])
        $actual._WinRMSessionOption.AuthMethod | Should-Be ([PSWSMan.AuthenticationMethod]::Kerberos)
        $actual._WinRMSessionOption.SPNHostName | Should-Be other.test
    }

    It "Keeps the TracePath through the conversion" {
        $transformer = [PSWSMan.WinRMSessionOptionTransformAttribute]::new()
        $pso = [System.Management.Automation.Remoting.PSSessionOption](New-WinRMSessionOption -TracePath /tmp/trace.log)

        $transformer.Transform($null, $pso).TracePath | Should-Be ([IO.Path]::GetFullPath('/tmp/trace.log'))
    }

    It "Attaches a copy of the options" {
        $option = New-WinRMSessionOption -AuthMethod Kerberos
        $actual = [System.Management.Automation.Remoting.PSSessionOption]$option
        $option.AuthMethod = 'NTLM'

        $actual._WinRMSessionOption.AuthMethod | Should-Be ([PSWSMan.AuthenticationMethod]::Kerberos)
    }

    It "Is used for the builtin -SessionOption parameters" {
        $cmd = Get-Command -Name New-PSSession
        $cmd.Parameters.SessionOption.ParameterType | Should-Be ([System.Management.Automation.Remoting.PSSessionOption])

        $actual = [System.Management.Automation.LanguagePrimitives]::ConvertTo((New-WinRMSessionOption -SkipCACheck), $cmd.Parameters.SessionOption.ParameterType)
        $actual.SkipCACheck | Should-BeTrue
    }
}

Describe "WinRMSessionOption transformation" {
    BeforeAll {
        $transformer = [PSWSMan.WinRMSessionOptionTransformAttribute]::new()
    }

    It "Passes through a WinRMSessionOption" {
        $option = New-WinRMSessionOption -SkipCNCheck

        $actual = $transformer.Transform($null, $option)

        [object]::ReferenceEquals($actual, $option) | Should-BeTrue
    }

    It "Converts a hashtable" {
        $actual = $transformer.Transform($null, @{
            operationtimeout = 30000
            OpenTimeout = '00:01:00'
            CancelTimeout = [TimeSpan]::FromSeconds(5)
            SkipCACheck = 1
            AuthMethod = 'Kerberos'
            Culture = 'en-AU'
            ApplicationArguments = @{ Key = 'value' }
        })

        $actual | Should-HaveType ([PSWSMan.WinRMSessionOption])
        $actual.OperationTimeout | Should-Be ([TimeSpan]::FromSeconds(30))
        $actual.OpenTimeout | Should-Be ([TimeSpan]::FromMinutes(1))
        $actual.CancelTimeout | Should-Be ([TimeSpan]::FromSeconds(5))
        $actual.SkipCACheck | Should-BeTrue
        $actual.AuthMethod | Should-Be ([PSWSMan.AuthenticationMethod]::Kerberos)
        $actual.Culture.Name | Should-Be 'en-AU'
        $actual.ApplicationArguments.Key | Should-Be 'value'
    }

    It "Converts a PSSessionOption converted from a WinRMSessionOption back" {
        $pso = [System.Management.Automation.Remoting.PSSessionOption](New-WinRMSessionOption -OperationTimeout 20000 -NoMachineProfile -AuthMethod NTLM -SPNService HTTP)
        $pso.OpenTimeout = [TimeSpan]::FromSeconds(5)

        $actual = $transformer.Transform($null, $pso)

        $actual | Should-HaveType ([PSWSMan.WinRMSessionOption])
        $actual.OperationTimeout | Should-Be ([TimeSpan]::FromSeconds(20))
        $actual.OpenTimeout | Should-Be ([TimeSpan]::FromSeconds(5))
        $actual.NoMachineProfile | Should-BeTrue
        $actual.AuthMethod | Should-Be ([PSWSMan.AuthenticationMethod]::NTLM)
        $actual.SPNService | Should-Be HTTP
    }

    It "Converts a plain PSSessionOption <Name>" -ForEach @(
        @{ Name = 'as New-PSSessionOption creates it'; NullObjectSize = $false }
        # New-PSSessionOption on Windows leaves this null rather than the 200MiB class default that the Linux one
        # keeps, both mean it was not set. Covers the Windows shape wherever the tests run.
        @{ Name = 'with a null MaximumReceivedObjectSize'; NullObjectSize = $true }
    ) {
        $option = New-PSSessionOption -SkipCACheck
        $option.OpenTimeout = [TimeSpan]::FromSeconds(10)
        if ($NullObjectSize) {
            $option.MaximumReceivedObjectSize = $null
        }

        $actual = $transformer.Transform($null, $option)

        $actual.SkipCACheck | Should-BeTrue
        $actual.OpenTimeout | Should-Be ([TimeSpan]::FromSeconds(10))
        $actual.AuthMethod | Should-Be ([PSWSMan.AuthenticationMethod]::Default)
    }

    It "Rejects a PSSessionOption with unsupported settings" {
        $option = New-PSSessionOption
        $option.NoCompression = $true
        $option.IdleTimeout = [TimeSpan]::FromMinutes(5)
        # As New-PSSessionOption leaves it on Windows, it must not be reported as set.
        $option.MaximumReceivedObjectSize = $null

        $err = { New-WinRMSession -ComputerName pswsman.invalid -SessionOption $option } | Should-Throw
        $err.FullyQualifiedErrorId | Should-Be 'ParameterArgumentTransformationError,PSWSMan.Commands.NewWinRMSession'
        $err.Exception.Message | Should-BeLikeString '*NoCompression, IdleTimeout which PSWSMan does not support*'
    }

    It "Rejects a PSSessionOption with MaximumReceivedObjectSize set" {
        $option = New-PSSessionOption
        $option.MaximumReceivedObjectSize = 500MB

        $err = { New-WinRMSession -ComputerName pswsman.invalid -SessionOption $option } | Should-Throw
        $err.Exception.Message | Should-BeLikeString '*sets MaximumReceivedObjectSize which PSWSMan does not support*'
    }

    It "Rejects an unknown hashtable key" {
        $err = { Invoke-WinRSCommand -ComputerName pswsman.invalid -Command hostname -SessionOption @{ OpTimeout = 1 } } | Should-Throw
        $err.FullyQualifiedErrorId | Should-Be 'ParameterArgumentTransformationError,PSWSMan.Commands.InvokeWinRSCommand'
        $err.Exception.Message | Should-BeLikeString "*'OpTimeout' is not a WinRM session option*"
    }

    It "Rejects a value that cannot be converted" {
        $err = { New-WinRMSession -ComputerName pswsman.invalid -SessionOption @{ AuthMethod = 'Invalid' } } | Should-Throw
        $err.Exception.Message | Should-BeLikeString "*WinRM session option 'AuthMethod' is not valid*"
    }

    It "Rejects another type" {
        $err = { New-WinRMSession -ComputerName pswsman.invalid -SessionOption 1 } | Should-Throw
        $err.Exception.Message | Should-BeLikeString "*Cannot convert 'System.Int32' to a WinRM session option*"
    }
}
