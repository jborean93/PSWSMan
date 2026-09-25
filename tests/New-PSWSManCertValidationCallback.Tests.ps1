using namespace System.Linq.Expressions
using namespace System.Net.Security
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

BeforeAll {
    # A throwaway self signed certificate that only ever exists in memory.
    $rsa = [RSA]::Create(2048)
    $request = [CertificateRequest]::new('CN=PSWSMan Test', $rsa, 'SHA256', [RSASignaturePadding]::Pkcs1)
    $cert = $request.CreateSelfSigned((Get-Date).AddDays(-1), (Get-Date).AddDays(1))
    $chain = [X509Chain]::new()
    $null = $chain.Build($cert)

    Function Invoke-CertValidationCallback {
        <#
        .SYNOPSIS
        Invokes the callback the way a TLS handshake does.

        .DESCRIPTION
        The connection code runs the callback from a thread pool thread that
        has no default runspace, so the callback has to bring its own. The
        arguments are bound into a compiled delegate because a script block
        cannot run on such a thread.
        #>
        [OutputType([bool])]
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [RemoteCertificateValidationCallback]
            $Callback,

            [object]
            $SenderObj = 'sender',

            [X509Certificate]
            $Certificate = $cert,

            [X509Chain]
            $Chain = $chain,

            [SslPolicyErrors]
            $SslPolicyErrors = [SslPolicyErrors]::None
        )

        $invoke = [Expression]::Invoke(
            [Expression]::Constant($Callback),
            [Expression]::Constant($SenderObj, [object]),
            [Expression]::Constant($Certificate, [X509Certificate]),
            [Expression]::Constant($Chain, [X509Chain]),
            [Expression]::Constant($SslPolicyErrors))
        $func = [Expression]::Lambda([Func[bool]], $invoke).Compile()

        [System.Threading.Tasks.Task[bool]]::Run($func).GetAwaiter().GetResult()
    }
}

Describe "New-PSWSManCertValidationCallback" {
    It "Creates a RemoteCertificateValidationCallback" {
        $actual = New-PSWSManCertValidationCallback -ScriptBlock { $true }

        $actual | Should -BeOfType ([RemoteCertificateValidationCallback])
    }

    It "Passes the arguments to the script block with <SslPolicyErrors>" -TestCases @(
        @{ SslPolicyErrors = [SslPolicyErrors]::None }
        @{ SslPolicyErrors = [SslPolicyErrors]::RemoteCertificateChainErrors }
        @{ SslPolicyErrors = [SslPolicyErrors]::RemoteCertificateNameMismatch }
        @{ SslPolicyErrors = [SslPolicyErrors]::RemoteCertificateNotAvailable }
        @{ SslPolicyErrors = [SslPolicyErrors]'RemoteCertificateChainErrors, RemoteCertificateNameMismatch' }
    ) {
        $state = @{}
        $callback = New-PSWSManCertValidationCallback -ScriptBlock {
            $state = $using:state
            $state['args'] = $args

            $true
        }

        $actual = Invoke-CertValidationCallback -Callback $callback -SslPolicyErrors $SslPolicyErrors

        $actual | Should -BeTrue
        $state['args'].Count | Should -Be 4
        $state['args'][0] | Should -Be 'sender'
        $state['args'][1] | Should -BeOfType ([X509Certificate])
        $state['args'][1].Thumbprint | Should -Be $cert.Thumbprint
        $state['args'][2] | Should -BeOfType ([X509Chain])
        $state['args'][2].ChainStatus.Status | Should -Contain ([X509ChainStatusFlags]::UntrustedRoot)
        $state['args'][3] | Should -Be $SslPolicyErrors
    }

    It "Runs on a thread without a default runspace" {
        $testRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace.Id
        $testThread = [Environment]::CurrentManagedThreadId

        $state = @{}
        $callback = New-PSWSManCertValidationCallback -ScriptBlock {
            $state = $using:state
            $state['runspace'] = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace.Id
            $state['thread'] = [Environment]::CurrentManagedThreadId

            $true
        }

        $actual = Invoke-CertValidationCallback -Callback $callback

        $actual | Should -BeTrue
        $state['runspace'] | Should -Not -Be $testRunspace
        $state['thread'] | Should -Not -Be $testThread
    }

    It "Uses a value captured with using" {
        $expected = [SslPolicyErrors]::RemoteCertificateNameMismatch
        $callback = New-PSWSManCertValidationCallback -ScriptBlock {
            param ($Sender, $Certificate, $Chain, $SslPolicyErrors)

            $SslPolicyErrors -eq $using:expected
        }

        Invoke-CertValidationCallback -Callback $callback -SslPolicyErrors $expected | Should -BeTrue
        Invoke-CertValidationCallback -Callback $callback -SslPolicyErrors None | Should -BeFalse
    }

    It "Returns <Expected> when the script block outputs <Expected>" -TestCases @(
        @{ Expected = $true }
        @{ Expected = $false }
    ) {
        $callback = New-PSWSManCertValidationCallback -ScriptBlock { $using:Expected }

        Invoke-CertValidationCallback -Callback $callback | Should -Be $Expected
    }

    It "Treats no output as a failed check" {
        $callback = New-PSWSManCertValidationCallback -ScriptBlock { }

        Invoke-CertValidationCallback -Callback $callback | Should -BeFalse
    }

    It "Uses only the last output" {
        $callback = New-PSWSManCertValidationCallback -ScriptBlock {
            $false
            $true
        }

        Invoke-CertValidationCallback -Callback $callback | Should -BeTrue
    }

    It "Treats a last output that is not a bool as a failed check" {
        $callback = New-PSWSManCertValidationCallback -ScriptBlock {
            $true
            'will fail'
        }

        Invoke-CertValidationCallback -Callback $callback | Should -BeFalse
    }

    It "Invokes a function provided through the function drive" {
        Function Test-CertValidation {
            param ($Sender, $Certificate, $Chain, $SslPolicyErrors)

            $state = $using:state
            $state['file'] = $MyInvocation.MyCommand.ScriptBlock.Ast.Extent.File
            $state['thumbprint'] = $Certificate.Thumbprint

            $SslPolicyErrors -eq [SslPolicyErrors]::RemoteCertificateChainErrors
        }

        $state = @{}
        $callback = New-PSWSManCertValidationCallback -ScriptBlock ${function:Test-CertValidation}

        $actual = Invoke-CertValidationCallback -Callback $callback -SslPolicyErrors RemoteCertificateChainErrors

        $actual | Should -BeTrue
        $state['thumbprint'] | Should -Be $cert.Thumbprint
        $state['file'] | Should -Be $PSCommandPath
    }

    It "Preserves the script block source location" {
        $state = @{}
        $scriptBlock = {
            $state = $using:state
            $state['extent'] = $MyInvocation.MyCommand.ScriptBlock.Ast.Extent

            $true
        }
        $callback = New-PSWSManCertValidationCallback -ScriptBlock $scriptBlock

        $actual = Invoke-CertValidationCallback -Callback $callback

        $actual | Should -BeTrue
        $state['extent'].File | Should -Be $PSCommandPath
        $state['extent'].StartLineNumber | Should -Be $scriptBlock.Ast.Extent.StartLineNumber
        $state['extent'].StartColumnNumber | Should -Be $scriptBlock.Ast.Extent.StartColumnNumber
        $state['extent'].Text | Should -Be $scriptBlock.Ast.Extent.Text
    }

    It "Invokes a script block created from a string" {
        $callback = New-PSWSManCertValidationCallback -ScriptBlock ([scriptblock]::Create('$args[3] -eq "None"'))

        Invoke-CertValidationCallback -Callback $callback | Should -BeTrue
    }

    It "Raises a script block error to the caller" {
        $callback = New-PSWSManCertValidationCallback -ScriptBlock { throw 'validation error' }

        { Invoke-CertValidationCallback -Callback $callback } | Should -Throw '*validation error*'
    }
}
