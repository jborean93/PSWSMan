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

Describe "New-RemoteCertificateValidationCallback" {
    It "Creates a RemoteCertificateValidationCallback" {
        $actual = New-RemoteCertificateValidationCallback -ScriptBlock { $true }

        $actual | Should-HaveType ([RemoteCertificateValidationCallback])
    }

    It "Passes the arguments to the script block with <SslPolicyErrors>" -TestCases @(
        @{ SslPolicyErrors = [SslPolicyErrors]::None }
        @{ SslPolicyErrors = [SslPolicyErrors]::RemoteCertificateChainErrors }
        @{ SslPolicyErrors = [SslPolicyErrors]::RemoteCertificateNameMismatch }
        @{ SslPolicyErrors = [SslPolicyErrors]::RemoteCertificateNotAvailable }
        @{ SslPolicyErrors = [SslPolicyErrors]'RemoteCertificateChainErrors, RemoteCertificateNameMismatch' }
    ) {
        $state = @{}
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock {
            $state = $using:state
            $state['args'] = $args

            $true
        }

        $actual = Invoke-CertValidationCallback -Callback $callback -SslPolicyErrors $SslPolicyErrors

        $actual | Should-BeTrue
        $state['args'].Count | Should-Be 4
        $state['args'][0] | Should-Be 'sender'
        $state['args'][1] | Should-HaveType ([X509Certificate])
        $state['args'][1].Thumbprint | Should-Be $cert.Thumbprint
        $state['args'][2] | Should-HaveType ([X509Chain])
        $state['args'][2].ChainStatus.Status | Should-ContainCollection ([X509ChainStatusFlags]::UntrustedRoot)
        $state['args'][3] | Should-Be $SslPolicyErrors
    }

    It "Runs on a thread without a default runspace" {
        $testRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace.Id
        $testThread = [Environment]::CurrentManagedThreadId

        $state = @{}
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock {
            $state = $using:state
            $state['runspace'] = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace.Id
            $state['thread'] = [Environment]::CurrentManagedThreadId

            $true
        }

        $actual = Invoke-CertValidationCallback -Callback $callback

        $actual | Should-BeTrue
        $state['runspace'] | Should-NotBe $testRunspace
        $state['thread'] | Should-NotBe $testThread
    }

    It "Uses a value captured with using" {
        $expected = [SslPolicyErrors]::RemoteCertificateNameMismatch
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock {
            param ($Sender, $Certificate, $Chain, $SslPolicyErrors)

            $SslPolicyErrors -eq $using:expected
        }

        Invoke-CertValidationCallback -Callback $callback -SslPolicyErrors $expected | Should-BeTrue
        Invoke-CertValidationCallback -Callback $callback -SslPolicyErrors None | Should-BeFalse
    }

    It "Uses a using variable regardless of its case" {
        $state = @{}
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock {
            $lower = $using:State
            $upper = $using:STATE
            $lower['lower'] = $true
            $upper['upper'] = $true

            $true
        }

        Invoke-CertValidationCallback -Callback $callback | Should-BeTrue
        $state['lower'] | Should-BeTrue
        $state['upper'] | Should-BeTrue
    }

    It "Uses a member of a using variable" {
        $state = @{}
        $obj = [PSCustomObject]@{
            Value = 'member value'
            Nested = [PSCustomObject]@{ Value = 'nested value' }
            Items = @(1, 2, 3)
        }
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock {
            $state = $using:state
            $state['value'] = $using:obj.Value
            $state['nested'] = $using:obj.Nested.Value
            $state['items'] = $using:obj.Items
            $state['missing'] = $using:obj.Missing

            $true
        }
        $obj.Value = 'changed'

        Invoke-CertValidationCallback -Callback $callback | Should-BeTrue
        $state['value'] | Should-Be 'member value'
        $state['nested'] | Should-Be 'nested value'
        , $state['items'] | Should-HaveType ([object[]])
        $state['items'] | Should-BeCollection @(1, 2, 3)
        $state['missing'] | Should-BeNull
    }

    It "Uses an index of a using variable" {
        $state = @{}
        $list = @('first', @('inner1', 'inner2'))
        $dict = @{ Key = 'dict value'; key2 = 'other value' }
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock {
            $state = $using:state
            $state['first'] = $using:list[0]
            $state['inner'] = $using:list[1]
            $state['nested'] = $using:list[1][-1]
            $state['dict'] = $using:dict['Key']
            $state['dict2'] = $using:dict['key2']
            $state['member'] = $using:list[0].Length

            $true
        }

        Invoke-CertValidationCallback -Callback $callback | Should-BeTrue
        $state['first'] | Should-Be 'first'
        $state['inner'] | Should-BeCollection @('inner1', 'inner2')
        $state['nested'] | Should-Be 'inner2'
        $state['dict'] | Should-Be 'dict value'
        $state['dict2'] | Should-Be 'other value'
        $state['member'] | Should-Be 5
    }

    It "Uses a null using variable" {
        $state = @{}
        $value = $null
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock {
            $state = $using:state
            $state['isNull'] = $null -eq $using:value

            $true
        }

        Invoke-CertValidationCallback -Callback $callback | Should-BeTrue
        $state['isNull'] | Should-BeTrue
    }

    It "Uses a scope qualified using variable" {
        $state = @{}
        $env:PSWSMAN_TEST_USING = 'env value'
        try {
            $callback = New-RemoteCertificateValidationCallback -ScriptBlock {
                $state = $using:local:state
                $state['env'] = $using:env:PSWSMAN_TEST_USING

                $true
            }
        }
        finally {
            $env:PSWSMAN_TEST_USING = $null
        }

        Invoke-CertValidationCallback -Callback $callback | Should-BeTrue
        $state['env'] | Should-Be 'env value'
    }

    It "Uses a using variable in a nested script block" {
        $state = @{}
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock {
            & {
                $state = $using:state
                $state['nested'] = $true
            }

            $true
        }

        Invoke-CertValidationCallback -Callback $callback | Should-BeTrue
        $state['nested'] | Should-BeTrue
    }

    It "Fails with a single error for all undefined using variables" {
        $err = {
            New-RemoteCertificateValidationCallback -ScriptBlock {
                $using:undefinedVar1
                $using:UNDEFINEDVAR1
                $using:undefinedVar2.Member
                $using:env:PSWSMAN_TEST_UNDEFINED
                $true
            }
        } | Should-Throw

        $err.FullyQualifiedErrorId | Should-Be 'UsingVariableIsUndefined,PSWSMan.Commands.NewRemoteCertificateValidationCallback'
        $err.CategoryInfo.Category | Should-Be ([System.Management.Automation.ErrorCategory]::InvalidArgument)
        $err.Exception | Should-HaveType ([ArgumentException])
        $err.Exception.Message | Should-Be ("The value of the using variable(s) '`$using:undefinedVar1', " +
            "'`$using:undefinedVar2.Member', '`$using:env:PSWSMAN_TEST_UNDEFINED' cannot be retrieved because " +
            "they have not been set in the local session.")
    }

    It "Returns <Expected> when the script block outputs <Expected>" -TestCases @(
        @{ Expected = $true }
        @{ Expected = $false }
    ) {
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock { $using:Expected }

        Invoke-CertValidationCallback -Callback $callback | Should-Be $Expected
    }

    It "Treats no output as a failed check" {
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock { }

        Invoke-CertValidationCallback -Callback $callback | Should-BeFalse
    }

    It "Uses only the last output" {
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock {
            $false
            $true
        }

        Invoke-CertValidationCallback -Callback $callback | Should-BeTrue
    }

    It "Treats a last output that is not a bool as a failed check" {
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock {
            $true
            'will fail'
        }

        Invoke-CertValidationCallback -Callback $callback | Should-BeFalse
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
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock ${function:Test-CertValidation}

        $actual = Invoke-CertValidationCallback -Callback $callback -SslPolicyErrors RemoteCertificateChainErrors

        $actual | Should-BeTrue
        $state['thumbprint'] | Should-Be $cert.Thumbprint
        $state['file'] | Should-Be $PSCommandPath
    }

    It "Preserves the script block source location" {
        $state = @{}
        $scriptBlock = {
            $state = $using:state
            $state['extent'] = $MyInvocation.MyCommand.ScriptBlock.Ast.Extent

            $true
        }
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock $scriptBlock

        $actual = Invoke-CertValidationCallback -Callback $callback

        $actual | Should-BeTrue
        $state['extent'].File | Should-Be $PSCommandPath
        $state['extent'].StartLineNumber | Should-Be $scriptBlock.Ast.Extent.StartLineNumber
        $state['extent'].StartColumnNumber | Should-Be $scriptBlock.Ast.Extent.StartColumnNumber
        $state['extent'].Text | Should-Be $scriptBlock.Ast.Extent.Text
    }

    It "Invokes a script block created from a string" {
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock ([scriptblock]::Create('$args[3] -eq "None"'))

        Invoke-CertValidationCallback -Callback $callback | Should-BeTrue
    }

    It "Raises a script block error to the caller" {
        $callback = New-RemoteCertificateValidationCallback -ScriptBlock { throw 'validation error' }

        { Invoke-CertValidationCallback -Callback $callback } | Should-Throw -ExceptionMessage '*validation error*'
    }
}
