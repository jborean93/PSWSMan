using namespace System.Collections.ObjectModel
using namespace System.Management.Automation
using namespace System.Management.Automation.Host

BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

    # The test cases use the types so they are needed at discovery already.
    if (-not ('PSWSManTests.RecordingHost' -as [type])) {
        Add-Type -Path ([IO.Path]::Combine($PSScriptRoot, 'data', 'RecordingHost.cs'))
    }
}

BeforeAll {
    Function New-WinRMClientHost {
        <#
        .SYNOPSIS
        Wraps a host in the internal host the WinRM session cmdlets give their runspace.
        #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [PSHost]
            $InnerHost
        )

        $type = [PSWSMan.WinRMSessionOption].Assembly.GetType('PSWSMan.CustomTransport.WinRMClientHost', $true)
        [Activator]::CreateInstance($type, @($InnerHost))
    }
}

Describe "WinRMClientHost" {
    Context "Forwarding to the wrapped host" {
        BeforeAll {
            $inner = [PSWSManTests.RecordingHost]::new()
            $wrapper = New-WinRMClientHost -InnerHost $inner

            $cells = [BufferCell[,]]::new(1, 1)
            $cells[0, 0] = [BufferCell]::new('x', 'White', 'Black', 'Complete')
            $fill = [BufferCell]::new('z', 'Gray', 'Blue', 'Complete')
            $choices = [Collection[ChoiceDescription]]@([ChoiceDescription]'&Yes', [ChoiceDescription]'&No', [ChoiceDescription]'&Maybe')
            $fields = [Collection[FieldDescription]]@([FieldDescription]'f1', [FieldDescription]'f2')
            $progress = [ProgressRecord]::new(1, 'activity', 'status')
            $information = [InformationRecord]::new('information message', 'source')
        }

        BeforeEach {
            $inner.ClearCalls()
        }

        It "Forwards <Call>" -TestCases @(
            # PSHost
            @{ Call = 'get_Name()'; Invoke = { $wrapper.Name }; Expected = 'RecordingHost' }
            @{ Call = 'get_Version()'; Invoke = { $wrapper.Version }; Expected = [Version]'1.2.3' }
            @{ Call = 'get_InstanceId()'; Invoke = { $wrapper.InstanceId }; Expected = [PSWSManTests.RecordingHostBase]::FixedInstanceId }
            @{ Call = 'get_CurrentCulture()'; Invoke = { $wrapper.CurrentCulture.Name }; Expected = 'de-DE' }
            @{ Call = 'get_CurrentUICulture()'; Invoke = { $wrapper.CurrentUICulture.Name }; Expected = 'fr-FR' }
            @{ Call = 'get_PrivateData()'; Invoke = { $wrapper.PrivateData }; Expected = 'private data' }
            @{ Call = 'get_DebuggerEnabled()'; Invoke = { $wrapper.DebuggerEnabled }; Expected = $true }
            @{ Call = 'set_DebuggerEnabled(False)'; Invoke = { $wrapper.DebuggerEnabled = $false } }
            @{ Call = 'SetShouldExit(3)'; Invoke = { $wrapper.SetShouldExit(3) } }
            @{ Call = 'EnterNestedPrompt()'; Invoke = { $wrapper.EnterNestedPrompt() } }
            @{ Call = 'ExitNestedPrompt()'; Invoke = { $wrapper.ExitNestedPrompt() } }
            @{ Call = 'NotifyBeginApplication()'; Invoke = { $wrapper.NotifyBeginApplication() } }
            @{ Call = 'NotifyEndApplication()'; Invoke = { $wrapper.NotifyEndApplication() } }

            # IHostSupportsInteractiveSession
            @{ Call = 'get_IsRunspacePushed()'; Invoke = { $wrapper.IsRunspacePushed }; Expected = $true }
            @{ Call = 'get_Runspace()'; Invoke = { $wrapper.Runspace }; Expected = $null }
            @{ Call = "PushRunspace(runspace $([runspace]::DefaultRunspace.Name))"; Invoke = { $wrapper.PushRunspace([runspace]::DefaultRunspace) } }
            @{ Call = 'PopRunspace()'; Invoke = { $wrapper.PopRunspace() } }

            # PSHostUserInterface
            @{ Call = 'get_SupportsVirtualTerminal()'; Invoke = { $wrapper.UI.SupportsVirtualTerminal }; Expected = $true }
            @{ Call = 'ReadLine()'; Invoke = { $wrapper.UI.ReadLine() }; Expected = 'read line' }
            @{ Call = 'ReadLineAsSecureString()'; Invoke = { [PSCredential]::new('u', $wrapper.UI.ReadLineAsSecureString()).GetNetworkCredential().Password }; Expected = 'secret line' }
            @{ Call = 'Write(text)'; Invoke = { $wrapper.UI.Write('text') } }
            @{ Call = 'Write(Red, Blue, text)'; Invoke = { $wrapper.UI.Write('Red', 'Blue', 'text') } }
            @{ Call = 'WriteLine()'; Invoke = { $wrapper.UI.WriteLine() } }
            @{ Call = 'WriteLine(text)'; Invoke = { $wrapper.UI.WriteLine('text') } }
            @{ Call = 'WriteLine(Red, Blue, text)'; Invoke = { $wrapper.UI.WriteLine('Red', 'Blue', 'text') } }
            @{ Call = 'WriteErrorLine(error)'; Invoke = { $wrapper.UI.WriteErrorLine('error') } }
            @{ Call = 'WriteDebugLine(debug)'; Invoke = { $wrapper.UI.WriteDebugLine('debug') } }
            @{ Call = 'WriteVerboseLine(verbose)'; Invoke = { $wrapper.UI.WriteVerboseLine('verbose') } }
            @{ Call = 'WriteWarningLine(warning)'; Invoke = { $wrapper.UI.WriteWarningLine('warning') } }
            @{ Call = 'WriteProgress(5, 1 activity status)'; Invoke = { $wrapper.UI.WriteProgress(5, $progress) } }
            @{ Call = 'WriteInformation(information message)'; Invoke = { $wrapper.UI.WriteInformation($information) } }
            @{ Call = 'Prompt(caption, message, f1|f2)'; Invoke = { $wrapper.UI.Prompt('caption', 'message', $fields)['f2'] }; Expected = 'value of f2' }
            @{ Call = 'PromptForCredential(caption, message, user, target)'; Invoke = { $wrapper.UI.PromptForCredential('caption', 'message', 'user', 'target').UserName }; Expected = 'credential user' }
            @{ Call = 'PromptForCredential(caption, message, user, target, Domain, AlwaysPrompt)'; Invoke = { $wrapper.UI.PromptForCredential('caption', 'message', 'user', 'target', 'Domain', 'AlwaysPrompt').UserName }; Expected = 'credential user options' }
            @{ Call = 'PromptForChoice(caption, message, &Yes|&No|&Maybe, 2)'; Invoke = { $wrapper.UI.PromptForChoice('caption', 'message', $choices, 2) }; Expected = 1 }

            # IHostUISupportsMultipleChoiceSelection
            @{ Call = 'PromptForChoice(caption, message, &Yes|&No|&Maybe, 0|1)'; Invoke = { ($wrapper.UI.PromptForChoice('caption', 'message', $choices, [int[]]@(0, 1))) -join ',' }; Expected = '0,2' }

            # PSHostRawUserInterface
            @{ Call = 'get_ForegroundColor()'; Invoke = { $wrapper.UI.RawUI.ForegroundColor }; Expected = [ConsoleColor]::DarkCyan }
            @{ Call = 'set_ForegroundColor(Red)'; Invoke = { $wrapper.UI.RawUI.ForegroundColor = 'Red' } }
            @{ Call = 'get_BackgroundColor()'; Invoke = { $wrapper.UI.RawUI.BackgroundColor }; Expected = [ConsoleColor]::DarkMagenta }
            @{ Call = 'set_BackgroundColor(Blue)'; Invoke = { $wrapper.UI.RawUI.BackgroundColor = 'Blue' } }
            @{ Call = 'get_CursorPosition()'; Invoke = { "$($wrapper.UI.RawUI.CursorPosition)" }; Expected = '3,4' }
            @{ Call = 'set_CursorPosition(7,8)'; Invoke = { $wrapper.UI.RawUI.CursorPosition = [Coordinates]::new(7, 8) } }
            @{ Call = 'get_WindowPosition()'; Invoke = { "$($wrapper.UI.RawUI.WindowPosition)" }; Expected = '5,6' }
            @{ Call = 'set_WindowPosition(9,10)'; Invoke = { $wrapper.UI.RawUI.WindowPosition = [Coordinates]::new(9, 10) } }
            @{ Call = 'get_CursorSize()'; Invoke = { $wrapper.UI.RawUI.CursorSize }; Expected = 17 }
            @{ Call = 'set_CursorSize(50)'; Invoke = { $wrapper.UI.RawUI.CursorSize = 50 } }
            @{ Call = 'get_BufferSize()'; Invoke = { "$($wrapper.UI.RawUI.BufferSize)" }; Expected = '121,3001' }
            @{ Call = 'set_BufferSize(80x25)'; Invoke = { $wrapper.UI.RawUI.BufferSize = [Size]::new(80, 25) } }
            @{ Call = 'get_WindowSize()'; Invoke = { "$($wrapper.UI.RawUI.WindowSize)" }; Expected = '119,41' }
            @{ Call = 'set_WindowSize(70x20)'; Invoke = { $wrapper.UI.RawUI.WindowSize = [Size]::new(70, 20) } }
            @{ Call = 'get_MaxWindowSize()'; Invoke = { "$($wrapper.UI.RawUI.MaxWindowSize)" }; Expected = '201,61' }
            @{ Call = 'get_MaxPhysicalWindowSize()'; Invoke = { "$($wrapper.UI.RawUI.MaxPhysicalWindowSize)" }; Expected = '301,81' }
            @{ Call = 'get_KeyAvailable()'; Invoke = { $wrapper.UI.RawUI.KeyAvailable }; Expected = $true }
            @{ Call = 'get_WindowTitle()'; Invoke = { $wrapper.UI.RawUI.WindowTitle }; Expected = 'recording title' }
            @{ Call = 'set_WindowTitle(new title)'; Invoke = { $wrapper.UI.RawUI.WindowTitle = 'new title' } }
            @{ Call = 'ReadKey(NoEcho, IncludeKeyUp)'; Invoke = { $wrapper.UI.RawUI.ReadKey('NoEcho, IncludeKeyUp').Character }; Expected = [char]'A' }
            @{ Call = 'ReadKey(IncludeKeyDown)'; Invoke = { $wrapper.UI.RawUI.ReadKey().VirtualKeyCode }; Expected = 65 }
            @{ Call = 'FlushInputBuffer()'; Invoke = { $wrapper.UI.RawUI.FlushInputBuffer() } }
            @{ Call = "SetBufferContents(1,2, cells 1x1 'x')"; Invoke = { $wrapper.UI.RawUI.SetBufferContents([Coordinates]::new(1, 2), $cells) } }
            @{ Call = "SetBufferContents(0,0,4,5, 'z' Gray/Blue)"; Invoke = { $wrapper.UI.RawUI.SetBufferContents([Rectangle]::new(0, 0, 4, 5), $fill) } }
            @{ Call = "SetBufferContents(-1,-1,-1,-1, ' ' Gray/Blue)"; Invoke = { $wrapper.UI.RawUI.SetBufferContents([Rectangle]::new(-1, -1, -1, -1), [BufferCell]::new(' ', 'Gray', 'Blue', 'Complete')) } }
            @{ Call = 'GetBufferContents(0,0,1,0)'; Invoke = { $wrapper.UI.RawUI.GetBufferContents([Rectangle]::new(0, 0, 1, 0))[0, 0].Character }; Expected = [char]'g' }
            @{ Call = "ScrollBufferContents(0,0,2,2, 1,1, 0,0,10,10, 'z' Gray/Blue)"; Invoke = { $wrapper.UI.RawUI.ScrollBufferContents([Rectangle]::new(0, 0, 2, 2), [Coordinates]::new(1, 1), [Rectangle]::new(0, 0, 10, 10), $fill) } }
            @{ Call = 'LengthInBufferCells(abc)'; Invoke = { $wrapper.UI.RawUI.LengthInBufferCells('abc') }; Expected = 101 }
            @{ Call = 'LengthInBufferCells(abc, 1)'; Invoke = { $wrapper.UI.RawUI.LengthInBufferCells('abc', 1) }; Expected = 102 }
            @{ Call = 'LengthInBufferCells(a)'; Invoke = { $wrapper.UI.RawUI.LengthInBufferCells([char]'a') }; Expected = 103 }
        ) {
            $actual = & $Invoke

            $inner.Calls | Should-BeCollection @($Call)
            if ($null -eq $Expected) {
                $actual | Should-BeNull
            }
            else {
                $actual | Should-Be $Expected
            }
        }

        It "Overrides every overridable member of <BaseType>" -TestCases @(
            @{ BaseType = [PSHost]; Wrapper = 'WinRMClientHost' }
            @{ BaseType = [PSHostUserInterface]; Wrapper = 'WinRMClientHostUI' }
            @{ BaseType = [PSHostRawUserInterface]; Wrapper = 'WinRMClientHostRawUI' }
        ) {
            # A member a new PowerShell version adds would otherwise use the base implementation rather than the
            # wrapped host without anything noticing.
            $wrapperType = [PSWSMan.WinRMSessionOption].Assembly.GetType("PSWSMan.CustomTransport.$Wrapper", $true)
            $flags = [System.Reflection.BindingFlags]'Public, NonPublic, Instance'
            $overridden = $wrapperType.GetMethods($flags) |
                Where-Object DeclaringType -EQ $wrapperType |
                ForEach-Object { $_.GetBaseDefinition() }

            $missing = $BaseType.GetMethods($flags) |
                Where-Object { $_.IsVirtual -and -not $_.IsFinal -and $_.DeclaringType -ne [object] } |
                Where-Object { $_.GetBaseDefinition() -notin $overridden } |
                ForEach-Object { "$($_.DeclaringType.Name).$($_.Name)" }

            $missing | Should-BeNull
        }

        It "Implements the same host interfaces" {
            $wrapper -is [IHostSupportsInteractiveSession] | Should-BeTrue
            $wrapper.UI -is [IHostUISupportsMultipleChoiceSelection] | Should-BeTrue
        }
    }

    Context "Host calls from a remote session on <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
        BeforeAll {
            $server = $_
            $inner = [PSWSManTests.RecordingHost]::new()
            $rs = $ps = $session = $null
            $openCalls = @()

            # The session is opened in a runspace whose host is the recording host so the cmdlet wraps it.
            if ($server.Uri) {
                $params = $server | Get-PSSessionSplat
                $rs = [RunspaceFactory]::CreateRunspace($inner)
                $rs.Open()
                $ps = [PowerShell]::Create()
                $ps.Runspace = $rs
                $session = $ps.AddScript({
                        param ($ModulePath, $Params)
                        Import-Module -Name $ModulePath
                        New-WinRMSession @Params
                    }).AddArgument([IO.Path]::Combine((Get-Module -Name PSWSMan).ModuleBase, 'PSWSMan.psd1')).
                    AddArgument($params).Invoke() | Select-Object -First 1
                $openCalls = $inner.Calls
            }

            Function Invoke-Remote {
                param ([string]$Script)

                $remote = [PowerShell]::Create()
                try {
                    $remote.Runspace = $session.Runspace
                    $remote.AddScript($Script).Invoke()
                    $remote.Streams.Error | Should-BeNull
                }
                finally {
                    $remote.Dispose()
                }
            }
        }

        AfterAll {
            if ($session) {
                Remove-PSSession -Session $session
            }
            if ($ps) {
                $ps.Dispose()
            }
            if ($rs) {
                $rs.Dispose()
            }
        }

        BeforeEach {
            # Get-PSSessionSplat skips the test when no server is configured.
            $null = $server | Get-PSSessionSplat
            $inner.ClearCalls()
        }

        It "Gives the remote host the details of the wrapped host when it opens" {
            $openCalls | Should-ContainCollection @(
                'get_ForegroundColor()'
                'get_BackgroundColor()'
                'get_CursorPosition()'
                'get_WindowPosition()'
                'get_CursorSize()'
                'get_BufferSize()'
                'get_WindowSize()'
                'get_MaxWindowSize()'
                'get_MaxPhysicalWindowSize()'
                'get_WindowTitle()'
            )

            $actual = Invoke-Remote -Script {
                $raw = $Host.UI.RawUI
                "$($raw.ForegroundColor) $($raw.BackgroundColor) $($raw.CursorPosition) $($raw.WindowPosition) $($raw.CursorSize)"
                "$($raw.BufferSize) $($raw.WindowSize) $($raw.MaxWindowSize) $($raw.MaxPhysicalWindowSize) $($raw.WindowTitle)"
            }

            $actual | Should-BeCollection @(
                'DarkCyan DarkMagenta 3,4 5,6 17'
                '121,3001 119,41 201,61 301,81 recording title'
            )
        }

        # The remote script runs on the server, which can be Windows PowerShell, so it sticks to syntax that works
        # there. Only the members PowerShell remoting sends as a host call are here, the rest are answered by the
        # remote host itself.
        It "Forwards <Call>" -TestCases @(
            @{ Call = 'Write(text)'; Script = { $Host.UI.Write('text') } }
            @{ Call = 'Write(Red, Blue, text)'; Script = { $Host.UI.Write('Red', 'Blue', 'text') } }
            @{ Call = 'WriteLine()'; Script = { $Host.UI.WriteLine() } }
            @{ Call = 'WriteLine(text)'; Script = { $Host.UI.WriteLine('text') } }
            @{ Call = 'WriteLine(Red, Blue, text)'; Script = { $Host.UI.WriteLine('Red', 'Blue', 'text') } }
            @{ Call = 'WriteErrorLine(error)'; Script = { $Host.UI.WriteErrorLine('error') } }
            @{ Call = 'WriteDebugLine(debug)'; Script = { $Host.UI.WriteDebugLine('debug') } }
            @{ Call = 'WriteVerboseLine(verbose)'; Script = { $Host.UI.WriteVerboseLine('verbose') } }
            @{ Call = 'WriteWarningLine(warning)'; Script = { $Host.UI.WriteWarningLine('warning') } }
            @{ Call = 'WriteProgress(5, 1 activity status)'; Script = { $Host.UI.WriteProgress(5, [System.Management.Automation.ProgressRecord]::new(1, 'activity', 'status')) } }
            @{ Call = 'ReadLine()'; Script = { $Host.UI.ReadLine() }; Expected = 'read line' }
            # The remote host warns about a secure read before it asks for it.
            @{ Call = 'ReadLineAsSecureString()'; Script = { [PSCredential]::new('u', $Host.UI.ReadLineAsSecureString()).GetNetworkCredential().Password }; Expected = 'secret line' }
            @{
                Call = 'Prompt(caption, message, f1|f2)'
                Script = {
                    $fields = [System.Collections.ObjectModel.Collection[System.Management.Automation.Host.FieldDescription]]::new()
                    'f1', 'f2' | ForEach-Object { $fields.Add([System.Management.Automation.Host.FieldDescription]::new($_)) }
                    $Host.UI.Prompt('caption', 'message', $fields)['f2']
                }
                Expected = 'value of f2'
            }
            # The remote host adds a warning to the caption and sends both overloads as the one with options.
            @{ Call = 'PromptForCredential(*caption*message, user, target, Default, ValidateUserNameSyntax)'; Script = { $Host.UI.PromptForCredential('caption', 'message', 'user', 'target').UserName }; Expected = 'credential user options' }
            @{ Call = 'PromptForCredential(*caption*message, user, target, Domain, AlwaysPrompt)'; Script = { $Host.UI.PromptForCredential('caption', 'message', 'user', 'target', 'Domain', 'AlwaysPrompt').UserName }; Expected = 'credential user options' }
            @{
                Call = 'PromptForChoice(caption, message, &Yes|&No|&Maybe, 2)'
                Script = {
                    $choices = [System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]]::new()
                    '&Yes', '&No', '&Maybe' | ForEach-Object { $choices.Add([System.Management.Automation.Host.ChoiceDescription]::new($_)) }
                    $Host.UI.PromptForChoice('caption', 'message', $choices, 2)
                }
                Expected = 1
            }
            @{
                Call = 'PromptForChoice(caption, message, &Yes|&No|&Maybe, 0|1)'
                Script = {
                    $choices = [System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]]::new()
                    '&Yes', '&No', '&Maybe' | ForEach-Object { $choices.Add([System.Management.Automation.Host.ChoiceDescription]::new($_)) }
                    # PowerShell fails to deserialize the host call when the defaults are an int[], a Collection[int]
                    # works.
                    $Host.UI.PromptForChoice('caption', 'message', $choices, [System.Collections.ObjectModel.Collection[int]]@(0, 1)) -join ','
                }
                Expected = '0,2'
            }
            @{ Call = 'set_ForegroundColor(Red)'; Script = { $Host.UI.RawUI.ForegroundColor = 'Red' } }
            @{ Call = 'set_BackgroundColor(Blue)'; Script = { $Host.UI.RawUI.BackgroundColor = 'Blue' } }
            @{ Call = 'set_CursorPosition(7,8)'; Script = { $Host.UI.RawUI.CursorPosition = [System.Management.Automation.Host.Coordinates]::new(7, 8) } }
            @{ Call = 'set_WindowPosition(9,10)'; Script = { $Host.UI.RawUI.WindowPosition = [System.Management.Automation.Host.Coordinates]::new(9, 10) } }
            @{ Call = 'set_CursorSize(50)'; Script = { $Host.UI.RawUI.CursorSize = 50 } }
            @{ Call = 'set_BufferSize(80x25)'; Script = { $Host.UI.RawUI.BufferSize = [System.Management.Automation.Host.Size]::new(80, 25) } }
            @{ Call = 'set_WindowSize(70x20)'; Script = { $Host.UI.RawUI.WindowSize = [System.Management.Automation.Host.Size]::new(70, 20) } }
            @{ Call = 'set_WindowTitle(new title)'; Script = { $Host.UI.RawUI.WindowTitle = 'new title' } }
            @{ Call = 'ReadKey(NoEcho, IncludeKeyDown)'; Script = { $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown').Character }; Expected = [char]'A' }
            @{ Call = 'FlushInputBuffer()'; Script = { $Host.UI.RawUI.FlushInputBuffer() } }
            @{
                Call = "SetBufferContents(1,2, cells 1x1 'x')"
                Script = {
                    $cells = [System.Management.Automation.Host.BufferCell[,]]::new(1, 1)
                    $cells[0, 0] = [System.Management.Automation.Host.BufferCell]::new('x', 'White', 'Black', 'Complete')
                    $Host.UI.RawUI.SetBufferContents([System.Management.Automation.Host.Coordinates]::new(1, 2), $cells)
                }
            }
            @{ Call = "SetBufferContents(0,0,4,5, 'z' Gray/Blue)"; Script = { $Host.UI.RawUI.SetBufferContents([System.Management.Automation.Host.Rectangle]::new(0, 0, 4, 5), [System.Management.Automation.Host.BufferCell]::new('z', 'Gray', 'Blue', 'Complete')) } }
            @{ Call = "ScrollBufferContents(0,0,2,2, 1,1, 0,0,10,10, 'z' Gray/Blue)"; Script = { $Host.UI.RawUI.ScrollBufferContents([System.Management.Automation.Host.Rectangle]::new(0, 0, 2, 2), [System.Management.Automation.Host.Coordinates]::new(1, 1), [System.Management.Automation.Host.Rectangle]::new(0, 0, 10, 10), [System.Management.Automation.Host.BufferCell]::new('z', 'Gray', 'Blue', 'Complete')) } }
        ) {
            $actual = Invoke-Remote -Script $Script.ToString()

            $inner.Calls[-1] | Should-BeLikeString $Call
            if ($null -eq $Expected) {
                $actual | Should-BeNull
            }
            else {
                $actual | Should-Be $Expected
            }
        }
    }

    Context "Hosts without optional features" {
        It "Has no UI when the wrapped host has none" {
            $wrapper = New-WinRMClientHost -InnerHost ([PSWSManTests.PlainHost]::new($false))

            $wrapper.UI | Should-BeNull
        }

        It "Has no RawUI when the wrapped UI has none" {
            $wrapper = New-WinRMClientHost -InnerHost ([PSWSManTests.RecordingHost]::new($false, $true, $false))

            $wrapper.UI | Should-NotBeNull
            $wrapper.UI.RawUI | Should-BeNull
        }

        It "Throws PSNotImplementedException for <Name> when the host does not support interactive sessions" -TestCases @(
            # PowerShell turns an exception from a property getter into $null, the getter methods show it.
            @{ Name = 'IsRunspacePushed'; Invoke = { $wrapper.get_IsRunspacePushed() } }
            @{ Name = 'Runspace'; Invoke = { $wrapper.get_Runspace() } }
            @{ Name = 'PushRunspace'; Invoke = { $wrapper.PushRunspace([runspace]::DefaultRunspace) } }
            @{ Name = 'PopRunspace'; Invoke = { $wrapper.PopRunspace() } }
        ) {
            # The same as the host the engine gives a cmdlet, which throws when the actual host does not implement it.
            $wrapper = New-WinRMClientHost -InnerHost ([PSWSManTests.PlainHost]::new())

            $err = { & $Invoke } | Should-Throw
            $err.Exception.GetBaseException() | Should-HaveType ([PSNotImplementedException])
        }

        It "Throws PSNotImplementedException for a multiple choice prompt when the UI does not support it" {
            $inner = [PSWSManTests.PlainHost]::new()
            $wrapper = New-WinRMClientHost -InnerHost $inner
            $choices = [Collection[ChoiceDescription]]@([ChoiceDescription]'&Yes', [ChoiceDescription]'&No')

            $err = { $wrapper.UI.PromptForChoice('caption', 'message', $choices, [int[]]@(0)) } | Should-Throw
            $err.Exception.GetBaseException() | Should-HaveType ([PSNotImplementedException])
            $inner.Calls | Should-BeNull
        }
    }

    Context "SetBufferContents failures" {
        It "Keeps the not implemented failure of a SetBufferContents call that is not a full screen clear" {
            $inner = [PSWSManTests.RecordingHost]::new($true)
            $wrapper = New-WinRMClientHost -InnerHost $inner
            $fill = [BufferCell]::new(' ', 'Gray', 'Black', 'Complete')

            $err = { $wrapper.UI.RawUI.SetBufferContents([Rectangle]::new(0, 0, 4, 5), $fill) } | Should-Throw
            $err.Exception.GetBaseException() | Should-HaveType ([NotImplementedException])
            $inner.Calls | Should-BeCollection @("SetBufferContents(0,0,4,5, ' ' Gray/Black)")
        }

        It "Keeps the not implemented failure of a full screen fill that is not a space" {
            $inner = [PSWSManTests.RecordingHost]::new($true)
            $wrapper = New-WinRMClientHost -InnerHost $inner
            $fill = [BufferCell]::new('x', 'Gray', 'Black', 'Complete')

            $err = { $wrapper.UI.RawUI.SetBufferContents([Rectangle]::new(-1, -1, -1, -1), $fill) } | Should-Throw
            $err.Exception.GetBaseException() | Should-HaveType ([NotImplementedException])
        }
    }
}
