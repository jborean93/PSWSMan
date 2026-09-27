BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "Invoke-WinRSCommand" {
    Context "Output" {
        It "Writes stdout lines as strings - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = Invoke-WinRSCommand @params -Command 'echo line1&& echo line2'

            $actual | Should-BeCollection -Because 'each line is a separate string' @('line1', 'line2')
            $actual[0] | Should-HaveType ([string])
            $LASTEXITCODE | Should-Be 0
        }

        It "Uses positional parameters - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            $computerName = $params.ComputerName
            $params.Remove('ComputerName')

            $actual = Invoke-WinRSCommand $computerName 'echo hello' @params

            $actual | Should-Be 'hello'
        }

        It "Passes the command verbatim to cmd.exe - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            # Double spaces, quotes and cmd's own escaping all reach cmd.exe untouched.
            $actual = Invoke-WinRSCommand @params -Command 'echo a  "b c" ^&d'

            $actual | Should-Be 'a  "b c" &d'
        }

        It "Lets cmd.exe expand environment variables - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = Invoke-WinRSCommand @params -Command 'echo %SystemRoot%'

            $actual | Should-BeLikeString '?:\*'
        }

        It "Runs a quoted path with spaces when the line is wrapped in quotes - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            $exe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

            $actual = Invoke-WinRSCommand @params -Command "`"`"$exe`" -NoProfile -Command 'hello'`""

            $actual | Should-Be 'hello'
        }

        It "Writes stderr lines as native command errors - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = Invoke-WinRSCommand @params -Command 'echo err1>&2&& echo err2>&2' -ErrorVariable err -ErrorAction SilentlyContinue

            $actual | Should-BeNull
            $err.Count | Should-Be 2
            $err[0] | Should-HaveType ([System.Management.Automation.ErrorRecord])
            $err[0].FullyQualifiedErrorId | Should-Be 'NativeCommandError'
            $err[0].Exception | Should-HaveType ([System.Management.Automation.RemoteException])
            $err[0].Exception.Message | Should-Be 'err1'
            $err[0].TargetObject | Should-Be 'err1'
            $err[1].FullyQualifiedErrorId | Should-Be 'NativeCommandErrorMessage'
            $err[1].Exception.Message | Should-Be 'err2'
        }

        It "Keeps stdout and stderr in the order they were written - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            # The server reads stdout and stderr separately so lines written at the same moment can swap, the ping
            # pauses about a second between the writes to each stream.
            $actual = Invoke-WinRSCommand @params -Command 'echo out1& ping -n 2 127.0.0.1 >nul& echo err1>&2& ping -n 2 127.0.0.1 >nul& echo out2' -ErrorAction Continue 2>&1

            ($actual | ForEach-Object { "$_" }) -join ',' | Should-Be 'out1,err1,out2'
        }

        It "Converts stderr records to the line text with ToString - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = Invoke-WinRSCommand @params -Command 'echo err1>&2' -ErrorAction Continue 2>&1 | ForEach-Object ToString

            $actual | Should-Be 'err1'
        }

        It "Stops at the first stderr line when the error action is Stop - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            $cmd = {
                $ErrorActionPreference = 'Stop'
                Invoke-WinRSCommand @params -Command 'echo err1>&2& echo out1& exit 3' 2>&1
            }

            $err = $cmd | Should-Throw -ExceptionMessage 'err1'
            $err.FullyQualifiedErrorId | Should-Be 'NativeCommandError'
        }

        It "Runs to completion with -ErrorAction Continue when the preference is Stop - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            $ErrorActionPreference = 'Stop'

            $actual = Invoke-WinRSCommand @params -Command 'echo err1>&2& echo out1& exit 3' -ErrorAction Continue 2>&1
            $succeeded = $?

            $actual | Where-Object { $_ -is [string] } | Should-Be 'out1'
            $LASTEXITCODE | Should-Be 3
            $succeeded | Should-BeFalse
        }

        It "Sets LASTEXITCODE from the process exit code - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = Invoke-WinRSCommand @params -Command 'exit 3'

            $actual | Should-BeNull
            $LASTEXITCODE | Should-Be 3
        }

        It "Closes stdin so a process reading it does not block - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = Invoke-WinRSCommand @params -Command 'findstr x'

            $actual | Should-BeNull
            $LASTEXITCODE | Should-Be 1
        }

        It "Decodes UTF-8 output - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            # 1, 2, 3 and 4 byte UTF-8 sequences, the last is a surrogate pair in .NET.
            $expected = "caf$([char]0x00E9) $([char]0x65E5)$([char]0x672C) $([char]::ConvertFromUtf32(0x1F3B5))"
            $command = Get-RawOutputCommand -Bytes ([System.Text.Encoding]::UTF8.GetBytes("$expected`r`n"))

            $actual = Invoke-WinRSCommand @params -Command $command

            $actual | Should-Be $expected
        }

        It "Stops the command when the pipeline stops - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            # ping writes its first line immediately and would otherwise run for about 30 seconds.
            # Select-Object -First 1 stops the pipeline on the first output.
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $actual = Invoke-WinRSCommand @params -Command 'ping -n 30 127.0.0.1' | Select-Object -First 1
            $sw.Stop()

            $actual | Should-HaveType ([string])
            $sw.Elapsed.TotalSeconds | Should-BeLessThan 20
        }

        It "Stops a long running command and its remote process - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            # The marker identifies the remote process, the check below uses -EncodedCommand so its own command
            # line does not contain it.
            $marker = "pswsman-$([Guid]::NewGuid())"
            $sleepCommand = "powershell.exe -NoProfile -Command `"'started'; Start-Sleep -Seconds 30 # $marker`""

            $ps = [PowerShell]::Create()
            try {
                $modulePath = [IO.Path]::Combine((Get-Module -Name PSWSMan).ModuleBase, 'PSWSMan.psd1')
                $null = $ps.AddCommand('Import-Module').AddParameter('Name', $modulePath).AddStatement()
                $null = $ps.AddCommand('Invoke-WinRSCommand').AddParameters($params).AddParameter('Command', $sleepCommand)

                $output = [System.Management.Automation.PSDataCollection[PSObject]]::new()
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $task = $ps.BeginInvoke([System.Management.Automation.PSDataCollection[PSObject]]$null, $output)

                # Stop only once the remote process has started, a stop does not need any output otherwise.
                while ($output.Count -eq 0 -and -not $task.IsCompleted -and $sw.Elapsed.TotalSeconds -lt 20) {
                    Start-Sleep -Milliseconds 100
                }
                $ps.Stop()
                $sw.Stop()
            }
            finally {
                $ps.Dispose()
            }

            $output[0] | Should-Be 'started'
            $sw.Elapsed.TotalSeconds | Should-BeLessThan 25
            $ps.InvocationStateInfo.State | Should-Be 'Stopped'

            # Remote powershell.exe writes its progress to stderr, which the full test run treats as an error.
            $check = "`$ProgressPreference = 'SilentlyContinue'; @(Get-CimInstance Win32_Process -Filter `"Name='powershell.exe'`" | Where-Object CommandLine -like '*$marker*').Count"
            $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($check))
            $remaining = $null
            foreach ($attempt in 1..10) {
                # The shell is deleted as the pipeline stops, the server ends its process shortly after.
                $remaining = Invoke-WinRSCommand @params -Command "powershell.exe -NoProfile -EncodedCommand $encoded" -ErrorAction SilentlyContinue
                if ($remaining -eq '0') {
                    break
                }
                Start-Sleep -Seconds 1
            }
            $remaining | Should-Be '0'
        }
    }

    Context "Input" {
        It "Sends nothing for null pipeline input - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            # find counts every line on stdin, including empty ones.
            $actual = $null | Invoke-WinRSCommand @params -Command 'find /v /c ""'

            $actual | Should-Be '0'
            $LASTEXITCODE | Should-Be 1
        }

        It "Skips null values between other input - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = 'a', $null, 'b', $null | Invoke-WinRSCommand @params -Command 'find /v /c ""'

            $actual | Should-Be '2'
        }

        It "Writes strings as lines to stdin - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = 'one', 'two', 'three' | Invoke-WinRSCommand @params -Command 'findstr t'

            $actual | Should-BeCollection @('two', 'three')
            $LASTEXITCODE | Should-Be 0
        }

        It "Writes other objects as their string form - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = 1..3 | Invoke-WinRSCommand @params -Command 'findstr 2'

            $actual | Should-Be '2'
        }

        It "Writes a byte array as raw data - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("abc`r`ndef`r`n")

            $actual = , $bytes | Invoke-WinRSCommand @params -Command 'findstr d'

            $actual | Should-Be 'def'
        }

        It "Collects enumerated bytes as raw data - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("abc`r`ndef`r`n")

            $actual = $bytes | Invoke-WinRSCommand @params -Command 'findstr d'

            $actual | Should-Be 'def'
        }

        It "Accepts InputObject as a parameter - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = Invoke-WinRSCommand @params -Command 'findstr t' -InputObject 'one', 'two'

            $actual | Should-Be 'two'
        }

        It "Encodes input as UTF-8 - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = 'café' | Invoke-WinRSCommand @params -Command 'findstr caf'

            $actual | Should-Be 'café'
        }

        It "Splits large input into chunks - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            $line = 'a' * 200000

            $actual = $line | Invoke-WinRSCommand @params -Command 'powershell.exe -NoProfile -Command [Console]::In.ReadToEnd().Length'

            # The line plus its CRLF terminator.
            $actual | Should-Be '200002'
        }

        It "Discards input once the process has exited - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = 1..30 | Invoke-WinRSCommand @params -Command 'exit 5'

            $actual | Should-BeNull
            $LASTEXITCODE | Should-Be 5
        }

        It "Writes output received while input is still being sent - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = 1..3 | Invoke-WinRSCommand @params -Command 'findstr .'

            $actual | Should-BeCollection @('1', '2', '3')
        }
    }

    Context "ConsoleEncoding" {
        It "Creates the shell with the UTF-8 code page by default - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            Invoke-WinRSCommand @params -Command chcp | Should-Be 'Active code page: 65001'
        }

        It "Sets the code page from a number - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            Invoke-WinRSCommand @params -Command chcp -ConsoleEncoding 437 | Should-Be 'Active code page: 437'
        }

        It "Sets the code page from an Encoding object - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            Invoke-WinRSCommand @params -Command chcp -ConsoleEncoding ([System.Text.Encoding]::GetEncoding(850)) | Should-Be 'Active code page: 850'
        }

        It "Sets the code page from a name - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            Invoke-WinRSCommand @params -Command chcp -ConsoleEncoding ascii | Should-Be 'Active code page: 20127'
        }

        It "Replaces invalid bytes by default instead of failing - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = Invoke-WinRSCommand @params -Command (Get-RawOutputCommand -Hex '61E90D0A')

            $actual | Should-Be "a$([char]0xFFFD)"
            $LASTEXITCODE | Should-Be 0
        }

        It "Decodes stderr with the encoding - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            # café in code page 437.
            $command = Get-RawOutputCommand -Hex '636166820D0A' -Stream Stderr

            $null = Invoke-WinRSCommand @params -Command $command -ConsoleEncoding 437 -ErrorAction SilentlyContinue -ErrorVariable err

            $err.Count | Should-Be 1
            $err[0].ToString() | Should-Be 'café'
        }

        It "Decodes output with the encoding - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            # café in code page 437, the é is 0x82 which is not valid UTF-8 on its own.
            $command = Get-RawOutputCommand -Hex '636166820D0A'

            $actual = Invoke-WinRSCommand @params -Command $command -ConsoleEncoding 437

            $actual | Should-Be "caf$([char]0x00E9)"
        }

        It "Encodes input with the encoding - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            'café' | Invoke-WinRSCommand @params -Command 'findstr caf' -ConsoleEncoding 437 | Should-Be 'café'
        }

    }

    Context "ConsoleEncoding transformation and completion" {
        BeforeAll {
            $transform = (Get-Command Invoke-WinRSCommand).Parameters.ConsoleEncoding.Attributes |
                Where-Object { $_ -is [System.Management.Automation.ArgumentTransformationAttribute] }

            Function Get-EncodingCompletion {
                param ([string]$Prefix)

                $line = "Invoke-WinRSCommand -ComputerName host -Command x -ConsoleEncoding $Prefix"
                [System.Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches
            }
        }

        It "Transforms the name <Value>" -ForEach @(
            @{ Value = 'UTF8'; CodePage = 65001; Preamble = 0 }
            @{ Value = 'UTF8Bom'; CodePage = 65001; Preamble = 3 }
            @{ Value = 'UTF8NoBom'; CodePage = 65001; Preamble = 0 }
            @{ Value = 'ASCII'; CodePage = 20127; Preamble = 0 }
        ) {
            $actual = $transform.Transform($ExecutionContext, $Value)

            Should-HaveType -Actual $actual -Expected ([System.Text.Encoding])
            $actual.CodePage | Should-Be $CodePage
            $actual.GetPreamble().Length | Should-Be $Preamble
        }

        It "Transforms the name <Value> to the local <Source> encoding" -ForEach @(
            @{ Value = 'ANSI'; Source = 'ANSI'; Expected = { [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage } }
            @{ Value = 'OEM'; Source = 'console output'; Expected = { [Console]::OutputEncoding.CodePage } }
            @{ Value = 'ConsoleInput'; Source = 'console input'; Expected = { [Console]::InputEncoding.CodePage } }
            @{ Value = 'ConsoleOutput'; Source = 'console output'; Expected = { [Console]::OutputEncoding.CodePage } }
        ) {
            $actual = $transform.Transform($ExecutionContext, $Value)

            $actual.CodePage | Should-Be (& $Expected)
        }

        It "Transforms names case insensitively: <_>" -ForEach @('utf8', 'uTf8BoM', 'ascii', 'Ascii') {
            $expected = $transform.Transform($ExecutionContext, $_.ToUpperInvariant())

            $actual = $transform.Transform($ExecutionContext, $_)

            $actual.CodePage | Should-Be $expected.CodePage
            $actual.GetPreamble().Length | Should-Be $expected.GetPreamble().Length
        }

        It "Transforms <Name>" -ForEach @(
            @{ Name = 'an int code page'; Value = 437; Expected = 437 }
            @{ Name = 'a numeric string code page'; Value = '850'; Expected = 850 }
            @{ Name = 'a .NET encoding name'; Value = 'ibm437'; Expected = 437 }
            @{ Name = 'a .NET web name'; Value = 'windows-1252'; Expected = 1252 }
            @{ Name = 'a UTF-16 name, rejected later by the server'; Value = 'utf-16'; Expected = 1200 }
        ) {
            $actual = $transform.Transform($ExecutionContext, $Value)

            $actual.CodePage | Should-Be $Expected
        }

        It "Returns an Encoding object as is" {
            $encoding = [System.Text.Encoding]::GetEncoding(1252)

            $actual = $transform.Transform($ExecutionContext, $encoding)

            Should-BeSame -Actual $actual -Expected $encoding
        }

        It "Unwraps a PSObject" {
            $actual = $transform.Transform($ExecutionContext, [PSObject]'utf8')

            $actual.CodePage | Should-Be 65001
        }

        It "Binds a transformed value to the parameter" {
            # A value that transforms gets past binding to the connection attempt.
            $cmd = { Invoke-WinRSCommand -ComputerName 'pswsman.invalid' -Command hostname -ConsoleEncoding '437' }

            $err = $cmd | Should-Throw
            $err.FullyQualifiedErrorId | Should-Be 'WinRSCommandFailed,PSWSMan.Commands.InvokeWinRSCommand'
        }

        It "Rejects <Name>" -ForEach @(
            @{ Name = 'an unknown name'; Value = 'nope'; Message = "*'nope' is not a supported encoding name*" }
            @{ Name = 'an out of range code page'; Value = 99999; Message = '*Valid values are between 0 and 65535*' }
            @{ Name = 'an out of range numeric string'; Value = '99999'; Message = '*Valid values are between 0 and 65535*' }
            @{ Name = 'a negative numeric string'; Value = '-1'; Message = "*'-1' is not a supported encoding name*" }
            @{ Name = 'a non integer number'; Value = 1.5; Message = "*Could not convert input '1.5' to a valid Encoding object*" }
            @{ Name = 'a hashtable'; Value = @{}; Message = '*Could not convert input*to a valid Encoding object*' }
            @{ Name = 'null'; Value = $null; Message = "*Could not convert input '' to a valid Encoding object*" }
        ) {
            $value = $Value
            $cmd = { Invoke-WinRSCommand -ComputerName 'pswsman.invalid' -Command hostname -ConsoleEncoding $value }

            $err = $cmd | Should-Throw -ExceptionMessage $Message
            $err.FullyQualifiedErrorId | Should-Be 'ParameterArgumentTransformationError,PSWSMan.Commands.InvokeWinRSCommand'
        }

        It "Completes all known names without a prefix" {
            $actual = Get-EncodingCompletion

            $actual.CompletionText | Should-BeCollection @('UTF8', 'UTF8Bom', 'UTF8NoBom', 'ASCII', 'ANSI', 'OEM', 'ConsoleInput', 'ConsoleOutput')
            $actual.ResultType | Should-All { $_ -eq 'ParameterValue' }
        }

        It "Completes names starting with <Prefix>" -ForEach @(
            @{ Prefix = 'utf'; Expected = @('UTF8', 'UTF8Bom', 'UTF8NoBom') }
            @{ Prefix = 'A'; Expected = @('ASCII', 'ANSI') }
            @{ Prefix = 'console'; Expected = @('ConsoleInput', 'ConsoleOutput') }
        ) {
            $actual = Get-EncodingCompletion -Prefix $Prefix

            $actual.CompletionText | Should-BeCollection $Expected
        }

        It "Completes a single match" {
            $actual = Get-EncodingCompletion -Prefix 'oe'

            $actual.CompletionText | Should-Be 'OEM'
        }

        It "Completes nothing for an unknown prefix" {
            $actual = Get-EncodingCompletion -Prefix 'nope'

            $actual | Should-BeNull
        }
    }

    Context "AsByteStream" {
        BeforeAll {
            # Copies stdin to stdout byte for byte.
            $echoCommand = 'powershell.exe -NoProfile -Command "$i=[Console]::OpenStandardInput(); $o=[Console]::OpenStandardOutput(); $i.CopyTo($o); $o.Flush()"'
        }

        It "Outputs stdout as byte[] chunks - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $data = [System.Text.Encoding]::UTF8.GetBytes("caf$([char]0x00E9)`r`n")

            $actual = @(Invoke-WinRSCommand @params -Command (Get-RawOutputCommand -Bytes $data) -AsByteStream)

            Should-HaveType -Actual $actual[0] -Expected ([byte[]])
            $bytes = [byte[]]($actual | ForEach-Object { $_ })
            [Convert]::ToHexString($bytes) | Should-Be ([Convert]::ToHexString($data))
        }

        It "Outputs every byte value unchanged - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            $data = [byte[]](0..255)

            $actual = Invoke-WinRSCommand @params -Command (Get-RawOutputCommand -Bytes $data) -AsByteStream

            [Convert]::ToHexString([byte[]]($actual | ForEach-Object { $_ })) | Should-Be ([Convert]::ToHexString($data))
        }

        It "Still uses the UTF-8 code page - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = Invoke-WinRSCommand @params -Command chcp -AsByteStream

            $bytes = [byte[]]($actual | ForEach-Object { $_ })
            [System.Text.Encoding]::UTF8.GetString($bytes) | Should-Be "Active code page: 65001`r`n"
        }

        It "Round trips binary data through stdin and stdout - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            $data = [byte[]]::new(300000)
            [Random]::new(1).NextBytes($data)

            $actual = , $data | Invoke-WinRSCommand @params -Command $echoCommand -AsByteStream

            $bytes = [byte[]]($actual | ForEach-Object { $_ })
            $bytes.Length | Should-Be $data.Length
            [System.Linq.Enumerable]::SequenceEqual($bytes, $data) | Should-BeTrue
        }

        It "Encodes string input as UTF-8 - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $actual = 'café' | Invoke-WinRSCommand @params -Command $echoCommand -AsByteStream

            $bytes = [byte[]]($actual | ForEach-Object { $_ })
            [Convert]::ToHexString($bytes) | Should-Be ([Convert]::ToHexString([System.Text.Encoding]::UTF8.GetBytes("café`r`n")))
        }

        It "Uses ConsoleEncoding for the code page and string input - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat

            $codePage = Invoke-WinRSCommand @params -Command chcp -AsByteStream -ConsoleEncoding 437
            $echoed = 'café' | Invoke-WinRSCommand @params -Command $echoCommand -AsByteStream -ConsoleEncoding 437

            [System.Text.Encoding]::ASCII.GetString([byte[]]($codePage | ForEach-Object { $_ })) | Should-Be "Active code page: 437`r`n"
            # é is 0x82 in code page 437.
            [Convert]::ToHexString([byte[]]($echoed | ForEach-Object { $_ })) | Should-Be '636166820D0A'
        }

        It "Writes stderr as text decoded with ConsoleEncoding - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat
            # stdout is not valid text in any code page it could be decoded with, stderr is café in code page 437.
            $stdout = Get-RawOutputCommand -Hex 'FF00E9820D0A'
            $stderr = Get-RawOutputCommand -Hex '636166820D0A' -Stream Stderr

            $actual = Invoke-WinRSCommand @params -Command "$stdout& $stderr" -AsByteStream -ConsoleEncoding 437 -ErrorVariable err -ErrorAction SilentlyContinue

            [Convert]::ToHexString([byte[]]($actual | ForEach-Object { $_ })) | Should-Be 'FF00E9820D0A'
            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'NativeCommandError'
            $err[0].Exception.Message | Should-Be "caf$([char]0x00E9)"
        }
    }

    Context "Connection" {
        It "Connects over <_.Uri.Scheme> - <_.Name>" -ForEach (Get-PSWSManTestServer) {
            $params = $_ | Get-PSSessionSplat

            Invoke-WinRSCommand @params -Command 'echo hello' | Should-Be 'hello'
        }

        It "Connects with ConnectionUri - <_.Name>" -ForEach (Get-PSWSManTestServer) {
            $params = $_ | Get-PSSessionSplat
            foreach ($key in 'ComputerName', 'Port', 'UseSSL', 'ApplicationName') {
                $params.Remove($key)
            }

            Invoke-WinRSCommand -ConnectionUri $_.Uri @params -Command 'echo hello' | Should-Be 'hello'
        }

        It "Connects with Negotiate (NTLM) - <_.Name>" -ForEach (Get-PSWSManTestServer -Auth NTLM) {
            # Connecting by IP address stops Negotiate from using Kerberos.
            $params = $_ | Get-PSSessionSplat -UseIPAddress

            Invoke-WinRSCommand @params -Command 'echo hello' | Should-Be 'hello'
        }

        It "Connects with Kerberos - <_.Name>" -ForEach (Get-PSWSManTestServer -Auth Kerberos) {
            $params = $_ | Get-PSSessionSplat

            Invoke-WinRSCommand @params -Command 'echo hello' -Authentication Kerberos | Should-Be 'hello'
        }

        # NTLM with the System provider needs SSPI, GSS.framework, or gss-ntlmssp with MIT krb5.
        It "Connects with NTLM - <_.Name>" -ForEach (Get-PSWSManTestServer -Auth NTLM) {
            $params = $_ | Get-PSSessionSplat

            Invoke-WinRSCommand @params -Command 'echo hello' -Authentication NTLM | Should-Be 'hello'
        }

        It "Connects with CredSSP - <_.Name>" -ForEach (Get-PSWSManTestServer -Auth CredSSP, Kerberos) {
            $params = $_ | Get-PSSessionSplat

            Invoke-WinRSCommand @params -Command 'echo hello' -Authentication CredSSP | Should-Be 'hello'
        }

        It "Connects with Basic over HTTP with NoEncryption - <_.Name>" -ForEach (Get-PSWSManTestServer -Scheme Http -Auth Basic) {
            $params = $_ | Get-PSSessionSplat -SessionOption @{ NoEncryption = $true }

            Invoke-WinRSCommand @params -Command 'echo hello' -Authentication Basic | Should-Be 'hello'
        }

        It "Uses the AuthMethod of the session option - <_.Name>" -ForEach (Get-PSWSManTestServer -Auth NTLM) {
            $params = $_ | Get-PSSessionSplat -SessionOption @{ AuthMethod = 'NTLM' }

            Invoke-WinRSCommand @params -Command 'echo hello' | Should-Be 'hello'
        }

        It "Prefers Authentication over the AuthMethod of the session option - <_.Name>" -ForEach (Get-PSWSManTestServer -Scheme Http -Auth Kerberos) {
            # Basic over HTTP cannot encrypt so the connection only works if the explicit Kerberos wins.
            $params = $_ | Get-PSSessionSplat -SessionOption @{ AuthMethod = 'Basic' }

            Invoke-WinRSCommand @params -Command 'echo hello' -Authentication Kerberos | Should-Be 'hello'
        }

        It "Applies the session option timeouts and culture - <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
            $params = $_ | Get-PSSessionSplat -SessionOption @{
                OperationTimeout = 20000
                OpenTimeout = 20000
                Culture = 'en-AU'
                UICulture = 'en-AU'
                NoMachineProfile = $true
            }

            Invoke-WinRSCommand @params -Command 'echo hello' | Should-Be 'hello'
        }
    }

    Context "Module" {
        It "Exports the iwcm alias" {
            $actual = Get-Alias -Name iwcm

            $actual.ResolvedCommand.Name | Should-Be 'Invoke-WinRSCommand'
            $actual.ModuleName | Should-Be 'PSWSMan'
        }
    }

    Context "Parameter validation" {
        It "Fails with a terminating error when the host cannot be reached" {
            $cmd = { Invoke-WinRSCommand -ComputerName 'pswsman.invalid' -Command hostname -ErrorAction Stop }

            $err = $cmd | Should-Throw
            $err.FullyQualifiedErrorId | Should-Be 'WinRSCommandFailed,PSWSMan.Commands.InvokeWinRSCommand'
            $err.TargetObject | Should-Be 'pswsman.invalid'
        }

        It "Uses port 80 for a ConnectionUri without a port" {
            $cmd = { Invoke-WinRSCommand -ConnectionUri 'http://pswsman.invalid' -Command hostname }

            $err = $cmd | Should-Throw -ExceptionMessage '*pswsman.invalid:80*'
            $err.FullyQualifiedErrorId | Should-Be 'WinRSCommandFailed,PSWSMan.Commands.InvokeWinRSCommand'
            $err.TargetObject | Should-Be ([Uri]'http://pswsman.invalid')
        }

        It "Fails with a ConnectionUri that is not an absolute http or https URI: <_>" -ForEach @(
            'pswsman.invalid'
            'pswsman.invalid:5985'
            'ftp://pswsman.invalid'
        ) {
            $uri = $_
            $cmd = { Invoke-WinRSCommand -ConnectionUri $uri -Command hostname }

            $err = $cmd | Should-Throw -ExceptionMessage '*must be an absolute http or https URI*'
            $err.FullyQualifiedErrorId | Should-Be 'WinRSCommandInvalidParameter,PSWSMan.Commands.InvokeWinRSCommand'
        }

        It "Fails when CertificateThumbprint is used with a http ConnectionUri" {
            $cmd = { Invoke-WinRSCommand -ConnectionUri 'http://pswsman.invalid' -Command hostname -CertificateThumbprint 'ABC' }

            $cmd | Should-Throw -ExceptionMessage '*CertificateThumbprint parameter requires UseSSL or a https ConnectionUri*'
        }

        It "Fails when ConnectionUri is combined with <_>" -ForEach @('Port', 'UseSSL', 'ApplicationName') {
            $extra = @{
                Port = @{ Port = 1234 }
                UseSSL = @{ UseSSL = $true }
                ApplicationName = @{ ApplicationName = 'wsman' }
            }[$_]
            $cmd = { Invoke-WinRSCommand -ConnectionUri 'http://pswsman.invalid' -Command hostname @extra }

            $err = $cmd | Should-Throw
            $err.FullyQualifiedErrorId | Should-Be 'AmbiguousParameterSet,PSWSMan.Commands.InvokeWinRSCommand'
        }

        It "Fails with Basic over HTTP without NoEncryption" {
            $cred = [PSCredential]::new('user', (ConvertTo-SecureString -AsPlainText -Force 'pass'))
            $cmd = { Invoke-WinRSCommand -ComputerName 'pswsman.invalid' -Command hostname -Credential $cred -Authentication Basic }

            $err = $cmd | Should-Throw -ExceptionMessage '*Cannot encrypt WSMan payload as BasicAuthContext does not support message encryption*'
            $err.FullyQualifiedErrorId | Should-Be 'WinRSCommandFailed,PSWSMan.Commands.InvokeWinRSCommand'
            $err.CategoryInfo.Category | Should-Be 'InvalidArgument'
        }

        It "Fails when CertificateThumbprint is used with Credential" {
            $cred = [PSCredential]::new('user', (ConvertTo-SecureString -AsPlainText -Force 'pass'))
            $cmd = { Invoke-WinRSCommand -ComputerName 'pswsman.invalid' -Command hostname -UseSSL -Credential $cred -CertificateThumbprint 'ABC' }

            $err = $cmd | Should-Throw -ExceptionMessage '*Credential parameter and the CertificateThumbprint parameter cannot be used together*'
            $err.FullyQualifiedErrorId | Should-Be 'WinRSCommandInvalidParameter,PSWSMan.Commands.InvokeWinRSCommand'
        }

        It "Fails when CertificateThumbprint is used with Authentication" {
            $cmd = { Invoke-WinRSCommand -ComputerName 'pswsman.invalid' -Command hostname -UseSSL -Authentication Kerberos -CertificateThumbprint 'ABC' }

            $cmd | Should-Throw -ExceptionMessage '*Authentication parameter and the CertificateThumbprint parameter cannot be used together*'
        }

        It "Fails when CertificateThumbprint is used without UseSSL" {
            $cmd = { Invoke-WinRSCommand -ComputerName 'pswsman.invalid' -Command hostname -CertificateThumbprint 'ABC' }

            $cmd | Should-Throw -ExceptionMessage '*CertificateThumbprint parameter requires UseSSL or a https ConnectionUri*'
        }

        It "Fails when the certificate thumbprint is not found" {
            $cmd = { Invoke-WinRSCommand -ComputerName 'pswsman.invalid' -Command hostname -UseSSL -CertificateThumbprint '0000000000000000000000000000000000000000' }

            $err = $cmd | Should-Throw -ExceptionMessage '*failed to find certificate with the thumbprint requested*'
            $err.CategoryInfo.Category | Should-Be 'AuthenticationError'
        }
    }
}
