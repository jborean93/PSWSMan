BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "Send-WinRSFile and Receive-WinRSFile" {
    Context "Copying files with <_.Name>" -ForEach (Get-PSWSManTestServer -First) {
        BeforeAll {
            $server = $_
            $params = @{}
            $remoteDir = $null

            if ($server.Uri) {
                $params = $server | Get-PSSessionSplat

                # Relative to the working directory of the shell, the user profile, so no admin rights are needed.
                $remoteDir = "PSWSMan-$([Guid]::NewGuid().ToString('N'))"
                Invoke-WinRSCommand @params -Command "mkdir $remoteDir"
            }

            Function New-TestFile {
                param ([string]$Path, [int]$Length)

                $data = [byte[]]::new($Length)
                [Random]::new($Length).NextBytes($data)
                [IO.File]::WriteAllBytes($Path, $data)
                Get-Item -LiteralPath $Path
            }

            Function Get-RemoteFileHash {
                <#
                .SYNOPSIS
                Gets the SHA256 hash of files on the remote host, in the order given.
                #>
                param ([string[]]$Path)

                # .NET directly rather than Get-FileHash, a module autoload makes powershell.exe write progress
                # records to stderr.
                $paths = ($Path | ForEach-Object {
                        "'$([System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($_))'"
                    }) -join ', '
                $script = @"
foreach (`$p in @($paths)) {
    `$fs = [IO.File]::OpenRead(`$p)
    try { [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash(`$fs)).Replace('-', '') }
    finally { `$fs.Dispose() }
}
"@
                Invoke-WinRSCommand @params -Command (Get-PowerShellCommand -Script $script)
            }

            Function Get-LocalFileHash {
                param ([string]$Path)

                (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
            }

            Function Get-RemoteDirList {
                param ([string]$Path = $remoteDir)

                Invoke-WinRSCommand @params -Command "dir /a /b `"$Path`"" -ErrorAction SilentlyContinue
            }
        }

        AfterAll {
            if ($remoteDir) {
                Invoke-WinRSCommand @params -Command "rmdir /s /q $remoteDir"
            }
        }

        BeforeEach {
            $localDir = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            $null = New-Item -Path $localDir -ItemType Directory
        }

        It "Copies a file of <Length> bytes there and back with <Compression> compression" -ForEach @(
            foreach ($compression in 'None', 'Deflate') {
                foreach ($length in 0, 1, 70000, 200000) {
                    @{ Length = $length; Compression = $compression }
                }
            }
        ) {
            $null = $server | Get-PSSessionSplat
            $source = New-TestFile -Path "$localDir/file $Length.bin" -Length $Length
            $back = Join-Path $localDir 'back.bin'

            Send-WinRSFile @params -Path $source.FullName -Destination "$remoteDir\sent $Length.bin" -Compression $Compression
            Receive-WinRSFile @params -Path "$remoteDir\sent $Length.bin" -Destination $back -Compression $Compression

            $expected = Get-LocalFileHash $source.FullName
            Get-RemoteFileHash "$remoteDir\sent $Length.bin" | Should-Be $expected
            (Get-Item -LiteralPath $back).Length | Should-Be $Length
            Get-LocalFileHash $back | Should-Be $expected
        }

        It "Copies a compressible file with <_> compression" -ForEach @('None', 'Deflate') {
            $null = $server | Get-PSSessionSplat
            $source = "$localDir/text.txt"
            Set-Content -LiteralPath $source -Value (1..20000 | ForEach-Object { "line $_ of a compressible file" })

            Send-WinRSFile @params -Path $source -Destination "$remoteDir\text-$_.txt" -Compression $_
            Receive-WinRSFile @params -Path "$remoteDir\text-$_.txt" -Destination "$localDir/back.txt" -Compression $_

            $expected = Get-LocalFileHash $source
            Get-RemoteFileHash "$remoteDir\text-$_.txt" | Should-Be $expected
            Get-LocalFileHash "$localDir/back.txt" | Should-Be $expected
        }

        It "Uses positional parameters" {
            $null = $server | Get-PSSessionSplat  # Skips test if no session is available
            $computerName = $params.ComputerName
            $positional = $params.Clone()
            $positional.Remove('ComputerName')
            $source = New-TestFile -Path "$localDir/positional.bin" -Length 10

            Send-WinRSFile $computerName $source.FullName "$remoteDir\positional.bin" @positional
            Receive-WinRSFile $computerName "$remoteDir\positional.bin" "$localDir/back.bin" @positional

            $expected = Get-LocalFileHash $source.FullName
            Get-RemoteFileHash "$remoteDir\positional.bin" | Should-Be $expected
            Get-LocalFileHash "$localDir/back.bin" | Should-Be $expected
        }

        It "Copies into an existing directory with the file name" {
            $null = $server | Get-PSSessionSplat
            $null = Invoke-WinRSCommand @params -Command "mkdir $remoteDir\intodir"
            $source = New-TestFile -Path "$localDir/named.bin" -Length 100
            $backDir = New-Item -Path "$localDir/back" -ItemType Directory

            Send-WinRSFile @params -Path $source.FullName -Destination "$remoteDir\intodir"
            Receive-WinRSFile @params -Path "$remoteDir\intodir\named.bin" -Destination $backDir.FullName

            Get-RemoteDirList "$remoteDir\intodir" | Should-Be 'named.bin'
            $expected = Get-LocalFileHash $source.FullName
            Get-RemoteFileHash "$remoteDir\intodir\named.bin" | Should-Be $expected
            Get-LocalFileHash "$($backDir.FullName)/named.bin" | Should-Be $expected
        }

        It "Replaces an existing file in both directions" {
            $null = $server | Get-PSSessionSplat
            $first = New-TestFile -Path "$localDir/first.bin" -Length 500
            $second = New-TestFile -Path "$localDir/second.bin" -Length 300

            $secondHash = Get-LocalFileHash $second.FullName

            Send-WinRSFile @params -Path $first.FullName -Destination "$remoteDir\replace.bin"
            Get-RemoteFileHash "$remoteDir\replace.bin" | Should-Be (Get-LocalFileHash $first.FullName)
            Send-WinRSFile @params -Path $second.FullName -Destination "$remoteDir\replace.bin"
            Get-RemoteFileHash "$remoteDir\replace.bin" | Should-Be $secondHash
            Receive-WinRSFile @params -Path "$remoteDir\replace.bin" -Destination $first.FullName

            Get-LocalFileHash $first.FullName | Should-Be $secondHash
        }

        It "Copies files piped from Get-ChildItem" {
            $null = $server | Get-PSSessionSplat
            $null = Invoke-WinRSCommand @params -Command "mkdir $remoteDir\piped"
            1..3 | ForEach-Object { $null = New-TestFile -Path "$localDir/piped$_.txt" -Length $_ }

            Get-ChildItem -LiteralPath $localDir -Filter 'piped*.txt' | Send-WinRSFile @params -Destination "$remoteDir\piped"

            Get-RemoteDirList "$remoteDir\piped" | Should-BeCollection @('piped1.txt', 'piped2.txt', 'piped3.txt')
            $expected = 1..3 | ForEach-Object { Get-LocalFileHash "$localDir/piped$_.txt" }
            Get-RemoteFileHash (1..3 | ForEach-Object { "$remoteDir\piped\piped$_.txt" }) | Should-BeCollection $expected
        }

        It "Copies several remote files from the pipeline" {
            $null = $server | Get-PSSessionSplat
            $sources = 1..2 | ForEach-Object { New-TestFile -Path "$localDir/multi$_.bin" -Length (10 * $_) }
            $sources | Send-WinRSFile @params -Destination $remoteDir
            $backDir = New-Item -Path "$localDir/back" -ItemType Directory

            "$remoteDir\multi1.bin", "$remoteDir\multi2.bin" | Receive-WinRSFile @params -Destination $backDir.FullName

            $expected = $sources | ForEach-Object { Get-LocalFileHash $_.FullName }
            Get-RemoteFileHash "$remoteDir\multi1.bin", "$remoteDir\multi2.bin" | Should-BeCollection $expected
            (Get-ChildItem -LiteralPath $backDir.FullName).Name | Should-BeCollection @('multi1.bin', 'multi2.bin')
            Get-LocalFileHash "$($backDir.FullName)/multi1.bin" | Should-Be $expected[0]
            Get-LocalFileHash "$($backDir.FullName)/multi2.bin" | Should-Be $expected[1]
        }

        It "Sends each piped file to a delay-bound destination" {
            $null = $server | Get-PSSessionSplat
            $null = Invoke-WinRSCommand @params -Command "mkdir $remoteDir\delaysend"
            1..2 | ForEach-Object { $null = New-TestFile -Path "$localDir/delay$_.txt" -Length $_ }

            Get-ChildItem -LiteralPath $localDir -Filter 'delay*.txt' |
                Send-WinRSFile @params -Destination { "$remoteDir\delaysend\renamed-$($_.Name)" }

            Get-RemoteDirList "$remoteDir\delaysend" | Should-BeCollection @('renamed-delay1.txt', 'renamed-delay2.txt')
            $expected = 1..2 | ForEach-Object { Get-LocalFileHash "$localDir/delay$_.txt" }
            Get-RemoteFileHash (1..2 | ForEach-Object { "$remoteDir\delaysend\renamed-delay$_.txt" }) | Should-BeCollection $expected
        }

        It "Sends with the destination from a pipeline property" {
            $null = $server | Get-PSSessionSplat
            $null = Invoke-WinRSCommand @params -Command "mkdir $remoteDir\propsend"
            $source = New-TestFile -Path "$localDir/prop.txt" -Length 3

            [PSCustomObject]@{ Path = $source.FullName; Destination = "$remoteDir\propsend\from-property.txt" } |
                Send-WinRSFile @params

            Get-RemoteDirList "$remoteDir\propsend" | Should-Be 'from-property.txt'
            Get-RemoteFileHash "$remoteDir\propsend\from-property.txt" | Should-Be (Get-LocalFileHash $source.FullName)
        }

        It "Receives each piped path to a delay-bound destination" {
            $null = $server | Get-PSSessionSplat
            $sources = 1..2 | ForEach-Object { New-TestFile -Path "$localDir/delayrecv$_.bin" -Length (5 * $_) }
            $sources | Send-WinRSFile @params -Destination $remoteDir
            $backDir = New-Item -Path "$localDir/back" -ItemType Directory

            "$remoteDir\delayrecv1.bin", "$remoteDir\delayrecv2.bin" |
                Receive-WinRSFile @params -Destination { Join-Path $backDir.FullName "copy-$($_.Split('\')[-1])" }

            $expected = $sources | ForEach-Object { Get-LocalFileHash $_.FullName }
            Get-RemoteFileHash "$remoteDir\delayrecv1.bin", "$remoteDir\delayrecv2.bin" | Should-BeCollection $expected
            (Get-ChildItem -LiteralPath $backDir.FullName).Name | Should-BeCollection @('copy-delayrecv1.bin', 'copy-delayrecv2.bin')
            Get-LocalFileHash "$($backDir.FullName)/copy-delayrecv1.bin" | Should-Be $expected[0]
            Get-LocalFileHash "$($backDir.FullName)/copy-delayrecv2.bin" | Should-Be $expected[1]
        }

        It "Uses remote paths literally" {
            $null = $server | Get-PSSessionSplat
            $name = "it's ‘quoted’ %TEMP% & (x) [y].bin"
            $source = New-TestFile -Path "$localDir/special.bin" -Length 20

            Send-WinRSFile @params -Path $source.FullName -Destination "$remoteDir\$name"
            Receive-WinRSFile @params -Path "$remoteDir\$name" -Destination "$localDir/back.bin"

            $expected = Get-LocalFileHash $source.FullName
            Get-RemoteFileHash "$remoteDir\$name" | Should-Be $expected
            Get-LocalFileHash "$localDir/back.bin" | Should-Be $expected
        }

        It "Uses local paths literally" {
            $null = $server | Get-PSSessionSplat
            $source = New-TestFile -Path "$localDir/[literal].bin" -Length 20

            Send-WinRSFile @params -Path $source.FullName -Destination "$remoteDir\literal.bin"
            Receive-WinRSFile @params -Path "$remoteDir\literal.bin" -Destination "$localDir/[back].bin"

            $expected = Get-LocalFileHash $source.FullName
            Get-RemoteFileHash "$remoteDir\literal.bin" | Should-Be $expected
            Get-LocalFileHash "$localDir/[back].bin" | Should-Be $expected
        }

        It "Leaves no temporary files behind" {
            $null = $server | Get-PSSessionSplat
            $null = Invoke-WinRSCommand @params -Command "mkdir $remoteDir\clean"
            $source = New-TestFile -Path "$localDir/clean.bin" -Length 100

            Send-WinRSFile @params -Path $source.FullName -Destination "$remoteDir\clean"
            Send-WinRSFile @params -Path "$localDir/missing.bin" -Destination "$remoteDir\clean" -ErrorAction SilentlyContinue
            Receive-WinRSFile @params -Path "$remoteDir\clean\clean.bin" -Destination "$localDir/back.bin"
            Receive-WinRSFile @params -Path "$remoteDir\clean\missing.bin" -Destination "$localDir/missing.bin" -ErrorAction SilentlyContinue

            Get-RemoteDirList "$remoteDir\clean" | Should-Be 'clean.bin'
            Get-RemoteFileHash "$remoteDir\clean\clean.bin" | Should-Be (Get-LocalFileHash $source.FullName)
            (Get-ChildItem -LiteralPath $localDir -Force).Name | Should-BeCollection @('back.bin', 'clean.bin')
        }

        It "Does not copy with WhatIf" {
            $null = $server | Get-PSSessionSplat
            $source = New-TestFile -Path "$localDir/whatif.bin" -Length 1

            Send-WinRSFile @params -Path $source.FullName -Destination "$remoteDir\whatif.bin" -WhatIf
            Receive-WinRSFile @params -Path "$remoteDir\verbose.bin" -Destination "$localDir/whatif-back.bin" -WhatIf

            Get-RemoteDirList "$remoteDir\whatif.bin" | Should-BeNull
            Test-Path -LiteralPath "$localDir/whatif-back.bin" | Should-BeFalse
        }

        It "Reports a missing remote file and continues with the next one" {
            $null = $server | Get-PSSessionSplat
            $source = New-TestFile -Path "$localDir/exists.bin" -Length 5
            Send-WinRSFile @params -Path $source.FullName -Destination "$remoteDir\exists.bin"
            $backDir = New-Item -Path "$localDir/back" -ItemType Directory

            "$remoteDir\missing.bin", "$remoteDir\exists.bin" |
                Receive-WinRSFile @params -Destination $backDir.FullName -ErrorAction SilentlyContinue -ErrorVariable err

            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRSReceiveFileFailed,PSWSMan.Commands.ReceiveWinRSFile'
            $err[0].Exception | Should-HaveType ([System.Management.Automation.RemoteException])
            $err[0].Exception.Message | Should-BeLikeString "Could not find file '*missing.bin'."
            $err[0].TargetObject | Should-Be "$remoteDir\missing.bin"
            (Get-ChildItem -LiteralPath $backDir.FullName -Force).Name | Should-Be 'exists.bin'
        }

        It "Reports a remote directory as the source" {
            $null = $server | Get-PSSessionSplat

            Receive-WinRSFile @params -Path $remoteDir -Destination "$localDir/dir.bin" -ErrorAction SilentlyContinue -ErrorVariable err

            $err.Count | Should-Be 1
            $err[0].Exception.Message | Should-BeLikeString '*is a directory, only files can be copied.'
            Test-Path -LiteralPath "$localDir/dir.bin" | Should-BeFalse
        }

        It "Reports a missing remote directory" {
            $null = $server | Get-PSSessionSplat
            $source = New-TestFile -Path "$localDir/nodir.bin" -Length 5

            Send-WinRSFile @params -Path $source.FullName -Destination "$remoteDir\missing\nodir.bin" -ErrorAction SilentlyContinue -ErrorVariable err

            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRSSendFileFailed,PSWSMan.Commands.SendWinRSFile'
            $err[0].Exception.Message | Should-BeLikeString "Could not find the directory of '*nodir.bin'."
        }

        It "Rejects a mismatched hash on the remote host" {
            $null = $server | Get-PSSessionSplat
            $asm = [PSWSMan.Commands.SendWinRSFile].Assembly
            $getCommandLine = $asm.GetType('PSWSMan.WinRSPowerShell').GetMethod('GetCommandLine', [System.Reflection.BindingFlags]'Static, NonPublic, Public')
            $cmd = $getCommandLine.Invoke($null, @('SendWinRSFile.ps1', [string[]]@("$remoteDir\bad.bin", 'bad.bin', 'None')))
            [byte[]]$frame = [BitConverter]::GetBytes([long]3) + [byte[]](1, 2, 3) + [byte[]]::new(32)

            $out = , $frame | Invoke-WinRSCommand @params -Command $cmd -ErrorAction SilentlyContinue -ErrorVariable err

            $out | Should-BeNull
            $LASTEXITCODE | Should-Be 1
            $err[0].Exception.Message | Should-BeLikeString '*does not match the sender''s hash 0000000000000000000000000000000000000000000000000000000000000000.'
            Get-RemoteDirList | Should-NotContainCollection 'bad.bin'
        }

        It "Rejects input that ends early on the remote host" {
            $null = $server | Get-PSSessionSplat
            $asm = [PSWSMan.Commands.SendWinRSFile].Assembly
            $getCommandLine = $asm.GetType('PSWSMan.WinRSPowerShell').GetMethod('GetCommandLine', [System.Reflection.BindingFlags]'Static, NonPublic, Public')
            $cmd = $getCommandLine.Invoke($null, @('SendWinRSFile.ps1', [string[]]@("$remoteDir\short.bin", 'short.bin', 'None')))
            [byte[]]$frame = [BitConverter]::GetBytes([long]10) + [byte[]](1, 2, 3)

            $null = , $frame | Invoke-WinRSCommand @params -Command $cmd -ErrorAction SilentlyContinue -ErrorVariable err

            $LASTEXITCODE | Should-Be 1
            $err[0].Exception.Message | Should-Be 'The input ended before the whole file was received.'
            Get-RemoteDirList | Should-NotContainCollection 'short.bin'
        }
    }

    Context "Parameter validation" {
        It "Reports a missing local file without connecting" {
            Send-WinRSFile -ComputerName 'pswsman.invalid' -Path "$TestDrive/missing.bin" -Destination 'C:\temp' -ErrorAction SilentlyContinue -ErrorVariable err

            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRSSendFileFailed,PSWSMan.Commands.SendWinRSFile'
            $err[0].CategoryInfo.Category | Should-Be 'ObjectNotFound'
            $err[0].TargetObject | Should-Be "$TestDrive/missing.bin"
        }

        It "Reports a local directory" {
            Send-WinRSFile -ComputerName 'pswsman.invalid' -Path $TestDrive -Destination 'C:\temp' -ErrorAction SilentlyContinue -ErrorVariable err

            $err.Count | Should-Be 1
            $err[0].Exception.Message | Should-BeLikeString '*is a directory, only files can be copied.'
            $err[0].CategoryInfo.Category | Should-Be 'InvalidArgument'
        }

        It "Reports a path that is not on the file system" {
            Send-WinRSFile -ComputerName 'pswsman.invalid' -Path 'env:PATH' -Destination 'C:\temp' -ErrorAction SilentlyContinue -ErrorVariable err
            Receive-WinRSFile -ComputerName 'pswsman.invalid' -Path 'C:\temp\file.txt' -Destination 'env:PATH' -ErrorAction SilentlyContinue -ErrorVariable +err

            $err.Count | Should-Be 2
            $err[0].Exception.Message | Should-Be "The path 'env:PATH' is not a file system path."
            $err[1].Exception.Message | Should-Be "The path 'env:PATH' is not a file system path."
        }

        It "Reports a missing local directory" {
            Receive-WinRSFile -ComputerName 'pswsman.invalid' -Path 'C:\temp\file.txt' -Destination "$TestDrive/missing/file.txt" -ErrorAction SilentlyContinue -ErrorVariable err

            $err.Count | Should-Be 1
            $err[0].FullyQualifiedErrorId | Should-Be 'WinRSReceiveFileFailed,PSWSMan.Commands.ReceiveWinRSFile'
            $err[0].CategoryInfo.Category | Should-Be 'ObjectNotFound'
        }

        It "Reports a remote path without a file name" {
            Receive-WinRSFile -ComputerName 'pswsman.invalid' -Path 'C:\' -Destination $TestDrive -ErrorAction SilentlyContinue -ErrorVariable err

            $err.Count | Should-Be 1
            $err[0].Exception.Message | Should-Be "The remote path 'C:\' does not have a file name."
        }

        It "Reports a command line too long for cmd.exe with <_>" -ForEach @('Send-WinRSFile', 'Receive-WinRSFile') {
            $file = New-Item -Path "$TestDrive/long.txt" -ItemType File -Force
            $cmdlet = $_
            # The remote path is embedded in the command line, one this long cannot fit in what cmd.exe accepts.
            $remotePath = 'C:\' + ('a' * 8191)
            $params = if ($cmdlet -eq 'Send-WinRSFile') {
                @{ Path = $file.FullName; Destination = $remotePath }
            }
            else {
                @{ Path = $remotePath; Destination = $TestDrive }
            }

            & $cmdlet -ComputerName 'pswsman.invalid' @params -ErrorAction SilentlyContinue -ErrorVariable err

            $err.Count | Should-Be 1
            $err[0].Exception.Message | Should-BeLikeString 'The remote PowerShell command line is * characters, more than the 8191 cmd.exe accepts. Use shorter paths.'
            $err[0].FullyQualifiedErrorId | Should-BeLikeString 'WinRS*FileFailed,PSWSMan.Commands.*WinRSFile'
            $err[0].CategoryInfo.Category | Should-Be 'InvalidArgument'
            Get-ChildItem -LiteralPath $TestDrive -Filter '.*.tmp' -Force | Should-BeNull
        }

        It "Does not connect with WhatIf" {
            $file = New-Item -Path "$TestDrive/whatif.txt" -ItemType File -Force

            Send-WinRSFile -ComputerName 'pswsman.invalid' -Path $file.FullName -Destination 'C:\temp' -WhatIf
            Receive-WinRSFile -ComputerName 'pswsman.invalid' -Path 'C:\temp\file.txt' -Destination $TestDrive -WhatIf
        }

        It "Fails with a terminating error when the host cannot be reached with <_>" -ForEach @('Send-WinRSFile', 'Receive-WinRSFile') {
            $file = New-Item -Path "$TestDrive/unreachable.txt" -ItemType File -Force
            $cmdlet = $_
            $source = if ($cmdlet -eq 'Send-WinRSFile') { $file.FullName } else { 'C:\temp\file.txt' }
            $cmd = { & $cmdlet -ComputerName 'pswsman.invalid' -Path $source -Destination $TestDrive -ErrorAction Stop }

            $err = $cmd | Should-Throw
            $err.FullyQualifiedErrorId | Should-BeLikeString 'WinRSCommandFailed,PSWSMan.Commands.*WinRSFile'
            $err.TargetObject | Should-Be 'pswsman.invalid'
        }

        It "Fails with a ConnectionUri that is not an absolute http or https URI with <_>" -ForEach @('Send-WinRSFile', 'Receive-WinRSFile') {
            $cmdlet = $_
            $cmd = { & $cmdlet -ConnectionUri 'ftp://pswsman.invalid' -Path 'file.txt' -Destination $TestDrive }

            $err = $cmd | Should-Throw -ExceptionMessage '*must be an absolute http or https URI*'
            $err.FullyQualifiedErrorId | Should-BeLikeString 'WinRSCommandInvalidParameter,PSWSMan.Commands.*WinRSFile'
        }

        It "Fails when CertificateThumbprint is used with Credential with <_>" -ForEach @('Send-WinRSFile', 'Receive-WinRSFile') {
            $cmdlet = $_
            $cred = [PSCredential]::new('user', (ConvertTo-SecureString -AsPlainText -Force 'pass'))
            $cmd = { & $cmdlet -ComputerName 'pswsman.invalid' -UseSSL -Credential $cred -CertificateThumbprint 'ABC' -Path 'file.txt' -Destination $TestDrive }

            $cmd | Should-Throw -ExceptionMessage '*Credential parameter and the CertificateThumbprint parameter cannot be used together*'
        }
    }
}
