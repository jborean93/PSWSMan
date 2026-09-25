BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

BeforeAll {
    Function Assert-PSWSManSession {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [hashtable]
            $SessionParams,

            [string]
            $ConfigurationName = 'Microsoft.PowerShell'
        )

        $s = New-PSSession @SessionParams
        try {
            $s.ComputerName | Should-Be $SessionParams.ComputerName
            $s.State | Should-Be 'Opened'
            $s.ConfigurationName | Should-Be $ConfigurationName
        }
        finally {
            $s | Remove-PSSession
        }

        $s.State | Should-Be 'Closed'
    }
}

Describe "PSWSMan Connection tests" {
    # Negotiate picks Kerberos for a domain account and NTLM for a local one.
    It "Connects with Negotiate - <_>" -ForEach (Get-PSWSManTestServer -AnyAuth Kerberos, NTLM) {
        $sessionParams = $_ | Get-PSSessionSplat

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects with Kerberos - <_>" -ForEach (Get-PSWSManTestServer -Auth Kerberos) {
        $sessionParams = $_ | Get-PSSessionSplat
        $sessionParams.Authentication = 'Kerberos'

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    # NTLM with the System provider needs SSPI, GSS.framework, or gss-ntlmssp with MIT krb5.
    It "Connects with NTLM - <_>" -ForEach (Get-PSWSManTestServer -Auth NTLM) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ AuthMethod = 'NTLM' }

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects with CredSSP - <_>" -ForEach (Get-PSWSManTestServer -Auth CredSSP) {
        $sessionParams = $_ | Get-PSSessionSplat
        $sessionParams.Authentication = 'Credssp'

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects with CredSSP + Kerberos - <_>" -ForEach (Get-PSWSManTestServer -Auth CredSSP, Kerberos) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{
            AuthMethod = 'CredSSP'
            CredSSPAuthMethod = 'Kerberos'
        }

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects with CredSSP + NTLM - <_>" -ForEach (Get-PSWSManTestServer -Auth CredSSP, NTLM) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{
            AuthMethod = 'CredSSP'
            CredSSPAuthMethod = 'NTLM'
        }

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects with Devolutions Negotiate - <_>" -ForEach (Get-PSWSManTestServer -AnyAuth Kerberos, NTLM) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ AuthProvider = 'Devolutions' }

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects with Devolutions Kerberos - <_>" -ForEach (Get-PSWSManTestServer -Auth Kerberos) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ AuthProvider = 'Devolutions' }
        $sessionParams.Authentication = 'Kerberos'

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects with Devolutions NTLM - <_>" -ForEach (Get-PSWSManTestServer -Auth NTLM) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{
            AuthMethod = 'NTLM'
            AuthProvider = 'Devolutions'
        }

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects with Devolutions CredSSP - <_>" -ForEach (Get-PSWSManTestServer -Auth CredSSP) {
        if ($IsWindows) {
            # https://github.com/Devolutions/sspi-rs/issues/752
            Set-ItResult -Skipped -Because 'Devolutions CredSSP using NTLM through Negotiate does not work, will need upstream fix'
        }
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ AuthProvider = 'Devolutions' }
        $sessionParams.Authentication = 'Credssp'

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects with Devolutions CredSSP + Kerberos - <_>" -ForEach (Get-PSWSManTestServer -Auth CredSSP, Kerberos) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{
            AuthMethod = 'CredSSP'
            CredSSPAuthMethod = 'Kerberos'
            AuthProvider = 'Devolutions'
        }

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects with Devolutions CredSSP + NTLM - <_>" -ForEach (Get-PSWSManTestServer -Auth CredSSP, NTLM) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{
            AuthMethod = 'CredSSP'
            CredSSPAuthMethod = 'NTLM'
            AuthProvider = 'Devolutions'
        }

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    # The scheme, host, port and application name all come from the URI rather than the separate parameters.
    It "Connects with ConnectionUri - <_>" -ForEach (Get-PSWSManTestServer) {
        $splat = $_ | Get-PSSessionSplat
        $sessionParams = @{
            ConnectionUri = $_.Uri
            Credential = $splat.Credential
        }
        if ($splat.SessionOption) {
            $sessionParams.SessionOption = $splat.SessionOption
        }

        $s = New-PSSession @sessionParams
        try {
            $s.ComputerName | Should-Be $_.Uri.Host
            $s.State | Should-Be 'Opened'
            $s.Runspace.ConnectionInfo.ConnectionUri | Should-Be $_.Uri
            $s.Runspace.ConnectionInfo.Port | Should-Be $_.Uri.Port
            $s.Runspace.ConnectionInfo.Scheme | Should-Be $_.Uri.Scheme

            Invoke-Command -Session $s -ScriptBlock { 'ok' } | Should-Be 'ok'
        }
        finally {
            $s | Remove-PSSession
        }

        $s.State | Should-Be 'Closed'
    }

    It "Connects with Basic - <_>" -ForEach (Get-PSWSManTestServer -Auth Basic) {
        $optionParams = @{}
        if ($_.Uri.Scheme -eq 'http') {
            $optionParams.NoEncryption = $true
        }
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption $optionParams
        $sessionParams.Authentication = 'Basic'

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Fails to connect over HTTP with Basic without -NoEncryption - <_>" -ForEach (Get-PSWSManTestServer -Scheme Http -First) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ AuthMethod = 'Basic' }

        { New-PSSession @sessionParams } | Should-Throw -ExceptionMessage '*Cannot encrypt WSMan payload as BasicAuthContext does not support message encryption*'
    }

    It "Connects over CredSSP with handshake failure - <_>" -ForEach (Get-PSWSManTestServer -Auth CredSSP -First) {
        $tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
            EnabledSslProtocols = 'Ssl3'  # Forces an unsupported TLS protocol
            TargetHost = $_.Uri.Host
            RemoteCertificateValidationCallback = New-PSWSManCertValidationCallback { $true }
        }
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ CredSSPTlsOption = $tlsOption }
        $sessionParams.Authentication = 'Credssp'

        $out = New-PSSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should-BeNull
        $err.Count | Should-Be 1

        $expected = 'TLS handshake failure:'
        [string]$err[0] | Should-BeLikeString "*$expected*"
    }

    It "Connects with invalid credential - <_>" -ForEach (Get-PSWSManTestServer -First) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ NoEncryption = $true }
        $sessionParams.Authentication = 'Basic'
        $sessionParams.Credential = [PSCredential]::new('fake', (ConvertTo-SecureString -AsPlainText -Force -String 'fake'))

        $out = New-PSSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should-BeNull
        $err.Count | Should-Be 1
        [string]$err[0] | Should-BeLikeString '*WinRM Basic authentication failure*'
    }

    # A remote host with a firewall drops the packets and the connect times out, a server on the local machine
    # refuses the connection straight away instead. Both are reported as a connection failure.
    It "Connects with invalid port and timeout - <_>" -ForEach (Get-PSWSManTestServer -First) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{
            OpenTimeout = 1
            NoEncryption = $true
        }
        $sessionParams.Port = 12658

        $out = New-PSSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should-BeNull
        $err.Count | Should-Be 1
        [string]$err[0] | Should-MatchString 'A connection could not be established within the configured ConnectTimeout|actively refused|Connection refused'
    }

    # Connecting by IP address makes the certificate name check fail on any HTTPS server, and on a server with an
    # untrusted certificate the chain check fails as well. SPNHostName keeps Kerberos working against the real name.
    It "Connects over HTTPS with invalid cert - <Method> - <Server>" -ForEach $(
        foreach ($server in (Get-PSWSManTestServer -Scheme Https)) {
            foreach ($method in 'Skip', 'TlsOption') {
                @{ Server = $server; Method = $method }
            }
        }
    ) {
        $sessionParams = $Server | Get-PSSessionSplat
        $sessionParams.ComputerName = [System.Net.Dns]::GetHostAddresses($Server.Uri.Host) |
            Where-Object AddressFamily -eq InterNetwork |
            Select-Object -First 1 -ExpandProperty IPAddressToString

        # Explicit SessionOption disables any certificate validation bypass on the server setting.
        # This is done on purpose to ensure that the certificate validation bypass is not applied elsewhere.
        $sessionParams.SessionOption = New-PSWSManSessionOption -SPNHostName $Server.Uri.Host

        $out = New-PSSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should-BeNull
        $err.Count | Should-Be 1
        [string]$err[0] | Should-BeLikeString '*The remote certificate is invalid*RemoteCertificateNameMismatch*'

        $optionParams = @{ SPNHostName = $Server.Uri.Host }
        if ($Method -eq 'Skip') {
            $optionParams.SkipCNCheck = $true
        }
        else {
            $optionParams.TlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
                TargetHost = $sessionParams.ComputerName
                RemoteCertificateValidationCallback = New-PSWSManCertValidationCallback { $true }
            }
        }
        $sessionParams.SessionOption = ($Server | Get-PSSessionSplat -SessionOption $optionParams).SessionOption

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects over HTTPS by IP with skip checks - <_>" -ForEach (Get-PSWSManTestServer -Scheme Https) {
        $sessionParams = $_ | Get-PSSessionSplat

        # Connecting by IP is enough to trigger a validation error. We cannot
        # guarantee that the CA is trusted or untrusted so we assume it isn't.
        $sessionParams.ComputerName = [System.Net.Dns]::GetHostAddresses($_.Uri.Host) |
            Where-Object AddressFamily -eq InterNetwork |
            Select-Object -First 1 -ExpandProperty IPAddressToString

        # SPNHostName keeps Kerberos working against the real name while connecting to the IP.
        $sessionParams.SessionOption = New-PSWSManSessionOption -SPNHostName $_.Uri.Host
        $out = New-PSSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should-BeNull
        $err.Count | Should-Be 1
        [string]$err[0] | Should-BeLikeString '*The remote certificate is invalid*RemoteCertificateNameMismatch*'

        $sessionParams.SessionOption = New-PSWSManSessionOption -SPNHostName $_.Uri.Host -SkipCACheck -SkipCNCheck
        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Failed to find certificate thumbprint - <_>" -ForEach (Get-PSWSManTestServer -First) {
        $sessionParams = $_ | Get-PSSessionSplat
        $sessionParams.Remove('Credential')
        $sessionParams.UseSSL = $true
        $sessionParams.CertificateThumbprint = '0000000000000000000000000000000000000000'

        {
            New-PSSession @sessionParams
        } | Should-Throw
    }

    It "Connects with Certificate auth by cert object - <_>" -ForEach (Get-PSWSManTestServer -Auth Certificate) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ ClientCertificate = $_.ClientCertificate }
        $sessionParams.Remove('Credential')

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects with cert auth and explicit TLS options - <_>" -ForEach (Get-PSWSManTestServer -Auth Certificate) {
        $sessionParams = $_ | Get-PSSessionSplat
        $sessionParams.Remove('Credential')

        # TlsOption replaces the certificate validation the splat would set up so it can be added afterwards.
        $tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
            TargetHost = $sessionParams.ComputerName
            RemoteCertificateValidationCallback = New-PSWSManCertValidationCallback { $true }
            ClientCertificates = [System.Security.Cryptography.X509Certificates.X509CertificateCollection]::new(
                @($_.ClientCertificate))
        }
        $sessionParams.SessionOption = New-PSWSManSessionOption -TlsOption $tlsOption

        Assert-PSWSManSession -SessionParams $sessionParams
    }

    It "Connects over HTTPS with handshake failure - <_>" -ForEach (Get-PSWSManTestServer -Scheme Https -First) {
        $tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
            EnabledSslProtocols = 'Ssl3'
            TargetHost = $_.Uri.Host
            RemoteCertificateValidationCallback = New-PSWSManCertValidationCallback { $true }
        }
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ TlsOption = $tlsOption }

        $out = New-PSSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should-BeNull
        $err.Count | Should-Be 1
        if ($IsMacOS) {
            [string]$err[0] | Should-BeLikeString '*Connection reset by peer*'
        }
        else {
            [string]$err[0] | Should-BeLikeString '*Authentication failed, see inner exception*'
        }
    }
}

Describe "PSWSMan Kerberos tests - <_>" -ForEach (Get-PSWSManTestServer -Auth Kerberos -First) {
    BeforeAll {
        Function Get-RemoteTicketFlags {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory)]
                [hashtable]
                $SessionParams
            )

            Invoke-Command @SessionParams {
                C:\Windows\System32\klist.exe |
                    Select-String -Pattern 'Ticket Flags.*->\s*(.*)' |
                    ForEach-Object { ($_.Matches.Groups[1].Value -split '\s+') -ne '' }
            }
        }
    }

    It "Connects with implicit credential with Linux" -Skip:$IsWindows {
        $sessionParams = $_ | Get-PSSessionSplat
        Invoke-Kinit -Credential $sessionParams.Credential

        try {
            $sessionParams.Remove('Credential')

            $actual = Get-RemoteTicketFlags -SessionParams $sessionParams
            $actual | Should-NotContainCollection 'forwarded'
        }
        finally {
            kdestroy
        }
    }

    It "Connects with implicit forwardable credential with Linux" -Skip:$IsWindows {
        $sessionParams = $_ | Get-PSSessionSplat
        Invoke-Kinit -Credential $sessionParams.Credential -Forwardable

        try {
            $sessionParams.Remove('Credential')

            $actual = Get-RemoteTicketFlags -SessionParams $sessionParams
            $actual | Should-NotContainCollection 'forwarded'
        }
        finally {
            kdestroy
        }
    }

    It "Connects with implicit forwardable credential with delegation Linux" -Skip:$IsWindows {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ RequestKerberosDelegate = $true }
        Invoke-Kinit -Credential $sessionParams.Credential -Forwardable

        try {
            $sessionParams.Remove('Credential')

            $actual = Get-RemoteTicketFlags -SessionParams $sessionParams
            $actual | Should-ContainCollection 'forwarded'
        }
        finally {
            kdestroy
        }
    }

    It "Connects with implicit credentials with Windows" -Skip:(-not $IsWindows) {
        $sessionParams = $_ | Get-PSSessionSplat
        $sessionParams.Remove('Credential')

        $actual = Get-RemoteTicketFlags -SessionParams $sessionParams
        $actual | Should-NotContainCollection 'forwarded'
    }

    It "Connects with explicit credentials with Windows" -Skip:(-not $IsWindows) {
        $sessionParams = $_ | Get-PSSessionSplat

        $actual = Get-RemoteTicketFlags -SessionParams $sessionParams
        $actual | Should-NotContainCollection 'forwarded'
    }

    # Windows only delegates to a server marked as trusted for delegation.
    It "Connects with implicit credentials with Windows and delegate - <_>" -Skip:(-not $IsWindows) -ForEach (
        Get-PSWSManTestServer -Auth Kerberos -TrustedForDelegation -First
    ) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ RequestKerberosDelegate = $true }
        $sessionParams.Remove('Credential')

        $actual = Get-RemoteTicketFlags -SessionParams $sessionParams
        $actual | Should-ContainCollection 'forwarded'
    }

    It "Connects with explicit credentials with Windows and delegate - <_>" -Skip:(-not $IsWindows) -ForEach (
        Get-PSWSManTestServer -Auth Kerberos -TrustedForDelegation -First
    ) {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ RequestKerberosDelegate = $true }

        $actual = Get-RemoteTicketFlags -SessionParams $sessionParams
        $actual | Should-ContainCollection 'forwarded'
    }
}

Describe "PSWSMan PSRemoting tests - <_>" -ForEach (Get-PSWSManTestServer -First) {
    BeforeEach {
        $sessionParams = $_ | Get-PSSessionSplat
    }

    It "Connects to JEA configuration - <_>" -ForEach (Get-PSWSManTestServer -JEA -First) {
        $sessionParams = $_ | Get-PSSessionSplat
        $sessionParams.ConfigurationName = $_.JEAName

        $s = New-PSSession @sessionParams
        try {
            $s.ComputerName | Should-Be $sessionParams.ComputerName
            $s.State | Should-Be 'Opened'
            $s.ConfigurationName | Should-Be $_.JEAName
            # A JEA session is NoLanguage so only a bare command can run, the role exposes this function.
            # The virtual account name contains a per session counter so only the prefix is checked.
            $out = Invoke-Command -Session $s -ScriptBlock { Get-PSWSManJeaUserName }
            $out | Should-BeLikeString 'WinRM VA_*'
        }
        finally {
            $s | Remove-PSSession
        }

        $s.State | Should-Be 'Closed'
    }

    It "Connects with large ApplicationArguments data" {
        $appArgs = @{Key = 'a' * 1MB }

        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ ApplicationArguments = $appArgs }
        $actual = Invoke-Command @sessionParams -ScriptBlock { $PSSenderInfo.ApplicationArguments }

        $actual.Key.Length | Should-Be 1MB
        $actual.Key | Should-Be ('a' * 1MB)
    }

    It "Runs command with large Command data" {
        $actual = Invoke-Command @sessionParams -ScriptBlock { $args[0] } -ArgumentList ('a' * 1MB)

        $actual.Length | Should-Be 1MB
        $actual | Should-Be ('a' * 1MB)
    }

    It "Pipes data into command" {
        $actual = ('a' * 1MB) | Invoke-Command @sessionParams -ScriptBlock { process { $_ } }

        $actual.Length | Should-Be 1MB
        $actual | Should-Be ('a' * 1MB)
    }

    It "Responds to user events" {
        $eventParams = @{
            EventName = "PSEventReceived"
            SourceIdentifier = "PSWSMan.UserEvent"
        }

        $session = New-PSSession @sessionParams
        try {
            $customEvent = Register-ObjectEvent -InputObject $session.Runspace.Events.ReceivedEvents @eventParams

            Invoke-Command -Session $session -ScriptBlock {
                $null = $Host.Runspace.Events.SubscribeEvent(
                    $null,
                    "PSWSManEvent",
                    "PSWSManEvent",
                    $null,
                    $null,
                    $true,
                    $true)
                $null = $Host.Runspace.Events.GenerateEvent(
                    "PSWSManEvent",
                    "sender",
                    @("my", "args"),
                    "extra data")
            }

            $actual = Wait-Event -SourceIdentifier $eventParams.SourceIdentifier -Timeout 1 | Select-Object *
        }
        finally {
            if ($customEvent) {
                Unregister-Event -SourceIdentifier $eventParams.SourceIdentifier
            }
            $session | Remove-PSSession
        }

        $actual | Should-NotBeNull
        $actual.Sender.ComputerName | Should-Be $session.ComputerName
        $actual.SourceIdentifier | Should-Be PSWSMan.UserEvent
        $actual.SourceArgs[0] | Should-Be sender
        $actual.SourceArgs[1].RunspaceId | Should-Be $session.Runspace.InstanceId
        $actual.SourceArgs[1].SourceArgs | Should-BeCollection @('my', 'args')
    }

    It "Receives a SecureString" {
        $actual = Invoke-Command @sessionParams -ScriptBlock { ConvertTo-SecureString -AsPlainText -Force -String secret }

        $actual.Length | Should-Be 6
        [PSCredential]::new('dummy', $actual).GetNetworkCredential().Password | Should-Be secret
    }

    It "Sends a SecureString" {
        $ss = ConvertTo-SecureString -AsPlainText -Force -String secret
        $actual = Invoke-Command @sessionParams -ScriptBlock {
            param([securestring]$obj)

            $obj.GetType().FullName
            [PSCredential]::new('dummy', $obj).GetNetworkCredential().Password
        } -ArgumentList $ss

        $actual[0] | Should-Be System.Security.SecureString
        $actual[1] | Should-Be secret
    }

    It "Receives a CimInstance" {
        $actual = Invoke-Command @sessionParams -ScriptBlock {
            Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $pid"
        }

        $actual | Should-NotBeNull
        $actual.Name | Should-Be 'wsmprovhost.exe'
        $actual.ProcessId | Should-HaveType ([uint32])
        $actual.PSComputerName | Should-Be $sessionParams.ComputerName
        $actual.PSObject.Properties.Name | Should-NotContainCollection '__ClassMetadata'
        $actual.PSObject.Properties.Name | Should-NotContainCollection '__InstanceMetadata'

        if ($IsWindows) {
            # The OS provides the MI library so PowerShell rehydrates a live CimInstance
            $actual.PSObject.BaseObject | Should-HaveType ([Microsoft.Management.Infrastructure.CimInstance])
            $actual.PSTypeNames[0] | Should-Be 'Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process'
        }
        else {
            # PSWSMan skips the libmi based rehydration and keeps the deserialized property bag
            $actual.PSObject.BaseObject | Should-HaveType ([System.Management.Automation.PSCustomObject])
            $actual.PSTypeNames[0] | Should-Be 'Deserialized.Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process'
        }
    }

    It "Sets max and min runspaces" {
        $connInfo = [System.Management.Automation.Runspaces.WSManConnectionInfo]@{
            Scheme = $_.Uri.Scheme
            ComputerName = $sessionParams.ComputerName
            Port = $sessionParams.Port
            Credential = $sessionParams.Credential
        }

        $rp = [runspacefactory]::CreateRunspacePool(2, 5, $connInfo)
        $rp.Open()
        try {
            $rp.SetMaxRunspaces(1) | Should-BeFalse
            $rp.SetMaxRunspaces(5) | Should-BeFalse
            $rp.SetMaxRunspaces(4) | Should-BeTrue

            $rp.SetMinRunspaces(6) | Should-BeFalse
            $rp.SetMinRunspaces(2) | Should-BeFalse
            $rp.SetMinRunspaces(1) | Should-BeTrue

            $rp.GetAvailableRunspaces() | Should-Be 4
        }
        finally {
            $rp.Dispose()
        }
    }

    It "Resets runspace" {
        $session = New-PSSession @sessionParams

        try {
            Invoke-Command -Session $session -ScriptBlock { $global:test = 'foo' }

            $out = Invoke-Command -Session $session -ScriptBlock { $global:test }
            $out | Should-Be foo

            $session.Runspace.ResetRunspaceState()

            $out = Invoke-Command -Session $session -ScriptBlock { $global:test }
            $out | Should-BeNull
        }
        finally {
            $session | Remove-PSSession
        }
    }

    It "Stops a running pipeline" {
        $session = New-PSSession @sessionParams

        try {
            $ps = [PowerShell]::Create()
            $ps.Runspace = $session.Runspace
            $null = $ps.AddScript("'started'; sleep 10")

            # Wait for the first output so the command is known to be running on the server before it is stopped.
            # Even then either the local or the remote stop can be the one EndInvoke reports, depending on which
            # completes first, so only the shared part of the message is checked.
            $output = [System.Management.Automation.PSDataCollection[psobject]]::new()
            $task = $ps.BeginInvoke([System.Management.Automation.PSDataCollection[psobject]]::new(), $output)
            while ($output.Count -eq 0 -and $ps.InvocationStateInfo.State -eq 'Running') {
                Start-Sleep -Milliseconds 50
            }
            $output[0] | Should-Be started

            $start = Get-Date
            $ps.Stop()

            $err = $null
            try {
                $ps.EndInvoke($task)
            }
            catch {
                $err = $_
            }

            $elapsed = (Get-Date) - $start

            $ps.InvocationStateInfo.State | Should-Be Stopped
            $session.State | Should-Be Opened
            Invoke-Command -Session $session -ScriptBlock { 'still alive' } | Should-Be 'still alive'
        }
        finally {
            $session | Remove-PSSession
        }

        $elapsed.TotalSeconds | Should-BeLessThan 10
        $err | Should-NotBeNull
        [string]$err | Should-BeLikeString '*pipeline has been stopped*'
    }

    It "Stops a pipeline before it starts and keeps the session usable" {
        $session = New-PSSession @sessionParams

        try {
            $ps = [PowerShell]::Create()
            $ps.Runspace = $session.Runspace
            $null = $ps.AddScript('sleep 10')

            # Stopping this early races the command creation on the server. Either the local or the remote stop
            # message is acceptable, what matters is the session can still run commands afterwards.
            $task = $ps.BeginInvoke()
            $ps.Stop()

            $err = $null
            try {
                $ps.EndInvoke($task)
            }
            catch {
                $err = $_
            }

            $ps.InvocationStateInfo.State | Should-Be Stopped
            [string]$err | Should-BeLikeString '*pipeline has been stopped*'

            $session.State | Should-Be Opened
            Invoke-Command -Session $session -ScriptBlock { 'still alive' } | Should-Be 'still alive'
        }
        finally {
            $session | Remove-PSSession
        }
    }

    It "Runs commands concurrently on a runspace pool" {
        $connInfo = [System.Management.Automation.Runspaces.WSManConnectionInfo]@{
            Scheme = $_.Uri.Scheme
            ComputerName = $sessionParams.ComputerName
            Port = $sessionParams.Port
            Credential = $sessionParams.Credential
        }
        if ($sessionParams.SessionOption) {
            $connInfo.SetSessionOptions($sessionParams.SessionOption)
        }

        $rp = [runspacefactory]::CreateRunspacePool(1, 3, $connInfo)
        $rp.Open()
        try {
            $start = Get-Date
            $pipelines = foreach ($i in 1..3) {
                $ps = [PowerShell]::Create()
                $ps.RunspacePool = $rp
                $null = $ps.AddScript("sleep 3; $i")
                @{ PowerShell = $ps; Task = $ps.BeginInvoke() }
            }
            $actual = foreach ($p in $pipelines) {
                try {
                    $p.PowerShell.EndInvoke($p.Task)
                }
                finally {
                    $p.PowerShell.Dispose()
                }
            }
            $elapsed = (Get-Date) - $start
        }
        finally {
            $rp.Dispose()
        }

        $actual | Should-BeCollection @(1, 2, 3)
        # Three serial sleeps would take at least 9 seconds.
        $elapsed.TotalSeconds | Should-BeLessThan 8
    }

    It "Receives output from a command that outlives the operation timeout" {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ OperationTimeout = 3000 }

        $start = Get-Date
        $actual = Invoke-Command @sessionParams -ScriptBlock { Start-Sleep -Seconds 7; 'done' }
        $elapsed = (Get-Date) - $start

        $actual | Should-Be done
        $elapsed.TotalSeconds | Should-BeGreaterThan 6
    }

    It "Receives large output" {
        $actual = Invoke-Command @sessionParams -ScriptBlock { 'a' * 10MB }
        $actual.Length | Should-Be 10MB

        $actual = Invoke-Command @sessionParams -ScriptBlock {
            1..5000 | ForEach-Object { [PSCustomObject]@{ Index = $_; Data = 'x' * 100 } }
        }
        $actual.Count | Should-Be 5000
        $actual[-1].Index | Should-Be 5000
        $actual[-1].Data.Length | Should-Be 100
    }

    It "Fails when output exceeds MaximumReceivedObjectSize" {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ MaximumReceivedObjectSize = 1MB }

        {
            Invoke-Command @sessionParams -ScriptBlock { 'a' * 2MB } -ErrorAction Stop
        } | Should-Throw -ExceptionMessage '*exceeded the allowed maximum object size*'
    }

    It "Receives the remote streams" {
        $session = New-PSSession @sessionParams

        try {
            $ps = [PowerShell]::Create()
            $ps.Runspace = $session.Runspace
            $null = $ps.AddScript({
                    $VerbosePreference = 'Continue'
                    $DebugPreference = 'Continue'
                    $InformationPreference = 'Continue'
                    $ProgressPreference = 'Continue'

                    Write-Warning -Message 'warning message'
                    Write-Verbose -Message 'verbose message'
                    Write-Debug -Message 'debug message'
                    Write-Information -MessageData 'information message'
                    Write-Host 'host message'
                    Write-Progress -Activity 'activity' -Status 'status' -PercentComplete 50 -Id 7
                    Write-Error -Message 'error message' -ErrorId MyErrorId -TargetObject 'target'
                    'output'
                })

            $actual = $ps.Invoke()

            $actual | Should-Be output
            $ps.Streams.Warning.Message | Should-Be 'warning message'
            $ps.Streams.Verbose.Message | Should-Be 'verbose message'
            $ps.Streams.Debug.Message | Should-Be 'debug message'

            $information = @($ps.Streams.Information | Where-Object Tags -NotContains PSHOST)
            $information.Count | Should-Be 1
            $information[0].MessageData | Should-Be 'information message'
            $hostOutput = @($ps.Streams.Information | Where-Object Tags -Contains PSHOST)
            $hostOutput.Count | Should-Be 1
            $hostOutput[0].MessageData | Should-Be 'host message'

            # The server may add its own progress records, like preparing modules for first use.
            $progress = @($ps.Streams.Progress | Where-Object ActivityId -eq 7)
            $progress.Count | Should-Be 1
            $progress[0].Activity | Should-Be activity
            $progress[0].StatusDescription | Should-Be status
            $progress[0].PercentComplete | Should-Be 50

            $ps.Streams.Error.Count | Should-Be 1
            $ps.Streams.Error[0].Exception | Should-HaveType ([System.Management.Automation.RemoteException])
            $ps.Streams.Error[0].Exception.Message | Should-Be 'error message'
            $ps.Streams.Error[0].FullyQualifiedErrorId | Should-Be MyErrorId
            $ps.Streams.Error[0].TargetObject | Should-Be target
        }
        finally {
            $session | Remove-PSSession
        }
    }

    It "Receives a remote terminating error" {
        $err = $null
        try {
            Invoke-Command @sessionParams -ScriptBlock { throw 'remote failure' }
        }
        catch {
            $err = $_
        }

        $err | Should-NotBeNull
        $err.Exception | Should-HaveType ([System.Management.Automation.RemoteException])
        $err.Exception.Message | Should-Be 'remote failure'
        $err.FullyQualifiedErrorId | Should-Be 'remote failure'
        $err.CategoryInfo.Category | Should-Be OperationStopped
        $err.TargetObject | Should-Be 'remote failure'
    }

    It "Stops on a remote non-terminating error with ErrorAction Stop" {
        $err = $null
        try {
            Invoke-Command @sessionParams -ScriptBlock { Write-Error -Message 'stop here' -ErrorId StopId } -ErrorAction Stop
        }
        catch {
            $err = $_
        }

        $err | Should-NotBeNull
        $err.Exception | Should-HaveType ([System.Management.Automation.RemoteException])
        $err.Exception.Message | Should-Be 'stop here'
        $err.FullyQualifiedErrorId | Should-Be 'StopId,Microsoft.PowerShell.Commands.WriteErrorCommand'
    }

    It "Round trips a host call" {
        # Reading and writing the window title goes through the client host as PSRP host calls.
        $originalTitle = $Host.UI.RawUI.WindowTitle
        $expected = "PSWSMan $([Guid]::NewGuid())"
        try {
            $actual = Invoke-Command @sessionParams -ScriptBlock {
                $Host.UI.RawUI.WindowTitle = $using:expected
                $Host.UI.RawUI.WindowTitle
                $Host.UI.RawUI.ForegroundColor
            }

            $actual[0] | Should-Be $expected
            $Host.UI.RawUI.WindowTitle | Should-Be $expected
            $actual[1] | Should-Be $Host.UI.RawUI.ForegroundColor
        }
        finally {
            $Host.UI.RawUI.WindowTitle = $originalTitle
        }
    }

    It "Skips the user profile with NoMachineProfile" {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{ NoMachineProfile = $true }

        $actual = Invoke-Command @sessionParams -ScriptBlock { $env:USERPROFILE }
        $actual | Should-Be 'C:\Windows\System32\config\systemprofile'

        $sessionParams = $_ | Get-PSSessionSplat
        $actual = Invoke-Command @sessionParams -ScriptBlock { $env:USERPROFILE }
        $actual | Should-NotBe 'C:\Windows\System32\config\systemprofile'
    }

    It "Applies the culture options" {
        $sessionParams = $_ | Get-PSSessionSplat -SessionOption @{
            Culture = 'fr-FR'
            UICulture = 'de-DE'
        }

        $actual = Invoke-Command @sessionParams -ScriptBlock { (Get-Culture).Name; (Get-UICulture).Name }

        $actual[0] | Should-Be fr-FR
        $actual[1] | Should-Be de-DE
    }

    It "Reports the CustomTransport capability without disconnect support" {
        $session = New-PSSession @sessionParams
        try {
            # CommandCompletion.CompleteInput skips tab completion when the capabilities are Default.
            $caps = $session.Runspace.GetCapabilities()
            $caps | Should-NotBe ([System.Management.Automation.Runspaces.RunspaceCapability]::Default)
            $caps.HasFlag([System.Management.Automation.Runspaces.RunspaceCapability]::CustomTransport) | Should-BeTrue

            # Disconnect is not implemented so the capability must not be advertised.
            $caps.HasFlag([System.Management.Automation.Runspaces.RunspaceCapability]::SupportsDisconnect) | Should-BeFalse
        }
        finally {
            $session | Remove-PSSession
        }
    }

    It "Completes input through the remote runspace" {
        $session = New-PSSession @sessionParams
        try {
            # A variable that only exists in the remote runspace proves the
            # completion ran there rather than locally.
            Invoke-Command -Session $session -ScriptBlock { $global:PSWSManCompletionTest = 1 }

            $ps = [PowerShell]::Create()
            try {
                $ps.Runspace = $session.Runspace

                $text = 'Get-ChildIte'
                $actual = [System.Management.Automation.CommandCompletion]::CompleteInput($text, $text.Length, $null, $ps)
                $actual.CompletionMatches.CompletionText | Should-ContainCollection 'Get-ChildItem'

                $text = 'Get-ChildItem -Pat'
                $actual = [System.Management.Automation.CommandCompletion]::CompleteInput($text, $text.Length, $null, $ps)
                $actual.CompletionMatches.CompletionText | Should-ContainCollection '-Path'

                $text = '$PSWSManCompletionTes'
                $actual = [System.Management.Automation.CommandCompletion]::CompleteInput($text, $text.Length, $null, $ps)
                $actual.CompletionMatches.CompletionText | Should-Be '$PSWSManCompletionTest'
            }
            finally {
                $ps.Dispose()
            }
        }
        finally {
            $session | Remove-PSSession
        }
    }

    It "Fails to disconnect a session" {
        $session = New-PSSession @sessionParams
        try {
            { $session.Runspace.Disconnect() } | Should-Throw -ExceptionMessage '*disconnection operation is not supported on the remote computer*'
            { $session.Runspace.DisconnectAsync() } | Should-Throw -ExceptionMessage '*disconnection operation is not supported on the remote computer*'

            # Disconnect-PSSession only exists on Windows.
            if (Get-Command -Name Disconnect-PSSession -ErrorAction SilentlyContinue) {
                $err = $null
                Disconnect-PSSession -Session $session -ErrorAction SilentlyContinue -ErrorVariable err
                $err.Count | Should-Be 1
                $err[0].FullyQualifiedErrorId | Should-BeLikeString 'PSSessionDisconnectFailed,*'
                $err[0].Exception.Message | Should-BeLikeString '*disconnection operation is not supported on the remote computer*'
            }

            # The failed attempts must leave the session usable.
            $session.State | Should-Be 'Opened'
            $session.Availability | Should-Be 'Available'
            Invoke-Command -Session $session -ScriptBlock { 'still connected' } | Should-Be 'still connected'
        }
        finally {
            $session | Remove-PSSession
        }
    }

    It "Fails to invoke a command in a disconnected session" {
        {
            Invoke-Command @sessionParams -ScriptBlock { 'never' } -InDisconnectedSession -ErrorAction Stop
        } | Should-Throw -ExceptionMessage '*Disconnected sessions are supported only when the remote computer*'

        # The failed session must not be left behind in the process.
        Get-PSSession | Where-Object ComputerName -eq $sessionParams.ComputerName | Should-BeNull
    }

    It "Closes a session while a command is running" {
        $session = New-PSSession @sessionParams
        $ps = [PowerShell]::Create()
        $ps.Runspace = $session.Runspace
        $null = $ps.AddScript("'started'; sleep 30")

        $output = [System.Management.Automation.PSDataCollection[psobject]]::new()
        $task = $ps.BeginInvoke([System.Management.Automation.PSDataCollection[psobject]]::new(), $output)
        while ($output.Count -eq 0 -and $ps.InvocationStateInfo.State -eq 'Running') {
            Start-Sleep -Milliseconds 50
        }

        $start = Get-Date
        $session | Remove-PSSession
        $elapsed = (Get-Date) - $start

        # EndInvoke completes without an error once the session is gone, the pipeline just reports Stopped.
        try {
            $ps.EndInvoke($task)
        }
        catch {
            # Also acceptable, the pipeline was interrupted either way.
        }

        $elapsed.TotalSeconds | Should-BeLessThan 10
        $session.State | Should-Be Closed
        $ps.InvocationStateInfo.State | Should-Be Stopped
    }

    It "Reports a broken session when the host process dies" {
        $session = New-PSSession @sessionParams

        try {
            $start = Get-Date
            {
                Invoke-Command -Session $session -ScriptBlock { Stop-Process -Id $pid -Force; Start-Sleep -Seconds 5; 'survived' } -ErrorAction Stop
            } | Should-Throw -ExceptionMessage '*The WSMan provider host process did not return a proper response*'
            $elapsed = (Get-Date) - $start

            $elapsed.TotalSeconds | Should-BeLessThan 10
            $session.State | Should-Be Broken

            {
                Invoke-Command -Session $session -ScriptBlock { 1 } -ErrorAction Stop
            } | Should-Throw -ExceptionMessage '*The session state is Broken*'
        }
        finally {
            $session | Remove-PSSession -ErrorAction SilentlyContinue
        }
    }

    It "Fails with an unknown application name" {
        $sessionParams.ApplicationName = 'pswsman-missing'

        $err = $null
        try {
            Invoke-Command @sessionParams -ScriptBlock { 1 } -ErrorAction Stop
        }
        catch {
            $err = $_
        }

        $err | Should-NotBeNull
        $err.Exception | Should-HaveType ([System.Management.Automation.Remoting.PSRemotingTransportException])
        [string]$err | Should-BeLikeString '*404*'
    }

    It "Fails with an unknown configuration name" {
        $sessionParams.ConfigurationName = 'pswsman-missing'

        $err = $null
        try {
            Invoke-Command @sessionParams -ScriptBlock { 1 } -ErrorAction Stop
        }
        catch {
            $err = $_
        }

        $err | Should-NotBeNull
        $err.Exception | Should-HaveType ([System.Management.Automation.Remoting.PSRemotingTransportException])
        [string]$err | Should-BeLikeString '*0x8033803B*'
    }

    It "Fails when the scheme does not match the listener" {
        # Talk TLS to the plain listener or plain HTTP to the TLS one, the exact message depends on the platform TLS
        # library so only the error type and that it fails promptly are checked.
        $sessionParams.UseSSL = -not $sessionParams.UseSSL
        $sessionParams.SessionOption = New-PSWSManSessionOption -OpenTimeout 10000 -SkipCACheck -SkipCNCheck

        $start = Get-Date
        $err = $null
        try {
            Invoke-Command @sessionParams -ScriptBlock { 1 } -ErrorAction Stop
        }
        catch {
            $err = $_
        }
        $elapsed = (Get-Date) - $start

        $err | Should-NotBeNull
        $err.Exception | Should-HaveType ([System.Management.Automation.Remoting.PSRemotingTransportException])
        $elapsed.TotalSeconds | Should-BeLessThan 10
    }
}
