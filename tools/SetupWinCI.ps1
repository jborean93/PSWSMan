using namespace System.IO
using namespace System.Management.Automation
using namespace System.Runtime.InteropServices
using namespace System.Text
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

Write-Information -MessageData "Configuring WinRM for PSWSMan tests"

function New-WinRMFirewallRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Int32]
        $Port,

        [Parameter(Mandatory)]
        [String]
        $Protocol
    )
    $fw = New-Object -ComObject HNetCfg.FWPolicy2
    $https_rule = "Windows Remote Management ($Protocol)"

    $rules = $fw.Rules | Where-Object { $_.Name -eq $https_rule }
    if (-not $rules) {
        Write-Information -MessageData "Creating a new WinRM $Protocol firewall rule"
        $rule = New-Object -ComObject HNetCfg.FwRule
        $rule.Name = $https_rule
        $rule.Description = "Inbound rule for Windows Remote Management via WS-Management. [TCP $Port]"
        $rule.Profiles = 0x7FFFFFFF
        $rules = @($rule)
    }

    foreach ($rule in $rules) {
        $rule_details = @{
            LocalPorts = $Port
            RemotePorts = "*"
            LocalAddresses = "*"
            Enabled = $true
            Direction = 1
            Action = 1
            Grouping = "Windows Remote Management"
            ApplicationName = "System"
        }
        $rule.Protocol = 6

        $changed = $false
        foreach ($detail in $rule_details.GetEnumerator()) {
            $original_value = $rule.$($detail.Name)
            $new_value = $detail.Value
            Write-Information -MessageData "Checking FW Rule property $($detail.Name) - Actual: '$original_value', Expected: '$new_value'"
            if ($original_value -ne $new_value) {
                Write-Information -MessageData "FW Rule property $($detail.Name) does not match, changing rule"
                $rule.$($detail.Name) = $new_value
                $changed = $true
            }
        }

        if ($changed) {
            Write-Information -MessageData "WinRM $Protocol firewall rule needs to be (re)created as config does not match expectation"
            try {
                $fw.Rules.Add($rule)
            }
            catch [COMException] {
                # E_UNEXPECTED 0x80000FFFF means the rule already exists
                if ($_.Exception.ErrorCode -eq 0x8000FFFF) {
                    Write-Information -MessageData "WinRM $Protocol firewall rule already exists, deleting before recreating"
                    $fw.Rules.Remove($rule.Name)
                    $fw.Rules.Add($rule)
                }
                else {
                    Write-Information -MessageData "Failed to add WinRM $Protocol firewall rule: $($_.Exception.Message)"
                    throw $_
                }
            }
        }
    }
}

function Reset-WinRMConfig {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [X509Certificate2]
        $CACertificate,

        [Parameter(Mandatory)]
        [String]
        $CtlStore
    )

    Write-Verbose "Removing all existing WinRM listeners"
    Get-ChildItem -LiteralPath WSMan:\localhost\Listener | Remove-Item -Force -Recurse

    Write-Information -MessageData "Creating HTTP listener"
    $selectorSet = @{
        Transport = "HTTP"
        Address = "*"
    }
    $valueSet = @{
        Enabled = $true
    }
    New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet $selectorSet -ValueSet $valueSet > $null

    $certParams = @{
        CertStoreLocation = 'Cert:\LocalMachine\My'
        DnsName = $env:COMPUTERNAME, 'localhost'
        NotAfter = (Get-Date).AddYears(1)
        Provider = 'Microsoft Software Key Storage Provider'
        Signer = $CACertificate
        Subject = "CN=$env:COMPUTERNAME"
    }
    $certificate = New-SelfSignedCertificate @certParams
    $selectorSet = @{
        Transport = "HTTPS"
        Address = "*"
    }
    $valueSet = @{
        CertificateThumbprint = $certificate.Thumbprint
        Enabled = $true
    }

    Write-Information -MessageData "Creating HTTPS listener"
    New-WSManInstance -ResourceURI "winrm/config/Listener" -SelectorSet $selectorSet -ValueSet $valueSet > $null

    Write-Verbose "Enabling PowerShell Remoting"
    Enable-PSRemoting -Force > $null

    Write-Information -MessageData "Enabling Basic authentication"
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true

    Write-Information -MessageData "Enabling Certificate authentication"
    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true

    Write-Information -MessageData "Enabling CredSSP authentication"
    Enable-WSManCredSSP -Role Server -Force > $null

    Write-Information -MessageData "Setting AllowUnencrypted to True"
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true

    Write-Information -MessageData "Configuring WinRM HTTPS firewall rule"
    New-WinRMFirewallRule -Port 5986 -Protocol HTTPS

    Write-Information -MessageData "Set CbtHardeningLevel to strict"
    Set-Item -Path WSMan:\localhost\Service\Auth\CbtHardeningLevel -Value Strict

    Write-Information -MessageData "Allow local admins over network auth"
    $regInfo = @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "LocalAccountTokenFilterPolicy"
        Value = 1
        PropertyType = "DWord"
        Force = $true
    }
    New-ItemProperty @regInfo > $null

    Write-Information -MessageData "Configuring WinRM HTTPS binding to use CTL trust store '$CtlStore'"
    $existingBinding = netsh.exe http show sslcert ipport=0.0.0.0:5986 json=enable
    if ($LASTEXITCODE) {
        throw "Failed to get existing WinRM HTTPS binding:`n$existingBinding"
    }
    $binding = $existingBinding | ConvertFrom-Json | Select-Object -ExpandProperty SslCertificateBindings

    $out = netsh.exe @(
        "http"
        "update"
        "sslcert"
        "ipport=0.0.0.0:5986"
        "appid=$($binding.GuidString)"
        "certhash=$($certificate.Thumbprint)"
        "sslctlstorename=$CtlStore"
    ) 2>&1
    if ($LASTEXITCODE) {
        throw "Failed to set sslctlstorename for WinRM binding:`n$out"
    }

    Write-Information -MessageData "WinRM and PS Remoting have been set up successfully"
}

Function New-CertificateAuthBinding {
    [OutputType([string])]
    [CmdletBinding()]
    Param (
        [String]
        $Name,

        [String]
        $CertPath,

        [X509Certificate2]
        $CACertificate,

        [PSCredential]
        $Credential
    )

    Write-Information -MessageData "Generating self signed certificate for authentication of user $Name"
    $certInfo = @{
        CertStoreLocation = "Cert:\CurrentUser\My"
        Provider = 'Microsoft Software Key Storage Provider'
        Signer = $CACertificate
        Subject = "CN=$Name"
        TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2", "2.5.29.17={text}upn=$Name@localhost")
        Type = "Custom"
    }
    $cert = New-SelfSignedCertificate @certInfo

    # The tests load this PFX directly, protected with the user's password so the
    # password path of the settings loader is exercised as well.
    Write-Information -MessageData "Exporting certificate and private key to a PFX file"
    $certPassword = $Credential.GetNetworkCredential().Password
    [File]::WriteAllBytes("$CertPath\cert.pfx", $cert.Export("Pfx", $certPassword))

    # WinRM seems to be very picky about the type of cert in the trusted people store, make sure this is set
    # to the cert and not cert + key.
    $certNoKey = [X509Certificate2]::new($cert.RawData)

    Write-Information -MessageData "Importing cert into LocalMachine\TrustedPeople"
    $store = Get-Item -Path Cert:\LocalMachine\TrustedPeople
    $store.Open([OpenFlags]::ReadWrite)
    $store.Add($certNoKey)
    $store.Dispose()

    $credBinding = @{
        Credential = $Credential
        Force = $true
        Issuer = $CACertificate.Thumbprint
        Path = "WSMan:\localhost\ClientCertificate"
        Subject = "$Name@localhost"
    }
    New-Item @credBinding > $null

    $cert.Thumbprint
}

Function New-JEAConfiguration {
    [CmdletBinding()]
    Param (
        [string]
        $Name
    )

    $modulePath = Join-Path -Path $env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\$Name"
    Write-Information -MessageData "Setting up JEA PowerShell module path at '$modulePath'"
    if (-not (Test-Path -Path $modulePath)) {
        New-Item -Path $modulePath -ItemType Directory | Out-Null
    }

    $functionsPath = Join-Path -Path $modulePath -ChildPath "$($Name)Functions.psm1"
    if (-not (Test-Path -Path $functionsPath)) {
        New-Item -Path $functionsPath -ItemType File | Out-Null
    }

    $manifestPath = Join-Path -Path $modulePath -ChildPath "$($Name).psd1"
    if (-not (Test-Path -Path $manifestPath)) {
        New-ModuleManifest -Path $manifestPath -RootModule "$($Name)Functions.psm1"
    }

    $rolePath = Join-Path -Path $modulePath -ChildPath "RoleCapabilities"
    if (-not (Test-Path -Path $rolePath)) {
        New-Item -Path $rolePath -ItemType Directory | Out-Null
    }

    $jeaGuid = New-Guid
    $jeaRole = @"
@{
    GUID = '$jeaGuid'
    Author = 'Jordan Borean'
    Description = 'A test JEA role used in the functional tests for PSWSMan'
    CompanyName = 'N/A'
    Copyright = '(c) 2026 Jordan Borean'
    VisibleFunctions = @{
        Name = 'Get-PSWSManJeaUserName'
        ScriptBlock = { [Environment]::UserName }
    }
}
"@
    Write-Information -MessageData "Creating JEA role configuration"
    Set-Content -LiteralPath "$rolePath\JEARole.psrc" -Value $jeaRole

    if (Get-PSSessionConfiguration | Where-Object { $_.Name -eq $name }) {
        Write-Information -MessageData "JEA role $Name already registered, removing to ensure we start fresh"
        Unregister-PSSessionConfiguration -Name $Name -NoServiceRestart
    }

    $jeaSettings = @"
@{
    SchemaVersion = '2.0.0.0'
    GUID = '$jeaGuid'
    Author = 'Jordan Borean'
    SessionType = 'RestrictedRemoteServer'
    RunAsVirtualAccount = `$true
    RoleDefinitions = @{
        'BUILTIN\Administrators' = @{ RoleCapabilities = 'JEARole' }
    }
}
"@
    Set-Content -LiteralPath "$modulePath\JEARoleSettings.pssc" -Value $jeaSettings
    Register-PSSessionConfiguration -Path "$modulePath\JEARoleSettings.pssc" -Name $Name -Force > $null
}

$UserName = 'PSWSMan-user'
$passwordChars = [char[]]((48..57) + (65..90) + (97..122)) + [char[]]'!@#$%&*'
$Password = -join ($passwordChars | Get-Random -Count 16)
$RepoPath = [Path]::GetFullPath("$PSScriptRoot\..")
$CertPath = [Path]::Combine($RepoPath, "output", "certs")
if (-not (Test-Path -Path $CertPath)) {
    New-Item -Path $CertPath -ItemType Directory | Out-Null
}

Write-Information -MessageData "Removing extra modules to speed up PowerShell startup due to slow WinRM issue"
'AWSPowerShell', 'DockerMsftProvider', 'ImageHelpers', 'MarkdownPS', 'Microsoft.*', 'PSWindowsUpdate', 'SqlServer', 'VSSetup' | ForEach-Object {
    $path = "C:\Program Files\WindowsPowerShell\Modules\$_"
    if (Test-Path -Path $path) {
        Remove-Item -Path $path -Recurse -Force
    }
}
if (Test-Path "C:\Modules") {
    Remove-Item -Path "C:\Modules\*" -Recurse -Force
}

$caParams = @{
    Extension = @(
        [X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        [X509KeyUsageExtension]::new('KeyCertSign', $true)
    )
    CertStoreLocation = 'Cert:\CurrentUser\My'
    NotAfter = (Get-Date).AddYears(1)
    Provider = 'Microsoft Software Key Storage Provider'
    Subject = 'CN=PSWSMan CA'
    Type = 'Custom'
}
Write-Information -MessageData "Creating CA certificate"
$ca = New-SelfSignedCertificate @caParams

$root = Get-Item -LiteralPath Cert:\LocalMachine\Root
$root.Open([OpenFlags]::ReadWrite)
$root.Add($ca)
$root.Dispose()

# Setup a specific store for the WinRM CTL as GHA's root store is too large
# and causes issues with WinRM cert selection during authentication
$ctlStoreName = 'WinRMTrustedIssuers'
$ctlStore = [X509Store]::new(
    $ctlStoreName,
    [StoreLocation]::LocalMachine)
$ctlStore.Open([OpenFlags]::ReadWrite)
$ctlStore.Add([X509Certificate2]::new($ca.RawData))  # Strip key affinity
$ctlStore.Dispose()

$secPassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$userCredential = [PSCredential]::new("$env:COMPUTERNAME\$UserName", $secPassword)

$localUser = New-LocalUser -Name $UserName -Password $secPassword -AccountNeverExpires -PasswordNeverExpires
Add-LocalGroupMember -Group Administrators -Member $localUser

Enable-PSRemoting -Force
Start-Service -Name WinRM
Reset-WinRMConfig -CACertificate $ca -CtlStore $ctlStoreName
Write-Information -MessageData "Setting up JEA configuration"
New-JEAConfiguration -Name JEARole
Restart-Service -Name winrm

# It is important we setup the certificate auth binding after the JEA session is
# registered. JEA will change the WinRM service account from NetworkService to
# SYSTEM and cert auth bindings are encrypted based on the service account.
$clientCertParams = @{
    Name = $UserName
    CertPath = $CertPath
    CACertificate = $ca
    Credential = $userCredential
}
$clientCertificate = New-CertificateAuthBinding @clientCertParams

# Only remove the CA/Key from CurrentUser\My after all other certs have been generated.
Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($ca.Thumbprint)" -Force

# Do one last restart, I've found that sometimes the service gets into a funky
# state after all the changes above.
Restart-Service -Name winrm

Write-Information -MessageData "Testing WinRM connection over HTTP"
$invokeParams = @{
    ComputerName = 'localhost'
    ScriptBlock = { [Environment]::UserName }
}
$user = Invoke-Command @invokeParams -Credential $userCredential
if ($user -ne $UserName) {
    throw "WinRM authentication did not return expected user. Expected: $UserName, Actual: $user"
}

# Seems like the HTTPS service can get into a bit of a funk based on our setup
# We retry a few times to get a successful connection rather than fail immediately.
Write-Information -MessageData "Testing WinRM connection over HTTPS"
$attempt = 0
while ($true) {
    try {
        $user = Invoke-Command @invokeParams -UseSSL -Credential $userCredential
        break
    }
    catch {
        if ($attempt -gt 4) {
            throw
        }

        Write-Information -MessageData "WinRM over HTTPS connection failed - $_`nRetrying in 5 seconds..."
        $attempt++

        Start-Sleep -Seconds 5
    }
}
if ($user -ne $UserName) {
    throw "WinRM authentication over HTTPS did not return expected user. Expected: $UserName, Actual: $user"
}

Write-Information -MessageData "Testing WinRM connection over HTTPS with certificate authentication"
$user = Invoke-Command @invokeParams -UseSSL -CertificateThumbprint $clientCertificate
if ($user -ne $UserName) {
    throw "Certificate authentication did not return expected user. Expected: $UserName, Actual: $user"
}

Write-Information -MessageData "Testing WinRM connection with JEA"
$jeaUserName = Invoke-Command -ComputerName localhost -ScriptBlock {
    Get-PSWSManJeaUserName
} -ConfigurationName JEARole -Credential $userCredential
if ($jeaUserName -notlike 'WinRM VA_*') {
    throw "JEA session did not run as a virtual account. Actual: $jeaUserName"
}

# Write the settings the Pester connection tests read, see tests/settings.schema.json.
# The runner only has a local account so Kerberos is never available. The plain
# username form is used as Basic auth requires it and the other methods accept it.
# The HTTPS entry goes first as the tests that need any server take the first
# entry and it supports every auth method the runner offers.
$settingsPath = [Path]::Combine($RepoPath, "test.settings.json")
Write-Information -MessageData "Writing test settings to '$settingsPath'"
$settings = [Ordered]@{
    servers = @(
        [Ordered]@{
            name = "http local"
            url = "http://localhost:5985/wsman"
            username = $UserName
            password = $Password
            auth = @("basic", "ntlm", "credssp")
            jea = "JEARole"
        }
        [Ordered]@{
            name = "https local"
            url = "https://localhost:5986/wsman"
            username = $UserName
            password = $Password
            auth = @("basic", "ntlm", "credssp", "certificate")
            client_certificate = [Ordered]@{
                cert = "output/certs/cert.pfx"
                password = $Password
            }
            jea = "JEARole"
        }
    )
}
$settingsJson = ConvertTo-Json -InputObject $settings -Depth 5
[File]::WriteAllText($settingsPath, $settingsJson, [UTF8Encoding]::new($false))
