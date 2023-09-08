$ErrorActionPreference = 'Stop'

$moduleName = (Get-Item ([IO.Path]::Combine($PSScriptRoot, '..', 'module', '*.psd1'))).BaseName
$manifestPath = [IO.Path]::Combine($PSScriptRoot, '..', 'output', $moduleName)

if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue)) {
    Import-Module $manifestPath -ErrorAction Stop
}

Enable-PSWSMan -Force

class JEAConfiguration {
    [string]$Name
    [string]$ExpectedUserName
}

class EXOConfiguration {
    [string]$Organization
    [string]$AppId
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
}

class PSWSManServer {
    [string]$HostName
    [PSCredential]$Credential
    [int]$Port
}

class PSWSManSettings {
    [System.Collections.Generic.Dictionary[[string], [PSWSManServer]]]$Servers
    [System.Collections.Generic.Dictionary[[string], [string]]]$Scenarios = [System.Collections.Generic.Dictionary[[string], [string]]]::new()
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $CACert
    [JEAConfiguration]$JEAConfiguration
    [EXOConfiguration]$EXOConfiguration
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCertificate

    [PSWSManServer] GetScenarioServer([string]$Scenario) {
        if ($this.Scenarios.ContainsKey($Scenario)) {
            $hostEntry = $this.Scenarios[$Scenario]
            return $this.Servers[$hostEntry]
        }

        return $null
    }
}

if (-not $global:PSWSManSettings) {
    $schemaPath = [IO.Path]::Combine($PSScriptRoot, 'settings.schema.json')
    $settingsPath = [IO.Path]::Combine($PSScriptRoot, '..', 'test.settings.json')
    if (Test-Path -LiteralPath $settingsPath) {
        $settingsJson = Get-Content -LiteralPath $settingsPath -Raw
        Test-Json -Json $settingsJson -SchemaFile $schemaPath -ErrorAction Stop

        $settings = ConvertFrom-Json -InputObject $settingsJson -AsHashtable

        $credentials = @{}
        $servers = [System.Collections.Generic.Dictionary[[string], [PSWSManServer]]]::new()
        $scenarios = [System.Collections.Generic.Dictionary[[string], [string]]]::new()
        $scenarios["default"] = "default"

        foreach ($cred in $settings.credentials.GetEnumerator()) {
            $psCred = [PSCredential]::new($cred.Value.username,
                (ConvertTo-SecureString -AsPlainText -Force -String $cred.Value.password))
            $credentials[$cred.Key] = $psCred
        }

        foreach ($server in $settings.servers.GetEnumerator()) {
            $credentialName = $server.Value.credential
            if (-not $credentialName) {
                $credentialName = 'default'
            }

            if (-not $credentials.ContainsKey($credentialName)) {
                throw "Failed to find the test settings credential '$credentialName' in host '$($server.Key)'"
            }

            $servers[$server.Key] = [PSWSManServer]@{
                HostName = $server.Value.hostname
                Credential = $credentials[$credentialName]
                Port = $server.Value.port
            }
        }

        if (-not $servers.ContainsKey("default")) {
            throw "No server under 'default' was set in the test configuration"
        }

        foreach ($scenario in $settings.scenarios.GetEnumerator()) {
            $scenarioName = $scenario.Key
            $hostName = $scenario.Value

            if (-not $servers.ContainsKey($hostName)) {
                throw "Failed to find the test settings server '$hostName' in scenario '$scenarioName'"
            }
            $scenarios[$scenarioName] = $hostName
        }

        $caCert = $null
        $jeaConfiguration = $null
        $exoConfiguration = $null
        $clientCert = $null
        if ($settings.data) {
            if (Test-Path -LiteralPath $settings.data.ca_file) {
                $caCert = Get-PfxCertificate -FilePath $settings.data.ca_file
            }

            if ($settings.data.client_certificate) {
                if (-not (Test-Path -LiteralPath $settings.data.client_certificate.cert)) {
                    throw "client_certificate.cert cannot be found"
                }
                if (-not (Test-Path -LiteralPath $settings.data.client_certificate.key)) {
                    throw "client_certificate.key cannot be found"
                }

                $certPath = Resolve-Path -Path $settings.data.client_certificate.cert
                $publicCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certPath)

                $keyContent = Get-Content -Path $settings.data.client_certificate.key -Raw
                $key = [System.Security.Cryptography.RSA]::Create()
                if ($settings.data.client_certificate.password) {
                    $key.ImportFromEncryptedPem($keyContent, $settings.data.client_certificate.password)
                }
                else {
                    $key.ImportFromPem($keyContent)
                }

                $clientCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey(
                    $publicCert, $key)
            }

            if ($settings.data.jea_configuration) {
                if (-not $scenarios.ContainsKey('jea')) {
                    throw "jea_configuration set but no jea scenario set."
                }

                $jeaConfiguration = [JEAConfiguration]@{
                    Name = $settings.data.jea_configuration.name
                    ExpectedUserName = $settings.data.jea_configuration.username
                }
            }

            if ($settings.data.exchange_online) {
                if (-not (Get-Module -Name ExchangeOnlineManagement)) {
                    $exoDepPath = [System.IO.Path]::GetFullPath(
                        [System.IO.Path]::Combine(
                            $PSScriptRoot,
                            '..',
                            'tools',
                            'Modules',
                            'ExchangeOnlineManagement'))
                    if (Test-Path -LiteralPath $exoDepPath) {
                        # Favour the local dep if present
                        Import-Module -Name $exoDepPath
                    }
                    else {
                        # Otherwise rely on it being installed somewhere. Fail if it isn't
                        Import-Module -Name ExchangeOnlineManagement -ErrorAction Stop
                    }
                }

                $exoCertificate = $null
                if ($certPath = $settings.data.exchange_online.certificate_path) {
                    $pfxParams = @{
                        FilePath = $certPath
                        ErrorAction = 'Stop'
                    }
                    if ($certPass = $settings.data.exchange_online.certificate_password) {
                        $pfxParams.Password = ConvertTo-SecureString -AsPlainText -Force -String $certPass
                    }
                    $exoCertificate = Get-PfxCertificate @pfxParams
                }

                $exoConfiguration = [EXOConfiguration]@{
                    Organization = $settings.data.exchange_online.organization
                    AppId = $settings.data.exchange_online.app_id
                    Certificate = $exoCertificate
                }
            }
        }

        $global:PSWSManSettings = [PSWSManSettings]@{
            Servers = $servers
            Scenarios = $scenarios
            CACert = $caCert
            JEAConfiguration = $jeaConfiguration
            EXOConfiguration = $exoConfiguration
            ClientCertificate = $clientCert
        }
    }
    else {
        $global:PSWSManSettings = [PSWSManSettings]::new()
    }
}

Function global:Get-PSSessionSplat {
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSWSManServer]$Server,

        [switch]
        $ForBasicAuth
    )

    $params = @{
        ComputerName = $Server.HostName
        Credential = $Server.Credential
    }
    if ($Server.Port) {
        $params.Port = $Server.Port
    }
    if ($ForBasicAuth) {
        # If using Basic auth the domain/server portion needs to be stripped out
        $newUserName = $params.Credential.UserName
        if ($newUserName -like '*\*') {
            $newUserName = ($newUserName -split '\\', 2)[1]
        }
        $params.Credential = [PSCredential]::new($newUserName, $params.Credential.Password)
        $params.Authentication = 'Basic'
    }

    $params
}

Function global:Invoke-Kinit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCredential]
        $Credential,

        [Switch]
        $Forwardable
    )

    $kinitArgs = @(
        if ($Forwardable) { '-f' }

        # Heimdal (used by macOS) requires this argument to successfully send the password to kinit
        if ($IsMacOs) { '--password-file=STDIN' }

        $Credential.UserName
    )

    $null = $Credential.GetNetworkCredential().Password | kinit $kinitArgs
}
