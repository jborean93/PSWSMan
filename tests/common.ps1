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
                HostName   = $server.Value.hostname
                Credential = $credentials[$credentialName]
                Port       = $server.Value.port
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
        $clientCert = $null
        if ($settings.data) {
            if (Test-Path -LiteralPath $settings.data.ca_file) {
                $caCert = Get-PfxCertificate -FilePath $settings.data.ca_file
            }

            if ($settings.data.client_certificate) {
                if (-not (Test-Path -LiteralPath $settings.data.client_certificate.path)) {
                    throw "client_certificate.path cannot be found"
                }

                $pfxParams = @{
                    FilePath            = $settings.data.client_certificate.path
                    NoPromptForPassword = $true
                }
                if ($settings.data.client_certificate.password) {
                    $pfxParams.Password = (ConvertTo-SecureString -AsPlainText -Force -String $settings.data.client_certificate.password)
                }
                $clientCert = Get-PfxCertificate @pfxParams
            }

            if ($settings.data.jea_configuration) {
                if (-not $scenarios.ContainsKey('jea')) {
                    throw "jea_configuration set but no jea scenario set."
                }

                $jeaConfiguration = [JEAConfiguration]@{
                    Name             = $settings.data.jea_configuration.name
                    ExpectedUserName = $settings.data.jea_configuration.username
                }
            }
        }

        $global:PSWSManSettings = [PSWSManSettings]@{
            Servers           = $servers
            Scenarios         = $scenarios
            CACert            = $caCert
            JEAConfiguration  = $jeaConfiguration
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
        [PSWSManServer]$Server
    )

    $params = @{
        ComputerName = $Server.HostName
        Credential   = $Server.Credential
    }
    if ($Server.Port) {
        $params.Port = $Server.Port
    }

    $params
}
