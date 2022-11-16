$ErrorActionPreference = 'Stop'

$moduleName = (Get-Item ([IO.Path]::Combine($PSScriptRoot, '..', 'module', '*.psd1'))).BaseName
$manifestPath = [IO.Path]::Combine($PSScriptRoot, '..', 'output', $moduleName)

if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue)) {
    Import-Module $manifestPath -ErrorAction Stop
}

Enable-PSWSMan -Force

class PSWSManServer {
    [string]$HostName
    [PSCredential]$Credential
    [int]$Port
}

class PSWSManSettings {
    [System.Collections.Generic.Dictionary[[string], [PSWSManServer]]]$Servers
    [System.Collections.Generic.Dictionary[[string], [string]]]$Scenarios

    [PSWSManServer] GetScenarioServer([string]$Scenario) {
        if ($this.Scenarios.ContainsKey($Scenario)) {
            $hostEntry = $this.Scenarios[$Scenario]
            return $this.Servers[$hostEntry]
        }

        return $null
    }
}

if (-not $global:PSOpenADSettings) {
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

        $global:PSWSManSettings = [PSWSManSettings]@{
            Servers   = $servers
            Scenarios = $scenarios
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
