#Requires -Module Yayaml

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $WSManEnvironmentPath
)

$wsmanInventoryPath = Join-Path $WSManEnvironmentPath 'inventory.yml'
$wsmanBuildPath = [System.IO.Path]::GetFullPath((Join-Path $WSManEnvironmentPath 'build'))
$wsmanInventory = Get-Content -LiteralPath $wsmanInventoryPath | ConvertFrom-Yaml -Schema Yaml11
$wsmanVars = $wsmanInventory.all.vars
$wsmanHost = "test.$($wsmanVars.domain_realm)"

$settings = [Ordered]@{
    credentials = [Ordered]@{
        default = [Ordered]@{
            username = "$($wsmanVars.domain_username)@$($wsmanVars.domain_realm.ToUpper())"
            password = $wsmanVars.domain_password
        }
        local = [Ordered]@{
            username = $wsmanVars.local_username
            password = $wsmanVars.local_password
        }
    }
    servers = [Ordered]@{
        default = [Ordered]@{
            hostname = $wsmanHost
        }
        local_auth = [Ordered]@{
            hostname = $wsmanHost
            credential = 'local'
        }
        untrusted = [Ordered]@{
            hostname = $wsmanHost
            port = 29904
        }
        https_sha1 = [Ordered]@{
            hostname = $wsmanHost
            port = 29916
        }
        https_sha256_pss = [Ordered]@{
            hostname = $wsmanHost
            port = 29920
        }
        https_sha384 = [Ordered]@{
            hostname = $wsmanHost
            port = 29924
        }
        https_sha512 = [Ordered]@{
            hostname = $wsmanHost
            port = 29928
        }
        https_sha512_pss = [Ordered]@{
            hostname = $wsmanHost
            port = 29932
        }
    }
    scenarios = [Ordered]@{
        domain_auth = "default"
        local_auth = "local_auth"
        https_domain_auth = "default"
        https_local_auth = "local_auth"
        https_trusted = "default"
        https_untrusted = "untrusted"
        https_sha1 = "https_sha1"
        https_sha256 = "default"
        https_sha256_pss = "https_sha256_pss"
        https_sha384 = "https_sha384"
        https_sha512 = "https_sha512"
        https_sha512_pss = "https_sha512_pss"
        jea = "default"
    }
    data = [Ordered]@{
        ca_file = [System.IO.Path]::Combine($wsmanBuildPath, 'ca.pem')
        client_certificate = [Ordered]@{
            cert = [System.IO.Path]::Combine($wsmanBuildPath, 'client_auth.pem')
            key = [System.IO.Path]::Combine($wsmanBuildPath, 'client_auth_password.key')
            password = 'password'
        }
        jea_configuration = [Ordered]@{
            name = 'JEA'
            username = "$($wsmanVars.gmsa_username)$"
        }
    }
}

$settingsPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'test.settings2.json'))
Set-Content -LiteralPath $settingsPath -Value (ConvertTo-Json $settings)
