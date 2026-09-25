using namespace System.IO
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

$ErrorActionPreference = 'Stop'

$moduleName = (Get-Item ([Path]::Combine($PSScriptRoot, '..', 'module', '*.psd1'))).BaseName
$manifestPath = [Path]::Combine($PSScriptRoot, '..', 'output', $moduleName)

if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue)) {
    Import-Module $manifestPath -ErrorAction Stop
}

Enable-PSWSMan -Force

# One entry of the servers list in test.settings.json, see tests/settings.schema.json.
class PSWSManTestServer {
    [string]$Name
    [Uri]$Uri
    # Null for an entry that only authenticates with a client certificate.
    [PSCredential]$Credential
    [string[]]$Auth
    [bool]$UntrustedCertificate
    [X509Certificate2]$ClientCertificate
    [string]$JEAName
    [string]$JEAUserName
    [bool]$TrustedForDelegation

    [string] ToString() {
        return $this.Name
    }
}

Function Import-PSWSManTestClientCertificate {
    <#
    .SYNOPSIS
    Loads the client_certificate of a settings entry with its private key.

    .DESCRIPTION
    A PFX key is loaded ephemerally so nothing is left in the OS key store,
    except on macOS which rejects that flag and uses a temporary keychain by
    default instead.

    .PARAMETER Url
    The url of the settings entry, used in error messages.

    .PARAMETER BaseDirectory
    The directory relative paths in Cert and Key are resolved from.

    .PARAMETER Cert
    A .pfx or .p12 file holding the certificate and its key, or a PEM
    certificate whose key is in Key.

    .PARAMETER Key
    The PEM private key for a PEM Cert. Ignored for a PFX.

    .PARAMETER Password
    The PFX password, or the password of the PEM key when it is encrypted.
    #>
    [OutputType([X509Certificate2])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Url,

        [Parameter(Mandatory)]
        [string]
        $BaseDirectory,

        [Parameter(Mandatory)]
        [string]
        $Cert,

        [AllowNull()]
        [string]
        $Key,

        [AllowNull()]
        [string]
        $Password
    )

    $certPath = [Path]::GetFullPath($Cert, $BaseDirectory)
    if (-not (Test-Path -LiteralPath $certPath)) {
        throw "client_certificate.cert '$certPath' for server '$Url' cannot be found"
    }

    # The X509Certificate2 constructors are obsolete since .NET 9 but the loader is not on .NET 8.
    $useLoader = [bool]('X509CertificateLoader' -as [type])

    if ([Path]::GetExtension($certPath) -in '.pfx', '.p12') {
        # macOS does not support the EphemeralKeySet flag, so use the default key set instead.
        $flags = if ($IsMacOS) { [X509KeyStorageFlags]::DefaultKeySet } else { [X509KeyStorageFlags]::EphemeralKeySet }
        if ($useLoader) {
            return [X509CertificateLoader]::LoadPkcs12FromFile($certPath, $Password, $flags)
        }
        else {
            return [X509Certificate2]::new($certPath, $Password, $flags)
        }
    }

    if (-not $Key) {
        throw "client_certificate.key for server '$Url' is required when cert is not a .pfx or .p12 file"
    }
    $keyPath = [Path]::GetFullPath($Key, $BaseDirectory)
    if (-not (Test-Path -LiteralPath $keyPath)) {
        throw "client_certificate.key '$keyPath' for server '$Url' cannot be found"
    }

    $publicCert = if ($useLoader) {
        [X509CertificateLoader]::LoadCertificateFromFile($certPath)
    }
    else {
        [X509Certificate2]::new($certPath)
    }
    $rsa = [RSA]::Create()
    $keyContent = Get-Content -LiteralPath $keyPath -Raw
    if ($Password) {
        $rsa.ImportFromEncryptedPem($keyContent, $Password)
    }
    else {
        $rsa.ImportFromPem($keyContent)
    }

    [RSACertificateExtensions]::CopyWithPrivateKey($publicCert, $rsa)
}

Function Import-PSWSManTestSettings {
    [OutputType([PSWSManTestServer])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [string]
        $SchemaPath
    )

    $settingsJson = Get-Content -LiteralPath $Path -Raw
    Test-Json -Json $settingsJson -SchemaFile $SchemaPath -ErrorAction Stop | Out-Null
    $settings = ConvertFrom-Json -InputObject $settingsJson -AsHashtable
    $settingsDir = [Path]::GetDirectoryName([Path]::GetFullPath($Path))

    foreach ($entry in $settings.servers) {
        $uri = [Uri]$entry.url
        $auth = @($entry.auth | ForEach-Object { $_.ToLowerInvariant() })

        $credential = $null
        if ($entry.username) {
            $credential = [PSCredential]::new(
                $entry.username,
                (ConvertTo-SecureString -AsPlainText -Force -String $entry.password))
        }
        elseif (@($auth | Where-Object { $_ -ne 'certificate' })) {
            throw "Server '$($entry.url)' needs a username and password for the auth methods $($auth -join ', ')"
        }

        $clientCert = $null
        if ($entry.client_certificate) {
            $clientCert = Import-PSWSManTestClientCertificate -Url $entry.url -BaseDirectory $settingsDir `
                -Cert $entry.client_certificate.cert -Key $entry.client_certificate.key `
                -Password $entry.client_certificate.password
        }
        elseif ($auth -contains 'certificate') {
            throw "Server '$($entry.url)' lists certificate auth but has no client_certificate"
        }

        $name = $entry.name
        if (-not $name) {
            $user = if ($entry.username) { $entry.username } else { 'certificate' }
            $name = "$user $($uri.Scheme)://$($uri.Host):$($uri.Port)"
        }

        [PSWSManTestServer]@{
            Name = $name
            Uri = $uri
            Credential = $credential
            Auth = $auth
            UntrustedCertificate = [bool]$entry.untrusted_certificate
            ClientCertificate = $clientCert
            JEAName = $entry.jea.name
            JEAUserName = $entry.jea.username
            TrustedForDelegation = [bool]$entry.trusted_for_delegation
        }
    }
}

if (-not $global:PSWSManTestServers) {
    $settingsPath = [Path]::Combine($PSScriptRoot, '..', 'test.settings.json')
    $global:PSWSManTestServers = if (Test-Path -LiteralPath $settingsPath) {
        @(Import-PSWSManTestSettings -Path $settingsPath -SchemaPath ([Path]::Combine($PSScriptRoot, 'settings.schema.json')))
    }
    else {
        @()
    }
}

Function global:Get-PSWSManTestServer {
    <#
    .SYNOPSIS
    Selects the configured test servers a test can run against.

    .DESCRIPTION
    Returns the matching PSWSManTestServer objects for use with the Pester
    -ForEach parameter, where each is available as $_ and <_> in the test name
    expands to its Name. When nothing matches a single placeholder without a
    Uri is returned so the test still appears in the results, and
    Get-PSSessionSplat marks it as skipped.

    Without -Auth or -AnyAuth only servers with a username and password are
    returned so a test that needs any server always gets a credential to use.

    .PARAMETER Scheme
    Only servers reachable over this scheme.

    .PARAMETER Auth
    Only servers whose entry lists every one of these auth methods.

    .PARAMETER AnyAuth
    Only servers whose entry lists at least one of these auth methods.

    .PARAMETER JEA
    Only servers with a JEA configuration.

    .PARAMETER TrustedForDelegation
    Only servers trusted for unconstrained delegation.

    .PARAMETER First
    Return at most one server, for tests that only need any server.
    #>
    [OutputType([PSWSManTestServer])]
    [CmdletBinding()]
    param (
        [ValidateSet('Http', 'Https')]
        [string]
        $Scheme,

        [ValidateSet('Basic', 'Kerberos', 'NTLM', 'CredSSP', 'Certificate')]
        [string[]]
        $Auth,

        [ValidateSet('Basic', 'Kerberos', 'NTLM', 'CredSSP', 'Certificate')]
        [string[]]
        $AnyAuth,

        [switch]
        $JEA,

        [switch]
        $TrustedForDelegation,

        [switch]
        $First
    )

    $matched = foreach ($server in $global:PSWSManTestServers) {
        if ($Scheme -and $server.Uri.Scheme -ne $Scheme) {
            continue
        }
        if ($JEA -and -not $server.JEAName) {
            continue
        }
        if ($TrustedForDelegation -and -not $server.TrustedForDelegation) {
            continue
        }
        if (-not $Auth -and -not $AnyAuth -and -not $server.Credential) {
            continue
        }
        if ($AnyAuth -and -not @($server.Auth | Where-Object { $_ -in $AnyAuth })) {
            continue
        }

        $missingAuth = $false
        foreach ($a in $Auth) {
            if ($server.Auth -notcontains $a) {
                $missingAuth = $true
                break
            }
        }
        if ($missingAuth) {
            continue
        }

        $server
        if ($First) {
            break
        }
    }

    if (-not $matched) {
        $matched = [PSWSManTestServer]@{ Name = 'no matching server' }
    }

    $matched
}

Function global:Get-PSSessionSplat {
    <#
    .SYNOPSIS
    Builds the New-PSSession/Invoke-Command parameters for a test server.

    .DESCRIPTION
    Splits the server URL into ComputerName, Port, UseSSL and ApplicationName so
    the tests exercise the common cmdlet parameters and adds the credential when
    the entry has one.

    The SessionOption hashtable is splatted to New-PSWSManSessionOption. For a
    server with an untrusted certificate SkipCACheck and SkipCNCheck are added
    unless the test supplies its own TlsOption, so every test can run against it.
    Remove the SessionOption key from the result to connect with certificate
    validation enabled.

    A Server without a Uri is the placeholder Get-PSWSManTestServer returns
    when nothing matched, calling this with it marks the current test as
    skipped.

    .PARAMETER Server
    A server returned by Get-PSWSManTestServer, usually piped in as $_.

    .PARAMETER SessionOption
    Parameters for New-PSWSManSessionOption. When set, or when the server has
    an untrusted certificate, the result contains a SessionOption entry.
    #>
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSWSManTestServer]
        $Server,

        [hashtable]
        $SessionOption
    )

    process {
        if (-not $Server.Uri) {
            Set-ItResult -Skipped -Because 'no server in test.settings.json matches what this test needs'
        }

        $params = @{
            ComputerName = $Server.Uri.Host
            Port = $Server.Uri.Port
        }
        if ($Server.Credential) {
            $params.Credential = $Server.Credential
        }
        if ($Server.Uri.Scheme -eq 'https') {
            $params.UseSSL = $true
        }

        $appName = $Server.Uri.AbsolutePath.Trim('/')
        if ($appName -and $appName -ne 'wsman') {
            $params.ApplicationName = $appName
        }

        $optionParams = @{}
        if ($SessionOption) {
            $optionParams += $SessionOption
        }
        if ($Server.UntrustedCertificate -and -not $optionParams.ContainsKey('TlsOption')) {
            $optionParams.SkipCACheck = $true
            $optionParams.SkipCNCheck = $true
        }
        if ($optionParams.Count) {
            $params.SessionOption = New-PSWSManSessionOption @optionParams
        }

        $params
    }
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
