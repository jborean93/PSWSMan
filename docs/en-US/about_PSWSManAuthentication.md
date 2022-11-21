# PowerShell WSMan Authentication
## about_PSWSManAuthentication

# SHORT DESCRIPTION
There are many different ways to authenticate with a Windows host over WSMan each with their own advantages and disadvantages.
It is complicated further that some authentication methods might be available on some hosts but not available on others.
This help page will go through the various authentication options available to `PSWSMan` and how they can be used.

# LONG DESCRIPTION
There are 6 different types of authentication methods supported by WSMan:

+ `Basic` - Simple HTTP basic authentication

+ `Certificate` - HTTPS client certificate authentication

+ `NTLM` - NTLM authentication

+ `Kerberos` - Kerberos authentication for domain accounts

+ `Negotiate` - Kerberos but with a fallback of NTLM authentication

+ `CredSSP` - Negotiate authentication with the ability to delegate credentials

The `Negotiate` authentication package is an authentication method that will attempt to use `Kerberos` before falling back to `NTLM` if that is unavailable.
Here is a simple matrix of each options and some of the features they support:

|Method|Local Account|Domain Account|HTTP Encryption|Delegation|
|-|-|-|-|-|
|Basic|Y|N|N|N|
|Certificate|Y|N|N/A¹|N|
|NTLM|Y|Y|Y²|N|
|Kerberos|N|Y|Y|Y|
|Negotiate|Y|Y|Y|Y³|
|CredSSP|Y|Y|Y|Y|

¹ Certificate auth only available over HTTPS
² NTLM HTTP Encryption is based on a weak RC4 cipher
³ Only available if Kerberos was negotiated

Exchange Online also offers Modern Auth (OAuth) but this just uses the Basic authentication headers to smuggle the OAuth token.

# BASIC AUTH
Basic authentication is sending the username nad password as a base64 encoded value in the HTTP headers.
This is the simplest authentication option available but also the weakeast.
It only works for local accounts and should only be used over a HTTPS connection.
Using it over a HTTP connection is dangerous as the credentials are simply encoded not encrypted and there is no encryption of the data exchanged between the client and server.

If Basic authentication over HTTP is truly desired then `New-PSWSManSessionOption -NoEncryption` must be set and the server must allow unencrypted access.

By default Basic authentication is disabled on the server, to enable it run:

```powershell
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value True
```

# CERTIFICATE AUTH
Certificate authentication is when the client offers an X.509 certificate to the server for authentication.
The server will check that this certificate was issued by a Certificate Authority (CA) that it trusts and whether the certificate maps to a local account mapping defined on the server itself.
It can only be used over a HTTPS connection as it's a feature done through the TLS connection itself.
To use certificate authentication the following must be done:

+ A WSMan HTTPS listener created on the server

+ A X.509 certificate created for `ClientAuthentication` extended key usage

+ The X.509 certificate must also have the Subject Alternative Name (SAN) set to `otherName:1.3.6.1.4.1.311.20.2.3;UTF8:$USERNAME@localhost` where the `$USERNAME` is the local user it is for

+ The X.509 certificate must be issued by a CA trusted by the server, if the client certificate is a self signed cert, it must be installed in the trusted CA root store on the server

+ The X.509 certificate must be installed in the `TrustedPeople` store on `LocalMachine`

+ A mapping between the certificate and the local user account must be set up

+ The WSMan service must be configured to allow Certificate authentication

The following PowerShell snippet can be used to generate a self-signed client certificate that is mapped to a local account on the server.

```powershell
# Prompt for the username and password to map the certificate to
# Do not use the SERVERNAME\ prefix. Just specify the username itself
$credential = Get-Credential -UserName username

# Generate self signed certificate for client authentication
$selfSignedParams = @{
    Subject           = "CN=$($credential.UserName)"
    KeyUsage          = 'DigitalSignature', 'KeyEncipherment'
    KeyAlgorithm      = 'RSA'
    KeyLength         = 2048
    TextExtension     = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=$($credential.UserName)@localhost")
    Type              = 'Custom'
    CertStoreLocation = "Cert:\CurrentUser\My"
}
$cert = New-SelfSignedCertificate @selfSignedParams

# Create a PFX for the client to use.
$certPath = Join-Path $pwd "client_auth.pfx"
$certBytes = $cert.Export("Pfx")

# Use this to export and protect with a password
# $certBytes = $cert.Export("Pfx", $password)
[System.IO.File]::WriteAllBytes($certPath, $certBytes)

# Remove it from the cert store once exported
Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force

# Reload the certificate but with no key associated with it
# before loading it into the relevant stores.
$certNoKey = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.RawData)

# Store the certificate in the trusted root store. This can be skipped if the
# cert is signed by a trusted CA. If the cert is signed but the issuer is not
# trusted, this should be the root CA certificate to trust.
$store = Get-Item -Path Cert:\LocalMachine\Root
$store.Open("ReadWrite")
$store.Add($certNoKey)
$store.Dispose()

# Install the client certificate into the TrustedPeople store.
# This is the client certificate itself and not the CA.
$store = Get-Item -Path Cert:\LocalMachine\TrustedPeople
$store.Open("ReadWrite")
$store.Add($certNoKey)
$store.Dispose()

# Get the thumbprint of the chain root. For self signed certs this is
# the cert itself, for a signed cert this is the root issuer.
$certChain = [Security.Cryptography.X509Certificates.X509Chain]::new()
[void]$certChain.Build($certNokey)
$caThumbprint = $certChain.ChainElements.Certificate[-1].Thumbprint

# Map the certificate to the user's credentials
$credBinding = @{
    Path       = 'WSMan:\localhost\ClientCertificate'
    Subject    = $credential.UserName
    URI        = "*"
    Issuer     = $caThumbprint
    Credential = $credential
    Force      = $true
}
New-Item @credBinding

# Enable Certificate authentication on the WSMan service
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value True
```

If the local account's password expires, the credential and the certificate needs to be remapped.

# NTLM AUTH
NTLM authentication is a legacy authentication protocol offered by Microsoft.
It supports both local and domain accounts making it usable in more circumstances but due to its age it is quite weak when used by itself.
NTLM authentication should only be used with WSMan when the connection is being used over HTTPS.
The reason for this is that HTTPS offers both server authentication through certificates, and strong message encryption through TLS.
Without server authentication, the client cannot know for sure the server it is talking to is who it thinks it is.
Without TLS message encryption, the data sent by NTLM is encrypted with a weak RC4 key.
The NTLM token send in the HTTP headers is also suceptible to cracking if a weak password was used.
Ultimately NTLM should be avoided unless HTTPS is being used.

Availability of NTLM depends on the OS and authentication provider used.
On Windows NTLM will work out of the box and supports using the current user's credentials.
On macOS NTLM will also work out of the box but can only be used when explicit credentials are passed with `-Credential` when creating the session.
On Linux NTLM is only available if both GSSAPI is installed and the [gss-ntlmssp](https://github.com/gssapi/gss-ntlmssp) package is installed and configured.

The `Devolutions` authentication provider also supports NTLM authentication out of the box.
It only supports explicit credentials but is a good option to use that is consistent across all platforms.
To specify the `Devolutions` authentication provider to be used pass in the session options `New-PSWSManSessionOption -AuthProvider Devolutions`.
Alternatively, the `Devolutions` authentication package can be set globally as the default with `Set-PSWSManAuthProvider -AuthProvider Devolutions`.
See `#DEVOLUTIONS SSPI` for more details.

# KERBEROS AUTH

# NEGOTIATE AUTH

# CREDSSP AUTH

# SPECIFY AUTHENTICATION METHOD

# CREDENTIAL DELEGATION

# DEVOLUTIONS SSPI
