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
It is also the default method used when no method is specified.

Here is a simple matrix of each options and some of the features they support:

|Method|Local Account|Domain Account|Implicit Credential|HTTP Encryption|Delegation|
|-|-|-|-|-|-|
|Basic|Y|N|N|N|N|
|Certificate|Y|N|N|N/A¹|N|
|NTLM|Y|Y|Y²|Y³|N|
|Kerberos|N|Y|Y|Y|Y|
|Negotiate|Y|Y|Y⁴|Y|Y⁵|
|CredSSP|Y|Y|N|Y|Y|

¹ Certificate auth only available over HTTPS
² Only on Windows with the System auth provider
³ NTLM HTTP Encryption is based on a weak RC4 cipher and should not be used
⁴ On Windows with the System auth provider or on other OS', implicit credentials will only work with Kerberos through Negotiate
⁵ Only available if Kerberos was negotiated

Exchange Online also offers Modern Auth (OAuth) but this just uses the Basic authentication headers to smuggle the OAuth token.

This is a list of known issues with the various authentication methods and providers on PSWSMan:

+ Certificate

  + No supported on Linux with PowerShell 7.2.x (dotnet 6) on a TLS 1.3 connection

+ Kerberos

  + Currently broken with the `Devolutions` authentication provider, requires a new release of the [DevolutionsSspi nuget package](https://www.nuget.org/packages/Devolutions.Sspi)

+ CredSSP

  + Currently not supported with the `Devolutions` authentication provider - https://github.com/Devolutions/sspi-rs/issues/84

# BASIC AUTH
Basic authentication is sending the username nad password as a base64 encoded value in the HTTP headers.
This is the simplest authentication option available but also the weakeast.
It only works for local accounts and should only be used over a HTTPS connection.
When specifying a credential for Basic authentication only the username should be used.
Do not specify the hostname portion of the username, e.g. use `username` and not `HOST\username`.

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
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value True
```

If the local account's password expires, the credential and the certificate needs to be remapped.

Support for using certificate authentication with TLS 1.3 enabled servers is limited.
Client certificate authentication does not currently work on Linux hosts running PowerShell 7.2 (dotnet 6) and with a TLS 1.3 connection.
In order to use certificate auth with TLS 1.3 on Linux either upgrade to PowerShell 7.3 or limit the TLS protocol to TLS 1.2.

```powershell
$tlsOption = [System.Net.Security.SslClientAuthenticationOptions]@{
    TargetHost                          = 'TargetHost'
    ClientCertificates                  = [System.Security.Cryptography.X509Certificates.X509CertificateCollection]::new(
        @($ClientCertificate))
}

if ($IsLinux -and [Environment]::Version -lt [Version]'7.0') {
    $tlsOption.EnabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls12
}

$pso = New-PSWSManSessionOption -TlsOption $tlsOption
Invoke-Command -ComputerName host -SessionOption $pso -ScriptBlock { ... }
```

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

By default Windows will allow NTLM authentication through the `Negotiate` auth package.
If this package has been disabled then NTLM will not work.

# KERBEROS AUTH
Kerberos authentication is a domain authentication method that supports AES encryption over HTTP and server authentication.
It is the first protocol that is attempted with the Negotiate method.

Kerberos authentication can also be used to delegate the ticket to remote host.
This delegation enables the remote session to be able to connect to another downstream server like a UNC path.
To request a delegated ticket the session option `New-PSWSManSessionOption -RequestKerberosDelegate` must be specified.
See `#CREDENTIAL DELEGATION` for more details.

Part of the Kerberos authentication process is to lookup the target server using an service principal name (SPN).
The SPN is constructed using the `-ComputerName` value that is being connected to form the SPN `host/$ComputerName`.
To change the service portion `host` to something else use `New-PSWSManSessionOption -SPNService host`.
To override the hostname portion to something else use `New-PSWSManSessionOpiton -SPNHostName other`.
For example `New-PSWSManSessionOption -SPNService http -SPNHostName test` will use the SPN `http/test`.

Availability of Kerberos depends on the OS and authentication provider used.
On Windows Kerberos will work out of the box and supports using the current user's credentials.
While it is easier for the host to be domain joined it is possible for Windows to use Kerberos if the host has been configured to map the realm to a KDC.
On macOS Kerberos will also work out of the box and credentials can be retrieved using `kinit` or with an explicit credential.
On Linux Kerberos is only available if GSSAPI is installed and like macOS credentials can be retrieved through `kinit` or with an explicit credential.
Both macOS and Linux GSSAPI can be configured through an `/etc/krb5.conf` file.
It can also use DNS SRV records to lookup domain realms.

The `Devolutions` authentication provider also supports Kerberos authentication out of the box.
It only support explicit credentials but as it requires no system packages it provides a consitent experience across all platforms.
DevolutionsSspi can retrieve domain configuration through many means, like the `/etc/krb5.config`.
To specify the `Devolutions` authentication provider to be used pass in the session options `New-PSWSManSessionOption -AuthProvider Devolutions`.
Alternatively, the `Devolutions` authentication package can be set globally as the default with `Set-PSWSManAuthProvider -AuthProvider Devolutions`.
See `#DEVOLUTIONS SSPI` for more details.

Kerberos can either be used through the Negotiate method but can also be explicitly used as the Kerberos method.

# NEGOTIATE AUTH
Negotiate authentication is a psuedo method that combines both Kerberos with a fallback for NTLM authentication.
It is enabled by default on the WSMan server.
It is the default authentication method tried by PSWSMan when no authentication method is chosen.

The same Kerberos options `-RequestKerberosDelegate`, `-SPNService`, and `-SPNHostName` also apply to Negotiate authentication if it negotiates Kerberos authentication.

# CREDSSP AUTH
CredSSP is a more complex authentication method that works for both local and domain accounts.
It will delegate the user's credentials to the remote host allowing it to access further downstream servers with its credentials.
Internally CredSSP uses the Negotiate protocol to authenticate the user but because it needs the users credentials to delegate it only works with credentials supplied by `-Credential`.

CredSSP creates a temporary TLS context that wraps the authentication exchange and subsequent messages.
This is unrelated to the actual HTTP transport, i.e. CredSSP works just fine over a HTTP connection.
The following options can be specified with `New-PSWSManSessionOption` to control the CredSSP authentication behaviour

+ `CredSSPAuthMethod` - By default CredSSP will use `Negotiate` but this can be set to `Kerberos` or `NTLM` to retrict CredSSP from only using one or the other

+ `CredSSPTlsOption` - Controls the TLS wrapper of the CredSSP session

As well as this the `-SPNService` and `-SPNHostName` will be used on the inner Negotiate stage of CredSSP if Kerberos is used.
The TLS option can be used to finely control the TLS context that CredSSP sets up.
For example the default TLS context for CredSSP will not validate the CredSSP certificate as it's typically an ephemeral self-signed certificate.
By specifying a custom TLS option for CredSSP it can be setup so the remote certificate is verified or that only specific TLS protocols or cipher suites are used.
Be careful not to restrict the TLS protocols available to just TLS 1.3, Windows does not support TLS 1.3 used for CredSSP as of yet.

CredSSP is not enabled by default on the remote server as the unconstrained delegation can be dangerous if the remote host is not trusted.
To enable CredSSP on the WSMan server run the following:

```powershell
Enable-WSManCredSSP -Role Server
```

# SPECIFY AUTHENTICATION METHOD
There are two main ways an authentication method is set:

+ On the `-Authentication` parameter of cmdlets that create a PSSession, e.g. `New-PSSession`, `Invoke-Command`, `Enter-PSSession`

+ On the `-AuthMethod` parameter of the `New-PSWSManSessionOption`

The `-Authentication` parameter is limited to just `Basic`, `Kerberos`, `Negotiate`, or `CredSSP` while the `-AuthMethod` parameter also includes `NTLM` as an option.
The `-AuthMethod` parameter takes priority over `-Authentication` if both are set.
The default authentication method chosen in `Negotiate` which typically offers the best out of box experience.
It favours the system SSPI/GSSAPI library but on Linux it may fallback to the Devolutions provider if GSSAPI is not installed.

# CREDENTIAL DELEGATION
A common problem that is encountered with remote PSSessions is the lack of credential delegation on the default authentication methods.
This problem is also known as the [double hop problem](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/ps-remoting-second-hop?view=powershell-7.3) and is essentially a failure to authenticate the remote session with a futher downstream server.
For example accessing a network path on the remote session will fail with access is denied even if the connection user typically has access to that server.

```powershell
Invoke-Command -ComputerName Server1 -ScriptBlock {
    # This will fail to access Server2
    Get-Content -Path "\\Server2\share\file.txt"
}
```

There are 2 main ways they can be solved in the connection method:

+ Use CredSSP, or

+ Use Kerberos (or Kerberos through Negotiate) with `-RequestKerberosDelegation`

Using `CredSSP` is straight forward as the credentials are provided as part of the authentication process and the remote session can delegate them.
This is considered unconstrained delegation and can be dangerous if the remote host is compromised as it now has access to your credentials to do as it wishes.

Using `-RequestKerberosDelegation` with Kerberos auth is also a form on unconstrained delegation so it has the same security concerns as CredSSP.
When this switch is set, the authentication process will request a delegated ticket from the KDC and use that as part of authenticating with the remote host.
This ticket is special in that the remote host can then use that authentication ticket to request subsequent tickets for any downstream servers as requested.
For a target server to get a delegated Kerberos ticket it must be marked in Active Directory with `Trust this computer for delegation to any service (Kerberos only)` in the Delegation tab.
Without the target server being trusted Windows will not give you a delegated ticket even if `-RequestKerberosDelegation` is set.

Linux and macOS are slightly different in that it ignores the delegation setting in AD unless `enforce_ok_as_delegate` is set in the `krb5.conf` file.
Linux and macOS can also only delegate if:

+ Using implicit creds, they are marked as forwardable (`kinit -f username@READLM.COM`)

+ Using explicit creds, the `forwardable = true` flag is set in the `krb5.conf`

To verify if the cred retrieved from `kinit` is forwardable, run `klist -f` and the flags should have `F`.

To verify if the remote PSSession has a forwardable ticket that it can use for delegation, the `klist.exe` command will display the `forwarded` flag.

The Devolutions auth provider does not currently support `-RequestKerberosDelegation` as it is missing the feature https://github.com/Devolutions/sspi-rs/issues/81.

# DEVOLUTIONS SSPI
By default the PSWSMan authentication process will use the system provided library, SSPI and GSSPI.
The module also ships with a copy of [sspi-rs](https://github.com/Devolutions/sspi-rs) from Devolutions.
The `sspi-rs` library is a cross platform implementation of the SSPI API that is completely independent from any system dependencies.
This means it can use both NTLM and Kerberos authentication without relying on either SSPI or GSSAPI to be installed and configured.
It also means that any behaviour on one platform is the same on any other.

By default Devolutions SSPI is only used if the builtin GSSAPI library is not installed on Linux but it can be set as the default authentication provider process wide or on a specific session.
The code `Set-PSWSManAuthProvider -AuthProvider Devolutions` can be used to default the process wide default to use Devolutions SSPI.
Otherwise `New-PSWSManSessionOption -AuthProvider Devolutions` can be used on a specific session setup to use Devolutions for that connection.
The `New-PSWSManSessionOption -AuthProvider ...` takes precendence over the global process wide setting.

Support for Devolutions is limited and while things should work it is an experimental feature and mileage may vary.
Currently `CredSSP` will not work with Devolutions due to it missing the feature https://github.com/Devolutions/sspi-rs/issues/84.
