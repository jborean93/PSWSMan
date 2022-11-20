---
external help file: PSWSMan.dll-Help.xml
Module Name: PSWSMan
online version: https://www.github.com/jborean93/PSWSMan/blob/main/docs/en-US/New-PSWSManSessionOption.md
schema: 2.0.0
---

# New-PSWSManSessionOption

## SYNOPSIS
Creates an object that specifies custom connection options for a WSMan PSSession.

## SYNTAX

### SimpleTls (Default)
```
New-PSWSManSessionOption [-MaximumRedirection <Int32>] [-NoMachineProfile] [-Culture <CultureInfo>]
 [-UICulture <CultureInfo>] [-MaximumReceivedDataSizePerCommand <Int32>] [-MaximumReceivedObjectSize <Int32>]
 [-MaxConnectionRetryCount <Int32>] [-ApplicationArguments <PSPrimitiveDictionary>] [-OpenTimeout <Int32>]
 [-CancelTimeout <Int32>] [-SkipCACheck] [-SkipCNCheck] [-ClientCertificate <X509Certificate>]
 [-OperationTimeout <Int32>] [-NoEncryption] [-SPNService <String>] [-SPNHostName <String>]
 [-AuthMethod <AuthenticationMethod>] [-AuthProvider <AuthenticationProvider>] [-RequestKerberosDelegate]
 [-CredSSPAuthMethod <AuthenticationMethod>] [-CredSSPTlsOption <SslClientAuthenticationOptions>]
 [<CommonParameters>]
```

### TlsOption
```
New-PSWSManSessionOption [-MaximumRedirection <Int32>] [-NoMachineProfile] [-Culture <CultureInfo>]
 [-UICulture <CultureInfo>] [-MaximumReceivedDataSizePerCommand <Int32>] [-MaximumReceivedObjectSize <Int32>]
 [-MaxConnectionRetryCount <Int32>] [-ApplicationArguments <PSPrimitiveDictionary>] [-OpenTimeout <Int32>]
 [-CancelTimeout <Int32>] [-OperationTimeout <Int32>] [-NoEncryption] [-SPNService <String>]
 [-SPNHostName <String>] [-AuthMethod <AuthenticationMethod>] [-AuthProvider <AuthenticationProvider>]
 [-RequestKerberosDelegate] [-TlsOption <SslClientAuthenticationOptions>]
 [-CredSSPAuthMethod <AuthenticationMethod>] [-CredSSPTlsOption <SslClientAuthenticationOptions>]
 [<CommonParameters>]
```

## DESCRIPTION
The `New-PSWSManSessionOption` cmdlet creates an object that contains advanced options for a user-managed session (`PSSession`).
You can use this object as a value of the `-SessionOption` parameter of cmdlets that create a `PSSession`, such as `New-PSSession`, `Enter-PSSession`, `Invoke-Command`.
It is designed to extend the existing [New-PSSession](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssessionoption?view=powershell-7.3) cmdlet but expose more features that are available to PSWSMan, or bring back options that were locked under Windows only.

Without parameters, `New-PSWSManSessionOption` generates an object that contains the default value for all of the options.
Just like with `New-PSSessionOption`, the session options from this cmdlet can be used with the `$PSSessionOption` preference variable.
The value of this variable estabilish new default values for the session options.
They are used when a new PSSession is made without any explicit session options specified by `-SessionOption`.
For more information about the `$PSSessionOption` preference variable, see [about_Preference_Variables-$PSSessionOption])(https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7.3#pssessionoption).

There are a a few parameters on `New-PSSessionOption` with Windows that are omitted on this cmdlet either due to features not being available or different behaviour across the OS platforms.
These cmdlets are:

+ `-IdleTimeout`: Disconnected operation support is not implemented

+ `-IncludePortInSPN`: The `-SPNHostName` can be used to set the SPN hostname portion to whatever is desired instead

+ `-NoCompression`: Compression support is not available on PSWSMan

+ `-OutputBufferingMode`: Disconnected operation support is not implemented

+ `-ProxyAccessType`: Proxy support is not implemented

+ `-ProxyAuthentication` Proxy support is not implemented

+ `-ProxyCredential`: Proxy support is not implemented

+ `-SkipRevocationCheck`: By default dotnet skips revocation checks as they are not implemented on all platforms. To opt-in to these checks use `-TlsOption` with `CertificateRevocationCheckMode` set to `Offline` or `Online`

+ `-UseUTF16`: This option is not useful and not implemented

## EXAMPLES

### Example 1: Create a default session option
```powershell
PS C:\> New-PSWSManSessionOption
```

Creates a SessionOption object with the default values

### Example 2: Connect to a session with custom options
```powershell
PS C:\> $pso = New-PSWSManSessionOption -AuthMethod Kerberos
PS C:\> Enter-PSSession -ComputerName Server01 -SessionOption $pso
```

Creates a SessionOption that is used to connect to `Server01` with only `Kerberos` authentication.
This SessionObject can be used for multiple connections as needed.

### Example 3: Send arguments to the remote session
```powershell
PS C:\> $info = @{Foo = "Bar"}
PS C:\> $pso = New-PSWSManSessionOption -ApplicationArguments $info
PS C:\> Invoke-Command -ComputerName Server02 -SessionOption $pso -ScriptBlock {
>>     if ($PSSenderInfo.ApplicationArguments.Foo -eq "Bar") {
>>         "Hello Bar"
>>     }
>>     else {
>>         "Hello Unknown"
>>     }
>> }
```

Creates a hashtable that contains a primitive value and sets that as the session's application arguments.
The session can then retrieve that primitive dictionary using the `$PSSenderInfo.ApplicationArguments` value.

### Example 4: Disable certificate checks
```powershell
PS C:\> $pso = New-PSWSManSessionOption -SkipCACheck -SkipCNCheck
PS C:\> Enter-PSSession -ComputerName 192.168.1.2 -UseSSL -SessionOption $pso
```

Connects to `192.168.1.2` with a HTTPS connection but skips checking the CN of the server's certificate and whether it is trusted by a known CA.

### Example 5: Enable certificate revocation checks
```powershell
PS C:\> $tls = [System.Net.Security.SslClientAuthenticationOptions]@{
>>     TargetHost = "Server03"
>>     CertificateRevocationCheckMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Offline
>> }
PS C:\> $pso = New-PSWSManSessionOption -TlsOptions $tls
PS C:\> Invoke-Command -ComputerName Server03 -SessionOption $pso -UseSSL -ScriptBlock { $env:COMPUTERNAME }
```

Enables certificate revocation checks in `Offline` mode to check the peers certificate against an offline revocation list.
The value can also be set to `Online` to have dotnet attempt to download the revocation lists from pre-configured locations.

### Example 6: Connect using client certificate authentication
```powershell
PS C:\> $cert = Get-PfxCertificate -FilePath ~/client.pfx
PS C:\> $pso = New-PSWSManSessionOption -ClientCertificate $cert
PS C:\> Invoke-Command -ComputerName host.domain.com -UseSSL -SessionOption $pso { 'hi' }
```

Connects to the endpoint with TLS and provides a client certificate to use for authentication.
This certificate will only work for local accounts on the target server and must be set up in a specific manner.
The `-UseSSL` option must be set on the cmdlet that is creating the session, i.e. `New-PSSession`, `Invoke-Command`, `Enter-PSSession`, etc.

## PARAMETERS

### -ApplicationArguments
Specifies a `PrimitiveDictionary` that is sent to the remote session.
Commands and scripts in the remote session, including startup scripts in the session configuration, can find this dictionary with `$PSSenderInfo.ApplicationArguments`.
A `PSPrimitiveDictionary` is a dictionary that is limited to case-insensitive keys, and a subset of primitive value types, like `string`, `int`, `datetime`, etc.

```yaml
Type: PSPrimitiveDictionary
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AuthMethod
A PSWSMan specific property that adds support for selecting authentication mechanisms allowed by PSWSMan.
If not specified or `Default` is used then the value for `-Authentication` on the builtin cmdlets from PowerShell is used instead.

```yaml
Type: AuthenticationMethod
Parameter Sets: (All)
Aliases:
Accepted values: Default, Basic, Negotiate, NTLM, Kerberos, CredSSP

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AuthProvider
The authentication provider to use when doing `NTLM`, `Kerberos`, `Negotiate`, or `CredSSP` authentication.
If omitted, or set to `Default`, then the process wide default provider is used.
Use [Get-PSWSManAuthProvider](./Get-PSWSManAuthProvider.md) to get the process wide default and [Set-PSWSManAuthProvider](./Set-PSWSManAuthProvider.md) to set the process wide default.

Using `Native` will use the system provided authentication provider.
On Windows this is `SSPI`, on Linux this is `GSSAPI`, and on macOS this is `GSS.Framework`.

Using `Devolutions` will use the [sspi-rs](https://github.com/Devolutions/sspi-rs) provider from Devolutions which is a standalone Kerberos and NTLM implementation written in Rust.
The `Devolutions` package is bundled with PSWSMan but is not tested as thourougly as the `Native` implementations.

```yaml
Type: AuthenticationProvider
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CancelTimeout
Determines how long PowerShell waits for a cancel operation (`ctrl + c`) to finish before ending it.
The value is measures in milliseconds.

The default value is `60000` (one minute).
A value of `0` means no time-out and the command continues indefinitely.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: CancelTimeoutMSec

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ClientCertificate
The `X509Certificate` object that is used for TLS client authentication, otherwise known as Certificate auth with WinRM.
This certificate must have a private key associated with it for this to be used for certificate auth.
The `-UseSSL` option much be set on the cmdlets that create the PSSession for certificates to be used.

This is a PSWSMan specific option that is used to specify a certificate for authentication for certificates that don't exist in the user or system wide certificate store.
Use the `-CertificateThumbprint` parameter on cmdlets that create the session to refer to certificates by thumbprint in the `Cert:\CurrentUser\My` or `Cert:\LocalMachine\My` store.

```yaml
Type: X509Certificate
Parameter Sets: SimpleTls
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CredSSPAuthMethod
Controls the sub-authentication protocol that CredSSP will use.
By default CredSSP will use `Negotiate` as part of its sub-authentication protocol but it can be set to either `Negotiate`, `NTLM`, `Kerberos` to control what it uses.
The `Basic` and `CredSSP` options cannot be specified here.

```yaml
Type: AuthenticationMethod
Parameter Sets: (All)
Aliases:
Accepted values: Default, Basic, Negotiate, NTLM, Kerberos, CredSSP

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CredSSPTlsOption
Controls the TLS options that is used by CredSSP when it establishes its TLS connection to the server.
This allows you to control TLS behaviour that the CredSSP connection uses to do things like validate the server certificate, control the TLS protocol or cipher suite selections.
Due to an API limitation in dotnet, the `TargetName` of these custom options must be set to a unique name when running on Linux or Windows.

```yaml
Type: SslClientAuthenticationOptions
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Culture
Specifies the culture to use for the session.
Enter the culture name in `<languagecode2>-<country/regioncode2>` format (like `ja-JP` or `en-US`).
This also accepts a `CultureInfo` object.

The default value is `$null`, and the culture that is set in the operating system is used in the session.

```yaml
Type: CultureInfo
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxConnectionRetryCount
Specifies the number of times that PowerShell attempts to make a connection to a target machine if the current attempt fails due to network issues.
The default value is `5`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaximumReceivedDataSizePerCommand
Specifies the maximum number of bytes that the local computer can receive from the remote computer in a single command.
By default, there is no data size limit.

This option is designed to protect the resources on the client computer.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaximumReceivedObjectSize
Specifies the maximum size of an object, in bytes, that the local computer can receive from the remote computer.
By default the value is `209715200`, or `200MiB`.

This option is designed to protect the resources on the client computer.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaximumRedirection
Determines how many times PowerShell redirects a connection to an altrnate Uniform Resource Identifier (URI) before the connection fails.
The default value is `5`, a value of `0` prevents all redirection.

This option is used in the session only when the `-AllowRedirection` parameter is used in the command that creates the session.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NoEncryption
Turns off data encryption that is used for `NTLM`, `Kerberos`, and `CredSSP` authentication over HTTP.
This should only be used for testing purposes as any data exchanged over the network will be in plaintext.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NoMachineProfile
Prevents loading the user's Windows user profile.
As a result, the session might be created faster, but user-specific registry settings, items such as environment variables, and certificate are not available in the session.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OpenTimeout
Determines how long the client computer waits for the session connection to be establish.
When the interval expires, the command to establish the connection fails.
Enter a value in milliseconds.

The default is `180000` (3 minutes) and a value of `0` means no time out.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: OpenTimeoutMSec

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OperationTimeout
Determines the maximum time WinRM waits for the server to process an operation, like creating a shell or connection before timing out.

The default value is `180000` (3 minutes) and a value of `0` means no time out.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: OperationTimeoutMSec

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequestKerberosDelegate
When using Kerberos auth, or Kerberos through Negotiate, this requests the ticket from the KDC to have delegation enabled.
For this to work on Linux and macOS the ticket retrieved through `kinit` must be forwardable, or if an explicit credential is specified then the `krb5.conf` used must be configured to request forwardable tickets.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipCACheck
Specifies that when it connects over HTTPS, the client does not validate that the server certificate is signed by a trusted certification authority (CA).
This option is mutually exclusive to `-TlsOption`.

Use this option only when the remote computer is trusted by using another mechanism.

```yaml
Type: SwitchParameter
Parameter Sets: SimpleTls
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipCNCheck
Specifies that the certificate common name (CN) of the server does not have to match the hostname of the server.
This option is used only in remote operations that use the HTTPS protocol.
This option is mutually exclusive to `-TlsOption`.

Use this option only when the remote computer is trusted by using another mechanism.

```yaml
Type: SwitchParameter
Parameter Sets: SimpleTls
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SPNHostName
Override the hostname portion used for the Service Principal Name (SPN) requested by Kerberos.
By default the hostname of the connection is used.
This can be used to build an SPN with an explicit port, or to request a different host entirely.

The SPN is built in the form `$SPNService/$SPNHostName` where the `$SPNService` can be specified by `-SPNService`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SPNService
Override the service portion used for the Service Principal Name (SPN) requested by Kerberos.
By default the service `host` is used.
This can be used to build an SPN that targets a different service for the host requested.

The SPN is built in the form ``$SPNService/$SPNHostName` where `$SPNHostName` can be specified by `-SPNHostName`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TlsOption
Set the TLS authentication options used on a HTTPS connection.
This option is mutually exclusive to `-SkipCACheck` and `-SkipCNCheck`.

Unlike `-SkipCACheck` and `-SkipCNCheck`, this can control more options around the TLS protocol, like the protocols and cipher suites used in a connection.
It can also be used to specify a custom certificate verification logic than what is provided by dotnet.

The [New-PSWSManCertValidationCallback](./New-PSWSManCertValidationCallback.md) cmdlet can be used to create a delegate for `RemoteCertificateValidationCallback` of this object that will run the PowerShell scriptblock for validation.

```yaml
Type: SslClientAuthenticationOptions
Parameter Sets: TlsOption
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UICulture
Specifies the UI culture to use for the session.

Values values include:

+ A culture name in `<languagecode2>-<count/regioncode2>` format, such as `ja-JP`, `en-US`, etc

+ A variable that contains a CultureInfo object

+ A command that gets a CultureInfo object, such as `Get-Culture`

The default value is `$null, and the UI culture that is set in the operation system when the session is created.

```yaml
Type: CultureInfo
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
This function does not accept input from the pipeline.

## OUTPUTS

### System.Management.Automation.Remoting.PSSessionOption
This cmdlet outputs a `PSSession` option with the PSWSMan specific properties added as a custom note property.

## NOTES

## RELATED LINKS
