---
external help file: PSWSMan.dll-Help.xml
Module Name: PSWSMan
online version:
schema: 2.0.0
---

# Invoke-WinRMCommand

## SYNOPSIS
Runs a command on remote hosts over PSWSMan's WinRM client without hooking PowerShell.

## SYNTAX

### ComputerName (Default)
```
Invoke-WinRMCommand [-ComputerName] <String[]> [-ScriptBlock] <ScriptBlock>
 [-ArgumentList <ArgumentsOrParameters>] [-InputObject <PSObject>] [-ConfigurationName <String>]
 [-ThrottleLimit <Int32>] [-HideComputerName] [-Credential <PSCredential>] [-Port <Int32>] [-UseSSL]
 [-ApplicationName <String>] [-SessionOption <WinRMSessionOption>] [-Authentication <AuthenticationMethod>]
 [-CertificateThumbprint <String>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### FilePathComputerName
```
Invoke-WinRMCommand [-ComputerName] <String[]> [-FilePath] <String> [-ArgumentList <ArgumentsOrParameters>]
 [-InputObject <PSObject>] [-ConfigurationName <String>] [-ThrottleLimit <Int32>] [-HideComputerName]
 [-Credential <PSCredential>] [-Port <Int32>] [-UseSSL] [-ApplicationName <String>]
 [-SessionOption <WinRMSessionOption>] [-Authentication <AuthenticationMethod>]
 [-CertificateThumbprint <String>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### ConnectionUri
```
Invoke-WinRMCommand [-ConnectionUri] <Uri[]> [-ScriptBlock] <ScriptBlock>
 [-ArgumentList <ArgumentsOrParameters>] [-InputObject <PSObject>] [-ConfigurationName <String>]
 [-ThrottleLimit <Int32>] [-HideComputerName] [-Credential <PSCredential>]
 [-SessionOption <WinRMSessionOption>] [-Authentication <AuthenticationMethod>]
 [-CertificateThumbprint <String>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### FilePathConnectionUri
```
Invoke-WinRMCommand [-ConnectionUri] <Uri[]> [-FilePath] <String> [-ArgumentList <ArgumentsOrParameters>]
 [-InputObject <PSObject>] [-ConfigurationName <String>] [-ThrottleLimit <Int32>] [-HideComputerName]
 [-Credential <PSCredential>] [-SessionOption <WinRMSessionOption>] [-Authentication <AuthenticationMethod>]
 [-CertificateThumbprint <String>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### Session
```
Invoke-WinRMCommand [-Session] <PSSession[]> [-ScriptBlock] <ScriptBlock>
 [-ArgumentList <ArgumentsOrParameters>] [-InputObject <PSObject>] [-ThrottleLimit <Int32>] [-HideComputerName]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### FilePathSession
```
Invoke-WinRMCommand [-Session] <PSSession[]> [-FilePath] <String> [-ArgumentList <ArgumentsOrParameters>]
 [-InputObject <PSObject>] [-ThrottleLimit <Int32>] [-HideComputerName] [-ProgressAction <ActionPreference>]
 [<CommonParameters>]
```

## DESCRIPTION
The `Invoke-WinRMCommand` cmdlet runs a scriptblock or script file on one or more remote hosts and returns the output, the same as `Invoke-Command`, but it uses PSWSMan's own WinRM client.
It does not require `Enable-PSWSMan`, the connections are made through the public custom remoting transport API of PowerShell 7.3 and newer like `New-WinRMSession`.

With `-ComputerName` or `-ConnectionUri` a session is opened to each host for the command and closed again afterwards, with `-Session` the command runs in existing sessions and any state it leaves behind, like variables, stays in the session.
The hosts are run at the same time, up to `-ThrottleLimit` at once, and the output is written as it arrives so the output of different hosts can be interleaved.
Each output object has the `PSComputerName`, `RunspaceId` and `PSShowComputerName` properties that `Invoke-Command` adds to tell where it came from.
A host that cannot be connected to is written as a non-terminating error with the host as its target object and the command still runs on the other hosts.

The streams behave like they do for `Invoke-Command`.
Errors from the remote command are written as non-terminating `RemotingErrorRecord` errors whose `OriginInfo` names the host, including a terminating error like one from `-ErrorAction Stop`.
The exception is a `throw` statement when the command runs on a single host or session, it is rethrown as a `RemoteException` that ends the calling script like a local `throw`, `-ErrorAction` does not apply to it and `try`/`catch` catches it.
With several hosts or sessions a `throw` is a non-terminating error of the host it came from.
Warning, verbose, debug and progress messages and the output of `Write-Host` are shown through the host by the remote session, redirecting those streams locally does not capture them, but the warnings are still added to `-WarningVariable`.
Information records are written to the information stream as `RemotingInformationRecord` objects.

Local values are passed to the remote command with `-ArgumentList`, `-InputObject` or the pipeline, or with the `$using:` scope modifier in the scriptblock or script file.
Unlike `Invoke-Command`, `-ArgumentList` also accepts a hashtable of parameter names and values that are bound by name, like splatting a hashtable.

Stopping the cmdlet with `Ctrl+C` stops the remote commands and closes the connections the cmdlet opened, the sessions given with `-Session` stay open and can be used again.

The `-AsJob`, `-InDisconnectedSession`, `-EnableNetworkAccess` and `-RemoteDebug` parameters of `Invoke-Command` are not supported.
To debug a remote command use the builtin `Invoke-Command -Session` with a session from `New-WinRMSession`, it works with these sessions without `Enable-PSWSMan`, see the examples.

## EXAMPLES

### Example 1: Run a command on several hosts
```powershell
PS C:\> Invoke-WinRMCommand -ComputerName Server01, Server02 -ScriptBlock { Get-Service -Name WinRM }
```

Gets the WinRM service on both hosts at the same time, each result has the host it came from in `PSComputerName`.

### Example 2: Pass positional arguments or named parameters
```powershell
PS C:\> $sb = {
>>     param ([string]$Name, [switch]$Force)
>>     "$Name $Force"
>> }
PS C:\> Invoke-WinRMCommand Server01 $sb -ArgumentList 'positional'
PS C:\> Invoke-WinRMCommand Server01 $sb -ArgumentList @{ Name = 'named'; Force = $true }
```

The first call passes `positional` as the first positional argument, the second binds the `Name` and `Force` parameters by name like splatting a hashtable.

### Example 3: Pass a hashtable as a positional argument
```powershell
PS C:\> Invoke-WinRMCommand Server01 { param ($Settings) $Settings.Key } -ArgumentList @(@{ Key = 'value' })
```

A hashtable given to `-ArgumentList` on its own is used as named parameters, wrapping it in an array with `@()` passes the hashtable itself as a positional argument.

### Example 4: Use local variables and pipeline input
```powershell
PS C:\> $threshold = 100
PS C:\> Get-Content ./processes.txt | Invoke-WinRMCommand Server01 {
>>     $input | ForEach-Object { Get-Process -Name $_ } | Where-Object CPU -gt $using:threshold
>> }
```

Sends each process name from the file to the remote command as input and uses the local `$threshold` variable with `$using:`.

### Example 5: Run multiple commands in a single session
```powershell
PS C:\> $session = New-WinRMSession -ComputerName Server01
PS C:\> Invoke-WinRMCommand -Session $session { $data = Get-Process }
PS C:\> Invoke-WinRMCommand -Session $session { $data.Count }
PS C:\> Remove-PSSession -Session $session
```

Runs two commands in the same session, the `$data` variable set by the first command is still there for the second one.

### Example 6: Debug a remote command
```powershell
PS C:\> $session = New-WinRMSession -ComputerName Server01
PS C:\> Invoke-Command -Session $session -RemoteDebug -ScriptBlock { $value = 'before'; Wait-Debugger; "after $value" }
Entering debug mode. Use h or ? for help.

At line:1 char:2
+  $value = 'before'; Wait-Debugger; "after $value"
+  ~~~~~~~~~~~~~~~~~
[Server01]:[DBG]: [Process:4712]: [Runspace2]: PS C:\Users\User\Documents> c
```

`Invoke-WinRMCommand` has no `-RemoteDebug` parameter as PowerShell only offers remote debugging through internal APIs.
The builtin `Invoke-Command -Session` works with a session from `New-WinRMSession` without `Enable-PSWSMan`, with `-RemoteDebug` it stops at the first statement and the remote debugger commands like `c`, `s` and `q` are used at the `[DBG]` prompt.

## PARAMETERS

### -ApplicationName
The application name segment of the connection URI, the default is `wsman`.

```yaml
Type: String
Parameter Sets: ComputerName, FilePathComputerName
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ArgumentList
The values passed to the remote command.
A hashtable or other dictionary binds its keys and values to the parameters of the command by name, like splatting a hashtable.
A switch parameter is turned on with `$true` or `[switch]::Present`, a value of `$false` binds it as off, the same as `-Force:$false`, and leaving the key out leaves it unbound.
Anything else is passed positionally in order, a single value is one argument.
To pass a hashtable as a positional argument wrap it in an array, like `-ArgumentList @(@{ Key = 'value' })`.

The values are serialized to the remote host like the output of a remote command, so most objects arrive as deserialized property bags.

```yaml
Type: ArgumentsOrParameters
Parameter Sets: (All)
Aliases: Args

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Authentication
The authentication method used to authenticate with the remote host.
The default selects Negotiate, or certificate authentication when `-CertificateThumbprint` or a client certificate in the session option is set.
Unlike `-Authentication` on `Invoke-Command` this uses the authentication methods of PSWSMan so `NTLM` and `CredSSP` can be selected directly.
When set to anything other than `Default` it takes precedence over the `AuthMethod` of the `-SessionOption`.
`Basic` requires either `-UseSSL` or `NoEncryption` in the session option.

```yaml
Type: AuthenticationMethod
Parameter Sets: ComputerName, FilePathComputerName, ConnectionUri, FilePathConnectionUri
Aliases:
Accepted values: Default, Basic, Negotiate, NTLM, Kerberos, CredSSP

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CertificateThumbprint
The thumbprint of a client certificate in the current user or local machine certificate store to authenticate with.
It requires `-UseSSL` or a `https` `-ConnectionUri` and cannot be used with `-Credential` or `-Authentication`.

```yaml
Type: String
Parameter Sets: ComputerName, FilePathComputerName, ConnectionUri, FilePathConnectionUri
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerName
The hosts to run the command on.
A session is opened to each host for the command and closed again once it finishes.

```yaml
Type: String[]
Parameter Sets: ComputerName, FilePathComputerName
Aliases: Cn

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConfigurationName
The session configuration (endpoint) on the remote host to connect to, the default is `Microsoft.PowerShell`.
A name is turned into the resource URI `http://schemas.microsoft.com/powershell/<name>`, a value that contains a `/` is used as the resource URI as is.

```yaml
Type: String
Parameter Sets: ComputerName, FilePathComputerName, ConnectionUri, FilePathConnectionUri
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConnectionUri
The full URIs of the WSMan endpoints to run the command on, for example `http://Server01:5985/wsman` or `https://Server01:5986/wsman`.
Each must be an absolute `http` or `https` URI and it is used as is, a URI without a port connects to port 80 or 443 as it does for `Invoke-Command`, and one without a path uses `/wsman`.
It cannot be used with `-ComputerName`, `-Port`, `-UseSSL` or `-ApplicationName`.

```yaml
Type: Uri[]
Parameter Sets: ConnectionUri, FilePathConnectionUri
Aliases: URI, CU

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
The credential used to authenticate with the remote host.
When not set the credential of the current user is used.

```yaml
Type: PSCredential
Parameter Sets: ComputerName, FilePathComputerName, ConnectionUri, FilePathConnectionUri
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FilePath
The path of a local script file to run on the remote hosts.
The file is read locally and its content is sent as the command, it does not need to exist on the remote host.
Like a scriptblock the script can use `$using:` and have a `param` block for `-ArgumentList`.

```yaml
Type: String
Parameter Sets: FilePathComputerName, FilePathConnectionUri, FilePathSession
Aliases: PSPath

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -HideComputerName
Sets the `PSShowComputerName` property of each output object to `$false` so the formatter does not show the `PSComputerName` column.
The `PSComputerName` property is still added.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: HCN

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InputObject
Input to the remote command, available there in `$input`.
Pipeline input is sent to every host as it arrives, a value given with `-InputObject` is sent as one object even when it is a collection.
Without either the input of the remote command is empty.

```yaml
Type: PSObject
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Port
The port of the WSMan listener, the default is `5985` or `5986` with `-UseSSL`.

```yaml
Type: Int32
Parameter Sets: ComputerName, FilePathComputerName
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
New common parameter introduced in PowerShell 7.4.

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ScriptBlock
The command to run on the remote hosts.
The scriptblock is sent as text and run on the remote host so it cannot use local functions or variables except through `$using:`, `-ArgumentList` and `-InputObject`.

```yaml
Type: ScriptBlock
Parameter Sets: ComputerName, ConnectionUri, Session
Aliases: Command

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Session
The sessions to run the command in, like those created by `New-WinRMSession`.
The command runs in the global scope of the session so variables and functions it defines stay in the session for later commands.
A session that is not open is written as an error and skipped.

```yaml
Type: PSSession[]
Parameter Sets: Session, FilePathSession
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SessionOption
The connection options, the output of `New-WinRMSessionOption` or a hashtable of its option names and values, like `@{ OperationTimeout = 30000; AuthProvider = 'Devolutions' }`.
A `PSSessionOption`, like the output of `New-PSSessionOption`, is accepted too, but it is an error if it sets an option PSWSMan does not support, like `NoCompression`, `IdleTimeout` or a proxy.
The `ApplicationArguments` of the options are sent to the remote session and available there in `$PSSenderInfo.ApplicationArguments`.
See `New-WinRMSessionOption` for the options and their defaults.

```yaml
Type: WinRMSessionOption
Parameter Sets: ComputerName, FilePathComputerName, ConnectionUri, FilePathConnectionUri
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ThrottleLimit
The most hosts or sessions the command runs on at the same time.
The default is `32`, a value of `0` or less also uses the default.

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

### -UseSSL
Connect over HTTPS instead of HTTP.

```yaml
Type: SwitchParameter
Parameter Sets: ComputerName, FilePathComputerName
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

### System.Management.Automation.PSObject
Input for the remote command, sent to every host.

## OUTPUTS

### System.Object
The output of the remote command, with the `PSComputerName`, `RunspaceId` and `PSShowComputerName` properties added to each object.

## NOTES
This cmdlet has the alias `iwcm`.

## RELATED LINKS

[New-WinRMSession](./New-WinRMSession.md)

[Enter-WinRMSession](./Enter-WinRMSession.md)

[New-WinRMSessionOption](./New-WinRMSessionOption.md)
