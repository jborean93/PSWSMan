BeforeDiscovery {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

    # A GSSAPI library the System provider can load on this host, if any.
    # Windows never uses GSSAPI so the library based tests are skipped there.
    $gssapiLib = $null
    if (-not $IsWindows) {
        $candidates = if ($IsMacOS) {
            '/System/Library/Frameworks/GSS.framework/GSS'
        }
        else {
            'libgssapi_krb5.so.2', 'libgssapi.so.3', 'libgssapi.so'
        }

        foreach ($candidate in $candidates) {
            $handle = [IntPtr]::Zero
            if ([System.Runtime.InteropServices.NativeLibrary]::TryLoad($candidate, [ref]$handle)) {
                [System.Runtime.InteropServices.NativeLibrary]::Free($handle)
                $gssapiLib = $candidate
                break
            }
        }
    }

    # The System provider can be selected when SSPI or a GSSAPI library is available.
    $systemAvailable = $IsWindows -or $null -ne $gssapiLib
}

# The discovery time values are passed through -ForEach so they are also
# available when the tests run.
Describe "Get and Set-PSWSManAuth" -ForEach @(@{ GssapiLib = $gssapiLib; SystemAvailable = $systemAvailable }) {
    It "Gets the default auth settings" {
        $actual = Get-PSWSManAuth
        $actual | Should -BeOfType ([PSWSMan.Commands.PSWSManAuthSettings])
        $actual.DefaultAuthProvider | Should -Be ([PSWSMan.AuthenticationProvider]::System)
        $actual.GssapiLib | Should -Be 'Default'
    }

    It "Sets the auth settings with WhatIf" {
        Set-PSWSManAuth -AuthProvider Devolutions -WhatIf
        $actual = Get-PSWSManAuth
        $actual.DefaultAuthProvider | Should -Be ([PSWSMan.AuthenticationProvider]::System)
        $actual.GssapiLib | Should -Be 'Default'
    }

    It "Sets the default auth provider" -Skip:(-not $SystemAvailable) {
        Set-PSWSManAuth -AuthProvider Devolutions
        try {
            $actual = Get-PSWSManAuth
            $actual.DefaultAuthProvider | Should -Be ([PSWSMan.AuthenticationProvider]::Devolutions)
        }
        finally {
            Set-PSWSManAuth -AuthProvider System
        }

        $actual = Get-PSWSManAuth
        $actual.DefaultAuthProvider | Should -Be ([PSWSMan.AuthenticationProvider]::System)
    }

    It "Fails to set the default auth provider to Default" {
        $out = Set-PSWSManAuth -AuthProvider Default -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*AuthProvider cannot be set to Default, must be System or Devolutions*'
    }

    It "Sets a custom GSSAPI library" -Skip:(-not $GssapiLib) {
        Set-PSWSManAuth -GssapiLib $GssapiLib
        try {
            $actual = Get-PSWSManAuth
            $actual.GssapiLib | Should -Be $GssapiLib
        }
        finally {
            Set-PSWSManAuth -GssapiLib Default
        }

        $actual = Get-PSWSManAuth
        $actual.GssapiLib | Should -Be 'Default'
    }

    It "Normalises the GSSAPI library Default value <Value>" -Skip:(-not $GssapiLib) -TestCases @(
        @{ Value = 'default' }
        @{ Value = 'DEFAULT' }
    ) {
        param ($Value)

        Set-PSWSManAuth -GssapiLib $Value
        $actual = Get-PSWSManAuth
        $actual.GssapiLib | Should -BeExactly 'Default'
    }

    It "Fails to set a GSSAPI library that cannot be loaded" -Skip:$IsWindows {
        $missing = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'PSWSManMissing', 'libgssapi.so')
        $out = Set-PSWSManAuth -GssapiLib $missing -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*Failed to load GSSAPI library '$missing': *"
        [string]$err[0] | Should -BeLike "*no such file*"
        $err[0].FullyQualifiedErrorId | Should -BeLike 'GssapiLibNotAvailable,*'

        $actual = Get-PSWSManAuth
        $actual.GssapiLib | Should -Be 'Default'
    }

    It "Reports the loader reason for a file that is not a library" -Skip:$IsWindows {
        $notALib = Join-Path $TestDrive 'libnotalib.so'
        Set-Content -LiteralPath $notALib -Value 'not a shared library'

        $out = Set-PSWSManAuth -GssapiLib $notALib -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        # The loader wording differs per platform, macOS dyld lists every
        # path it tried, so only check a reason follows the library name.
        $prefix = "Failed to load GSSAPI library '$notALib': "
        [string]$err[0] | Should -BeLike "${prefix}?*"
    }

    It "Reports the missing export for a library that is not GSSAPI" -Skip:$IsWindows {
        # Every host has a C library, which loads fine but has no gss_ exports.
        $notGssapi = if ($IsMacOS) { '/usr/lib/libSystem.B.dylib' } else { 'libc.so.6' }

        $out = Set-PSWSManAuth -GssapiLib $notGssapi -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*GSSAPI library '$notGssapi' is missing a required export: *gss_*"

        $actual = Get-PSWSManAuth
        $actual.GssapiLib | Should -Be 'Default'
    }

    It "Changes nothing when any requested setting is invalid" -Skip:$IsWindows {
        $missing = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'PSWSManMissing', 'libgssapi.so')
        $out = Set-PSWSManAuth -AuthProvider Devolutions -GssapiLib $missing -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1

        $actual = Get-PSWSManAuth
        $actual.DefaultAuthProvider | Should -Be ([PSWSMan.AuthenticationProvider]::System)
        $actual.GssapiLib | Should -Be 'Default'
    }

    It "Fails to set the GSSAPI library on Windows" -Skip:(-not $IsWindows) {
        $out = Set-PSWSManAuth -GssapiLib Default -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*GssapiLib cannot be set on Windows, SSPI is always used*'
        $err[0].FullyQualifiedErrorId | Should -BeLike 'GssapiLibNotSupported,*'

        $actual = Get-PSWSManAuth
        $actual.GssapiLib | Should -Be 'Default'
    }

    It "Fails to set the System provider when no GSSAPI library is available" -Skip:$SystemAvailable {
        $out = Set-PSWSManAuth -AuthProvider System -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike '*Failed to find a system GSSAPI library*'
    }

    It "Uses the default settings when opened from a thread with no runspace" {
        # A host can open a runspace from a thread pool thread where
        # Runspace.DefaultRunspace is null. The settings lookup must fall
        # back to the defaults so the open reaches the transport and fails on
        # the closed port rather than on the lookup.
        if (-not ('PSWSManTest.BackgroundOpen' -as [type])) {
            Add-Type -ReferencedAssemblies System.Management.Automation -TypeDefinition @'
using System;
using System.Management.Automation.Runspaces;
using System.Threading.Tasks;

namespace PSWSManTest;

public static class BackgroundOpen
{
    public static Exception Run(WSManConnectionInfo connInfo)
    {
        return Task.Run(() =>
        {
            try
            {
                using Runspace rs = RunspaceFactory.CreateRunspace(connInfo);
                rs.Open();
                return null;
            }
            catch (Exception e)
            {
                return e;
            }
        }).GetAwaiter().GetResult();
    }
}
'@
        }

        $cred = [PSCredential]::new('user', (ConvertTo-SecureString -AsPlainText -Force 'pass'))
        $connInfo = [System.Management.Automation.Runspaces.WSManConnectionInfo]::new(
            $false, 'localhost', 1, '/wsman', 'http://schemas.microsoft.com/powershell/Microsoft.PowerShell', $cred)
        $connInfo.AuthenticationMechanism = 'Negotiate'
        $connInfo.OpenTimeout = 5000

        $err = [PSWSManTest.BackgroundOpen]::Run($connInfo)
        $err | Should -Not -BeNullOrEmpty
        $err | Should -BeOfType ([System.Management.Automation.Remoting.PSRemotingTransportException])
    }
}
