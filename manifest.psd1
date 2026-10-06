@{
    InvokeBuildVersion = '5.14.23'
    PesterVersion = '6.2.0'
    BuildRequirements = @(
        @{
            ModuleName = 'Microsoft.PowerShell.PSResourceGet'
            ModuleVersion = '1.2.0'
        }
        @{
            ModuleName = 'OpenAuthenticode'
            RequiredVersion = '0.6.3'
        }
        @{
            ModuleName = 'Microsoft.PowerShell.PlatyPS'
            RequiredVersion = '1.0.3'
        }
    )
    TestRequirements = @(
        # The KDC for the Kerberos authentication unit tests, see
        # Invoke-WithTestKdc in tools/common.ps1. It needs PowerShell 7.6, an
        # older build host skips it and those tests skip.
        @{
            ModuleName = 'Obol'
            RequiredVersion = '0.1.0'
            PowerShellVersion = '7.6'
        }
    )
    # Installed into a virtual environment under output/python-venv by the
    # Test task. The authentication unit tests skip when it is unavailable.
    # The kerberos extra is python-gssapi for the Linux and macOS acceptor,
    # it adds nothing on Windows where pyspnego uses SSPI.
    PythonRequirements = @(
        'pyspnego[kerberos]==0.12.4'
    )
}
