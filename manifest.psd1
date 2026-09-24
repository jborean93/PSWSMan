@{
    InvokeBuildVersion = '5.14.23'
    PesterVersion = '5.9.1'
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
            ModuleName = 'platyPS'
            RequiredVersion = '0.14.2'
        }
    )
    TestRequirements = @()
    # Installed into a virtual environment under output/python by the Test
    # task. The authentication unit tests skip when it is unavailable.
    PythonRequirements = @(
        'pyspnego==0.12.2'
    )
}
