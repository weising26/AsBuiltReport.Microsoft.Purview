#
# Module manifest for AsBuiltReport.Microsoft.Purview
#
@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'AsBuiltReport.Microsoft.Purview.psm1'

    # Version number of this module.
    ModuleVersion     = '0.1.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID              = 'a3f1c2d4-5e6b-7f8a-9b0c-1d2e3f4a5b6c'

    # Author of this module
    Author            = 'Pai Wei Sing'

    # Company or vendor of this module
    CompanyName       = 'Logicalis Australia'

    # Copyright statement for this module
    Copyright         = '(c) 2026 Pai Wei Sing. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'An AsBuiltReport module used to document Microsoft Purview compliance configuration.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules left empty — dependency checks are handled at runtime in the invoke function
    RequiredModules   = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'Invoke-AsBuiltReport.Microsoft.Purview'
    )

    # Cmdlets to export from this module
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport   = @()

    # Private data to pass to the module specified in RootModule
    PrivateData       = @{
        PSData = @{
            # Tags applied to this module for discoverability
            Tags         = @('AsBuiltReport', 'Microsoft', 'Purview', 'Compliance', 'Documentation', 'Report')

            # A URL to the license for this module
            LicenseUri   = 'https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.Purview/blob/master/LICENSE'

            # A URL to the main website for this project
            ProjectUri   = 'https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.Purview'

            # ReleaseNotes of this module
            ReleaseNotes = 'https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.Purview/blob/master/CHANGELOG.md'
        }
    }
}
