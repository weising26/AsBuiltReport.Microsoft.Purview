#region --- Section Orchestrators ---
# These functions group related Get-AbrPurview* calls into top-level report sections,
# mirroring the pattern used in AsBuiltReport.Microsoft.AD (e.g. Get-AbrForestSection).

function Get-AbrPurviewInformationProtectionSection {
    <#
    .SYNOPSIS
    Orchestrates the Information Protection section of the Purview As Built Report.
    .DESCRIPTION
        Calls Sensitivity Label and DLP sub-functions to build the
        Information Protection section of the report.
    .NOTES
        Version:        0.1.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TenantId
    )

    Section -Style Heading2 'Information Protection' {
        Paragraph "The following section provides a summary of the Information Protection configuration for tenant $TenantId."
        BlankLine

        if ($script:InfoLevel.InformationProtection -ge 1) {
            Write-Host '    - Working on Sensitivity Labels sub-section.'
            Get-AbrPurviewSensitivityLabel -TenantId $TenantId
        }

        if ($script:InfoLevel.DLP -ge 1) {
            Write-Host '    - Working on DLP Policies sub-section.'
            Get-AbrPurviewDLPPolicy -TenantId $TenantId
        }
    }
}

function Get-AbrPurviewDataLifecycleSection {
    <#
    .SYNOPSIS
    Orchestrates the Data Lifecycle Management section of the Purview As Built Report.
    .DESCRIPTION
        Calls Retention Policy sub-functions to build the
        Data Lifecycle Management section of the report.
    .NOTES
        Version:        0.1.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TenantId
    )

    Section -Style Heading2 'Data Lifecycle Management' {
        Paragraph "The following section provides a summary of the Data Lifecycle Management configuration for tenant $TenantId."
        BlankLine

        if ($script:InfoLevel.Retention -ge 1) {
            Write-Host '    - Working on Retention Policies sub-section.'
            Get-AbrPurviewRetentionPolicy -TenantId $TenantId
        }

        if ($script:InfoLevel.RecordManagement -ge 1) {
            Write-Host '    - Working on Records Management sub-section.'
            Get-AbrPurviewRecordManagement -TenantId $TenantId
        }
    }
}

function Get-AbrPurviewRiskAndComplianceSection {
    <#
    .SYNOPSIS
    Orchestrates the Risk & Compliance section of the Purview As Built Report.
    .DESCRIPTION
        Calls Insider Risk, Communication Compliance, and Compliance Manager
        sub-functions to build the Risk & Compliance section of the report.
    .NOTES
        Version:        0.1.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TenantId
    )

    Section -Style Heading2 'Risk and Compliance' {
        Paragraph "The following section provides a summary of the Risk and Compliance configuration for tenant $TenantId."
        BlankLine

        if ($script:InfoLevel.InsiderRisk -ge 1) {
            Write-Host '    - Working on Insider Risk Management sub-section.'
            Get-AbrPurviewInsiderRisk -TenantId $TenantId
        }

        if ($script:InfoLevel.CommunicationCompliance -ge 1) {
            Write-Host '    - Working on Communication Compliance sub-section.'
            Get-AbrPurviewCommunicationCompliance -TenantId $TenantId
        }

        if ($script:InfoLevel.ComplianceManager -ge 1) {
            Write-Host '    - Working on Compliance Manager sub-section.'
            Get-AbrPurviewComplianceManager -TenantId $TenantId
        }
    }
}

function Get-AbrPurviewAuditSection {
    <#
    .SYNOPSIS
    Orchestrates the Audit section of the Purview As Built Report.
    .DESCRIPTION
        Calls Audit Policy sub-functions to build the Audit section of the report.
    .NOTES
        Version:        0.1.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TenantId
    )

    Section -Style Heading2 'Audit' {
        Paragraph "The following section provides a summary of the Audit configuration for tenant $TenantId."
        BlankLine

        if ($script:InfoLevel.Audit -ge 1) {
            Write-Host '    - Working on Audit Policies sub-section.'
            Get-AbrPurviewAuditPolicy -TenantId $TenantId
        }
    }
}

function Get-AbrPurviewEDiscoverySection {
    <#
    .SYNOPSIS
    Orchestrates the eDiscovery section of the Purview As Built Report.
    .DESCRIPTION
        Calls eDiscovery sub-functions to build the eDiscovery section of the report.
    .NOTES
        Version:        0.1.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TenantId
    )

    Section -Style Heading2 'eDiscovery' {
        Paragraph "The following section provides a summary of the eDiscovery configuration for tenant $TenantId."
        BlankLine

        if ($script:InfoLevel.EDiscovery -ge 1) {
            Write-Host '    - Working on eDiscovery sub-section.'
            Get-AbrPurviewEDiscovery -TenantId $TenantId
        }
    }
}

#endregion
