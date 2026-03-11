function Invoke-AsBuiltReport.Microsoft.Purview {
    <#
    .SYNOPSIS
        PowerShell script to document the configuration of Microsoft Purview
        in Word/HTML/Text formats.
    .DESCRIPTION
        Documents the configuration of Microsoft Purview compliance services
        in Word/HTML/Text formats using PScribo.

        Covers:
          - Information Protection (Sensitivity Labels, DLP)
          - Data Lifecycle Management (Retention Policies & Labels)
          - eDiscovery (Cases, Holds, Content Searches)
          - Audit (Log Config, Retention Policies)
          - Risk & Compliance (Insider Risk, Communication Compliance, Compliance Manager)

    .NOTES
        Version:        0.1.0
        Author:         Pai Wei Sing
        Twitter:        @paiwsing
        Github:         paiwsing

    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.Purview

    .PARAMETER Target
        Specifies the Microsoft 365 tenant domain name (e.g. contoso.onmicrosoft.com).

    .PARAMETER Credential
        Optional PSCredential. The username is used as the UPN if
        Options.UserPrincipalName is not set in the report config JSON.
    #>

    param (
        [String[]] $Target,
        [PSCredential] $Credential
    )

    Write-ReportModuleInfo -ModuleName 'Microsoft.Purview'

    #---------------------------------------------------------------------------------------------#
    #                            Dependency Module Version Check                                  #
    #---------------------------------------------------------------------------------------------#
    $ModuleArray = @('AsBuiltReport.Core', 'ExchangeOnlineManagement', 'Microsoft.Graph')

    foreach ($Module in $ModuleArray) {
        try {
            $InstalledVersion = Get-Module -ListAvailable -Name $Module -ErrorAction SilentlyContinue |
                Sort-Object -Property Version -Descending |
                Select-Object -First 1 -ExpandProperty Version

            if ($InstalledVersion) {
                Write-Host "  - $Module module v$($InstalledVersion.ToString()) is currently installed."

                # Only check for newer versions if PowerShellGet is available (requires internet)
                $PSGetAvailable = Get-Module -ListAvailable -Name PowerShellGet -ErrorAction SilentlyContinue
                if ($PSGetAvailable) {
                    try {
                        Import-Module PowerShellGet -ErrorAction SilentlyContinue
                        $LatestVersion = Find-Module -Name $Module -Repository PSGallery -ErrorAction SilentlyContinue |
                            Select-Object -ExpandProperty Version
                        if ($LatestVersion -and $InstalledVersion -lt $LatestVersion) {
                            Write-Host "    - $Module module v$($LatestVersion.ToString()) is available." -ForegroundColor Red
                            Write-Host "    - Run 'Update-Module -Name $Module -Force' to install the latest version." -ForegroundColor Red
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "Unable to check latest version for $Module`: $($_.Exception.Message)"
                    }
                } else {
                    Write-Host "  - Skipping update check for $Module (PowerShellGet not available)."
                }
            } else {
                Write-Host "  - $Module module is NOT installed. Run 'Install-Module -Name $Module -Force'." -ForegroundColor Red
            }
        } catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
    }

    #---------------------------------------------------------------------------------------------#
    #                               Import Report Configuration                                   #
    #---------------------------------------------------------------------------------------------#
    #---------------------------------------------------------------------------------------------#
    #                  Report Config Patch (must run before $script:Report assignment)            #
    #---------------------------------------------------------------------------------------------#
    # Patch $ReportConfig in-place before $script:Report is assigned.
    # 1. Set correct report name based on ReportType
    # 2. Set CoverPageImage to the Purview logo bundled with this module
    #    ($PSScriptRoot = .../Src/Public — logo lives there)
    $EarlyReportType = if ($ReportConfig.Options.ReportType) { $ReportConfig.Options.ReportType.Trim() } else { 'AsBuilt' }
    if ($EarlyReportType -eq 'Assessment') {
        $ReportConfig.Report.Name = 'Microsoft Purview Optimization Assessment Report'
    } elseif ($EarlyReportType -eq 'Both') {
        $ReportConfig.Report.Name = 'Microsoft Purview As Built Report with Assessment'
    } else {
        $ReportConfig.Report.Name = 'Microsoft Purview As Built Report'
    }

    # Always point the cover image to our bundled Purview logo PNG
    $script:PurviewLogoPath = Join-Path $PSScriptRoot 'AsBuiltReport.Microsoft.Purview.png'
    if (Test-Path $script:PurviewLogoPath) {
        $ImageBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($script:PurviewLogoPath ))
        Image -Text 'Microsoft Purview As Built Report' -Align Left -Percent 50 -Base64 $ImageBase64
        Write-Host "  - Cover page logo set: $script:PurviewLogoPath" -ForegroundColor Cyan
    } else {
        Write-Warning "Cover page logo not found at: $script:PurviewLogoPath"
    }
    

    $script:Report        = $ReportConfig.Report
    $script:InfoLevel     = $ReportConfig.InfoLevel
    $script:Options       = $ReportConfig.Options
    $script:TextInfo      = (Get-Culture).TextInfo
    $script:SectionTimers = [System.Collections.Generic.Dictionary[string,object]]::new()

    # Optional: enable transcript log file output
    # $script:TranscriptLogPath = "C:\Reports\PurviewReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

    #---------------------------------------------------------------------------------------------#
    #                                   Disclaimer (HealthCheck)                                  #
    #---------------------------------------------------------------------------------------------#
    if ($Healthcheck) {
        Section -Style TOC -ExcludeFromTOC 'DISCLAIMER' {
            Paragraph 'This report was generated using the AsBuiltReport framework and provides a snapshot of the current Microsoft Purview configuration at the time of generation. The information in this report is intended for documentation and reference purposes. Any configuration settings should be reviewed and validated by a qualified administrator before making changes.'
        }
        PageBreak
    }

    #---------------------------------------------------------------------------------------------#
    #                                    Connection Section                                       #
    #---------------------------------------------------------------------------------------------#
    foreach ($System in $Target) {

        Write-Host " "
        Write-Host "- Starting report for tenant: $System"
        Write-TranscriptLog "Starting Purview report for tenant: $System" 'INFO' 'MAIN' | Out-Null

        #region Resolve UPN
        $ResolvedUPN = $null
        if ($Options.UserPrincipalName -and (Test-UserPrincipalName -UserPrincipalName $Options.UserPrincipalName)) {
            $ResolvedUPN = $Options.UserPrincipalName
        } elseif ($Credential -and (Test-UserPrincipalName -UserPrincipalName $Credential.UserName)) {
            $ResolvedUPN = $Credential.UserName
        } else {
            throw "No valid UserPrincipalName found. Set 'Options.UserPrincipalName' in your report config JSON (e.g. admin@$System), or pass -Credential with a UPN-format username."
        }
        Write-TranscriptLog "Using UPN: $ResolvedUPN" 'INFO' 'AUTH' | Out-Null
        #endregion

        #region Connect
        try {
            Connect-PurviewSession -UserPrincipalName $ResolvedUPN
        } catch {
            throw "Connection failed for tenant '$System'. Error: $($_.Exception.Message)"
        }
        #endregion

        #region Retrieve Tenant Info
        Write-Host "  - Retrieving tenant information..."
        try {
            # Try Get-MgOrganization only if the sub-module is already loaded
            # to avoid assembly conflicts from re-importing it
            if (Get-Module -Name 'Microsoft.Graph.Identity.DirectoryManagement' -ErrorAction SilentlyContinue) {
                $script:TenantInfo = Get-MgOrganization -ErrorAction Stop
                $script:TenantId   = $TenantInfo.Id
                $script:TenantName = ($TenantInfo.VerifiedDomains | Where-Object { $_.IsDefault }).Name
            } else {
                # Fall back to Get-MgContext which is always safe — no sub-module needed
                $MgCtx = Get-MgContext -ErrorAction SilentlyContinue
                $script:TenantId   = if ($MgCtx) { $MgCtx.TenantId } else { $System }
                $script:TenantName = $System
            }
            Write-Host "  - Tenant: $($script:TenantName) ($($script:TenantId))" -ForegroundColor Cyan
            Write-TranscriptLog "Tenant identified: $($script:TenantName) ($($script:TenantId))" 'INFO' 'MAIN' | Out-Null
        } catch {
            $script:TenantId   = $System
            $script:TenantName = $System
            Write-TranscriptLog "Unable to retrieve tenant info from Graph. Using '$System' as identifier." 'WARNING' 'MAIN' | Out-Null
        }
        #endregion

        #---------------------------------------------------------------------------------------------#
        #                                     Report Sections                                         #
        #---------------------------------------------------------------------------------------------#

        # Determine report mode from Options
        $ReportType = if ($Options.ReportType) { $Options.ReportType.Trim() } else { 'AsBuilt' }
        Write-Host "  - Report type: $ReportType" -ForegroundColor Cyan
        Write-TranscriptLog "Report type: $ReportType" 'INFO' 'MAIN' | Out-Null
        
        if ($ReportType -ne 'Assessment') {

            #------------------------------------------------------------------#
            #  ASBUILT MODE — Standard documentation sections                  #
            #------------------------------------------------------------------#

            if ($InfoLevel.InformationProtection -ge 1 -or $InfoLevel.DLP -ge 1) {
                Write-Host '- Working on Information Protection section.'
                Get-AbrPurviewInformationProtectionSection -TenantId $script:TenantName
            }
            if ($InfoLevel.Retention -ge 1) {
                Write-Host '- Working on Data Lifecycle Management section.'
                Get-AbrPurviewDataLifecycleSection -TenantId $script:TenantName
            }
            if ($InfoLevel.EDiscovery -ge 1) {
                Write-Host '- Working on eDiscovery section.'
                Get-AbrPurviewEDiscoverySection -TenantId $script:TenantName
            }
            if ($InfoLevel.Audit -ge 1) {
                Write-Host '- Working on Audit section.'
                Get-AbrPurviewAuditSection -TenantId $script:TenantName
            }
            if ($InfoLevel.InsiderRisk -ge 1 -or $InfoLevel.CommunicationCompliance -ge 1 -or $InfoLevel.ComplianceManager -ge 1) {
                Write-Host '- Working on Risk and Compliance section.'
                Get-AbrPurviewRiskAndComplianceSection -TenantId $script:TenantName
            }

        if ($ReportType -eq 'Assessment' -or $ReportType -eq 'Both') {

            #------------------------------------------------------------------#
            #  ASSESSMENT MODE — Purview Optimization Assessment (POA)         #
            #------------------------------------------------------------------#
            Write-Host '- Working on Purview Optimization Assessment section.'
            Get-AbrPurviewAssessment -TenantId $script:TenantName
        }

        
        } # end ReportType branch

        #---------------------------------------------------------------------------------------------#
        #                              Clean Up Connections                                           #
        #---------------------------------------------------------------------------------------------#
        Write-Host " "
        Write-Host "- Finished report generation for tenant: $($script:TenantName)"
        Write-TranscriptLog "Report generation complete for: $($script:TenantName)" 'SUCCESS' 'MAIN' | Out-Null

        Disconnect-PurviewSession

    } #endregion foreach Target loop
}
