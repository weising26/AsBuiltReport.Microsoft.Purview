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
    $script:HealthCheck   = $ReportConfig.HealthCheck
    $script:TextInfo      = (Get-Culture).TextInfo
    $script:SectionTimers = [System.Collections.Generic.Dictionary[string,object]]::new()

    # Transcript log — enabled when Options.TranscriptPath is set in the report config JSON.
    # Generates a timestamped log file capturing all INFO/SUCCESS/WARNING/ERROR events
    # plus PScribo document warnings, useful for troubleshooting without needing to
    # copy/paste console output.
    if ($script:Options.TranscriptPath -and $script:Options.TranscriptPath.Trim() -ne '') {
        # Expand the path and create the directory if needed
        $script:TranscriptLogPath = $script:Options.TranscriptPath.Trim()
        $logDir = Split-Path $script:TranscriptLogPath -Parent
        if ($logDir -and -not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        # Write a header so it's clear when the session started
        $header = @"
================================================================================
  AsBuiltReport.Microsoft.Purview — Diagnostic Transcript
  Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Host    : $($env:COMPUTERNAME)
  User    : $($env:USERNAME)
================================================================================
"@
        Set-Content -Path $script:TranscriptLogPath -Value $header -Encoding UTF8
        Write-Host "  - Transcript log: $script:TranscriptLogPath" -ForegroundColor Cyan

        # Hook into PScribo's Write-PScriboMessage so WARNING lines from the
        # document renderer (including "Unexpected System.Boolean" and other
        # internal errors) are captured to the log file automatically.
        # PScribo writes warnings via Write-Warning, so we redirect the
        # WarningVariable stream at the Section/Table level isn't practical —
        # instead we register a custom warning handler using Set-PSDebug isn't right either.
        # The most reliable approach: wrap the entire report generation in a
        # transcript using Start-Transcript which captures everything including warnings.
        try {
            Start-Transcript -Path ($script:TranscriptLogPath -replace '\.log$', '_console.log') `
                -Append -Force -ErrorAction SilentlyContinue | Out-Null
            $script:TranscriptStarted = $true
        } catch {
            $script:TranscriptStarted = $false
        }
    } else {
        $script:TranscriptLogPath  = $null
        $script:TranscriptStarted  = $false
    }

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
        if ($script:Options.UserPrincipalName -and (Test-UserPrincipalName -UserPrincipalName $script:Options.UserPrincipalName)) {
            $ResolvedUPN = $script:Options.UserPrincipalName
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

                # Map ISO country code -> MCCA geo tags for DLP gap analysis
                $script:TenantCountry = $TenantInfo.CountryLetterCode  # e.g. 'AU', 'US', 'GB'
                $script:TenantGeos    = @('INTL')  # INTL always included
                $countryToGeo = @{
                    # Asia-Pacific
                    'AU'='AUS'; 'NZ'='AUS'
                    'JP'='JPN'
                    'CN'='APC'; 'HK'='APC'; 'SG'='APC'; 'MY'='APC'; 'PH'='APC'
                    'TW'='APC'; 'TH'='APC'; 'TR'='APC'; 'IL'='APC'; 'SA'='APC'; 'ID'='APC'
                    'KR'='KOR'
                    'IN'='IND'
                    'ZA'='ZAF'
                    # North America
                    'US'='NAM'; 'CA'='CAN'; 'MX'='NAM'
                    # UK
                    'GB'='GBR'
                    # Latin America
                    'BR'='LAM'; 'AR'='LAM'; 'CL'='LAM'; 'CO'='LAM'; 'PE'='LAM'
                    # Europe (all EU/EEA + associated countries)
                    'AT'='EUR'; 'BE'='EUR'; 'BG'='EUR'; 'HR'='EUR'; 'CY'='EUR'
                    'CZ'='EUR'; 'DK'='EUR'; 'EE'='EUR'; 'FI'='EUR'; 'FR'='FRA'
                    'DE'='EUR'; 'GR'='EUR'; 'HU'='EUR'; 'IE'='EUR'; 'IT'='EUR'
                    'LV'='EUR'; 'LT'='EUR'; 'LU'='EUR'; 'MT'='EUR'; 'NL'='EUR'
                    'NO'='EUR'; 'PL'='EUR'; 'PT'='EUR'; 'RO'='EUR'; 'SK'='EUR'
                    'SI'='EUR'; 'ES'='EUR'; 'SE'='EUR'; 'CH'='EUR'; 'UA'='EUR'
                    'RU'='EUR'
                }
                if ($script:TenantCountry -and $countryToGeo.ContainsKey($script:TenantCountry)) {
                    $script:TenantGeos += $countryToGeo[$script:TenantCountry]
                    # France also includes EUR
                    if ($countryToGeo[$script:TenantCountry] -eq 'FRA') { $script:TenantGeos += 'EUR' }
                    # GBR also includes EUR (shared EU SITs)
                    if ($countryToGeo[$script:TenantCountry] -eq 'GBR') { $script:TenantGeos += 'EUR' }
                    # CAN also includes NAM
                    if ($countryToGeo[$script:TenantCountry] -eq 'CAN') { $script:TenantGeos += 'NAM' }
                } else {
                    # Unknown country — include all geos so nothing is missed
                    $script:TenantGeos += 'NAM','AUS','EUR','FRA','GBR','APC','JPN','CAN','IND','KOR','LAM','ZAF'
                }
                $script:TenantGeos = $script:TenantGeos | Sort-Object -Unique
                Write-Host "  - Tenant country: $($script:TenantCountry) → DLP geos: $($script:TenantGeos -join ', ')" -ForegroundColor Gray
                Write-TranscriptLog "Tenant country: $($script:TenantCountry), DLP geos: $($script:TenantGeos -join ', ')" 'INFO' 'MAIN' | Out-Null
            } else {
                # Fall back to Get-MgContext which is always safe — no sub-module needed
                $MgCtx = Get-MgContext -ErrorAction SilentlyContinue
                $script:TenantId    = if ($MgCtx) { $MgCtx.TenantId } else { $System }
                $script:TenantName  = $System
                $script:TenantCountry = $null
                # Without country, include the most common geos to avoid empty DLP tables
                $script:TenantGeos  = @('INTL','NAM','AUS','EUR','FRA','GBR','APC','JPN','CAN')
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
        #                       Pre-flight: Role & License Check (MCCA-inspired)                     #
        #---------------------------------------------------------------------------------------------#
        # Checks Entra roles and licensing before generating the report.
        # Warns if sections will have limited data. Does NOT block report generation.
        # Role requirements sourced from MCCA (github.com/OfficeDev/MCCA) role table.
        Write-Host '  - Checking user roles and licensing...'
        try {
            $script:RoleWarnings   = [System.Collections.ArrayList]::new()
            $script:LicenseWarnings = [System.Collections.ArrayList]::new()
            $script:DetectedRoles  = @()
            $script:HasE5License   = $false

            # Get Entra roles for current user via Graph
            $MgCtxAccount = (Get-MgContext -ErrorAction SilentlyContinue).Account
            if ($MgCtxAccount) {
                $RoleResp = Invoke-MgGraphRequest `
                    -Uri "https://graph.microsoft.com/v1.0/users/$MgCtxAccount/transitiveMemberOf/microsoft.graph.directoryRole" `
                    -Method GET -ErrorAction SilentlyContinue -SkipHttpErrorCheck
                if ($RoleResp -and -not $RoleResp.error -and $RoleResp.value) {
                    $script:DetectedRoles = $RoleResp.value.displayName
                }
            }

            # Role tier assessment (from MCCA role table)
            $FullAccessRoles  = @('Global Administrator','Compliance Administrator','Compliance Data Administrator')
            $PartialRoles     = @('Security Administrator','Security Reader','Security Operator','Global Reader')
            $HasFullAccess    = ($script:DetectedRoles | Where-Object { $FullAccessRoles -contains $_ }).Count -gt 0
            $HasPartialAccess = ($script:DetectedRoles | Where-Object { $PartialRoles    -contains $_ }).Count -gt 0

            if ($script:DetectedRoles.Count -gt 0) {
                Write-Host "    Detected roles: $($script:DetectedRoles -join ', ')" -ForegroundColor Gray
                Write-TranscriptLog "Detected Entra roles: $($script:DetectedRoles -join ', ')" 'INFO' 'PREFLIGHT' | Out-Null
                if (-not $HasFullAccess -and -not $HasPartialAccess) {
                    $msg = "No recognised compliance role detected. Some sections may be empty. Recommended: Compliance Administrator or Global Administrator."
                    Write-Host "    WARNING: $msg" -ForegroundColor Yellow
                    Write-TranscriptLog $msg 'WARNING' 'PREFLIGHT' | Out-Null
                    $null = $script:RoleWarnings.Add($msg)
                } elseif (-not $HasFullAccess) {
                    $msg = "Partial-access role detected. Insider Risk, Communication Compliance and eDiscovery case details may be limited. Full access requires Compliance Administrator."
                    Write-Host "    NOTE: $msg" -ForegroundColor Yellow
                    Write-TranscriptLog $msg 'WARNING' 'PREFLIGHT' | Out-Null
                    $null = $script:RoleWarnings.Add($msg)
                } else {
                    Write-Host "    Role check: OK ($( ($script:DetectedRoles | Where-Object { $FullAccessRoles -contains $_ }) -join ', '))" -ForegroundColor Green
                    Write-TranscriptLog "Role check passed." 'SUCCESS' 'PREFLIGHT' | Out-Null
                }
            } else {
                Write-Host "    Could not retrieve role assignments." -ForegroundColor Gray
            }

            # License check via Graph
            $SkuResp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/subscribedSkus" `
                -Method GET -ErrorAction SilentlyContinue -SkipHttpErrorCheck
            if ($SkuResp -and -not $SkuResp.error -and $SkuResp.value) {
                $Skus = $SkuResp.value
                $E5Skus = $Skus | Where-Object {
                    $_.skuPartNumber -match 'SPE_E5|COMPLIANCE_E5|M365_E5|ENTERPRISEPREMIUM|Microsoft_365_E5'
                }
                $script:HasE5License = $E5Skus.Count -gt 0
                if ($script:HasE5License) {
                    Write-Host "    License check: E5 detected — all sections available." -ForegroundColor Green
                    Write-TranscriptLog "E5 license confirmed: $($E5Skus.skuPartNumber -join ', ')" 'SUCCESS' 'PREFLIGHT' | Out-Null
                } else {
                    $E3Skus = $Skus | Where-Object { $_.skuPartNumber -match 'SPE_E3|ENTERPRISEPACK|Microsoft_365_E3' }
                    $licMsg = if ($E3Skus) {
                        "E3 license detected ($($E3Skus.skuPartNumber -join ', ')). Insider Risk Management, Communication Compliance and Advanced eDiscovery require E5 or M365 E5 Compliance add-on."
                    } else {
                        "License tier unknown. Insider Risk, Communication Compliance and Advanced eDiscovery may require E5 or E5 Compliance add-on."
                    }
                    Write-Host "    NOTE: $licMsg" -ForegroundColor Yellow
                    Write-TranscriptLog $licMsg 'WARNING' 'PREFLIGHT' | Out-Null
                    $null = $script:LicenseWarnings.Add($licMsg)
                }
            }
        } catch {
            Write-TranscriptLog "Pre-flight check skipped (non-fatal): $($_.Exception.Message)" 'WARNING' 'PREFLIGHT' | Out-Null
        }

        #---------------------------------------------------------------------------------------------#
        #                                     Report Sections                                         #
        #---------------------------------------------------------------------------------------------#

        # Determine report mode from Options
        $ReportType = if ($script:Options.ReportType) { $script:Options.ReportType.Trim() } else { 'AsBuilt' }
        Write-Host "  - Report type: $ReportType" -ForegroundColor Cyan
        Write-TranscriptLog "Report type: $ReportType" 'INFO' 'MAIN' | Out-Null
        
        if ($ReportType -ne 'Assessment') {

            #------------------------------------------------------------------#
            #  ASBUILT MODE — Standard documentation sections                  #
            #------------------------------------------------------------------#

            if ($script:InfoLevel.InformationProtection -ge 1 -or $script:InfoLevel.DLP -ge 1) {
                Write-Host '- Working on Information Protection section.'
                Get-AbrPurviewInformationProtectionSection -TenantId $script:TenantName
            }
            if ($script:InfoLevel.Retention -ge 1 -or $script:InfoLevel.RecordManagement -ge 1) {
                Write-Host '- Working on Data Lifecycle Management section.'
                Get-AbrPurviewDataLifecycleSection -TenantId $script:TenantName
            }
            if ($script:InfoLevel.EDiscovery -ge 1) {
                Write-Host '- Working on eDiscovery section.'
                Get-AbrPurviewEDiscoverySection -TenantId $script:TenantName
            }
            if ($script:InfoLevel.Audit -ge 1) {
                Write-Host '- Working on Audit section.'
                Get-AbrPurviewAuditSection -TenantId $script:TenantName
            }
            if ($script:InfoLevel.InsiderRisk -ge 1 -or $script:InfoLevel.CommunicationCompliance -ge 1 -or $script:InfoLevel.ComplianceManager -ge 1) {
                Write-Host '- Working on Risk and Compliance section.'
                Get-AbrPurviewRiskAndComplianceSection -TenantId $script:TenantName
            }

        } # end AsBuilt sections

        if ($ReportType -eq 'Assessment' -or $ReportType -eq 'Both') {

            #------------------------------------------------------------------#
            #  ASSESSMENT MODE — Purview Optimization Assessment (POA)         #
            #------------------------------------------------------------------#
            Write-Host '- Working on Purview Optimization Assessment section.'
            Get-AbrPurviewAssessment -TenantId $script:TenantName

        } # end Assessment section

        #---------------------------------------------------------------------------------------------#
        #                              Clean Up Connections                                           #
        #---------------------------------------------------------------------------------------------#
        Write-Host " "
        Write-Host "- Finished report generation for tenant: $($script:TenantName)"
        Write-TranscriptLog "Report generation complete for: $($script:TenantName)" 'SUCCESS' 'MAIN' | Out-Null

        if ($script:Options.KeepConnected -eq $true) {
            Write-Host '  - KeepConnected: skipping session disconnect.' -ForegroundColor Yellow
            Write-TranscriptLog 'KeepConnected is set — sessions left open.' 'INFO' 'MAIN' | Out-Null
        } else {
            Disconnect-PurviewSession
        }

    } #endregion foreach Target loop

    # Stop transcript if we started one
    if ($script:TranscriptStarted) {
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Host "  - Transcript saved to: $($script:Options.TranscriptPath -replace '\.log$', '_console.log')" -ForegroundColor Cyan
    }
}
