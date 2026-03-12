function Get-AbrPurviewACSCAssessment {
    <#
    .SYNOPSIS
    Used by As Built Report to generate an ACSC ISM / Essential Eight compliance
    summary for Microsoft Purview (triggered at InfoLevel 3).
    .DESCRIPTION
        Evaluates the tenant's Purview configuration against the ACSC Information
        Security Manual (ISM) controls and Essential Eight strategies that are
        directly verifiable via Microsoft Purview. Produces a consolidated
        compliance table with ISM control IDs, maturity level tags, and pass/fail
        status based on live configuration data already collected during the
        As Built sections.

        ISM controls covered:
          ISM-0271  Information classified before storage/transmission
          ISM-0272  Labels applied to all information (mandatory labelling)
          ISM-0884  Encryption applied to sensitive information
          ISM-1550  DLP controls preventing unauthorised disclosure
          ISM-0580  Event logging policy implemented (audit log enabled)
          ISM-0585  Sufficient audit detail (mailbox auditing default)
          ISM-1998  Event logs retained >= 12 months
          ISM-1989  Event logs retained >= 7 years (records)
          ISM-0109  Event logs analysed in timely manner (audit alerts)
          ISM-1228  Cyber security events analysed (protection alerts)
          ISM-1511  Backups retained and protected (retention policies)
          ISM-1515  Backups cannot be modified/deleted (Preservation Lock)
          ISM-0854  Legal hold capability (eDiscovery holds)
          PSPF-059  Mandatory labelling enforced (Australian Government)
          PSPF-060  Label downgrade justification required (Australian Government)

        Essential Eight strategies covered:
          E8-Backup-ML1  Regular backups configured for critical data
          E8-Backup-ML2  Backups cannot be modified/deleted (Preservation Lock)

    .NOTES
        Version:        0.1.0
        Author:         Pai Wei Sing
        ISM Reference:  https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism
        E8 Reference:   https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory)]
        [string]$TenantId
    )

    begin {
        Write-PScriboMessage -Message "Running ACSC ISM / Essential Eight assessment for tenant $TenantId." | Out-Null
        Show-AbrDebugExecutionTime -Start -TitleMessage 'ACSC Assessment'
    }

    process {

        Section -Style Heading2 'ACSC ISM / Essential Eight Compliance Summary' {

            Paragraph "The following section evaluates the Microsoft Purview configuration for $TenantId against ACSC Information Security Manual (ISM) controls and Essential Eight strategies that are directly verifiable via Purview. Controls that require process or people evidence outside of Purview are marked as Manual Review Required."
            BlankLine
            Paragraph "ISM Reference: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism"
            BlankLine

            #region ── Data Collection ─────────────────────────────────────────────

            # Sensitivity Labels
            $Labels        = @(try { Get-Label -ErrorAction Stop } catch { @() })
            $LabelPolicies = @(try { Get-LabelPolicy -ErrorAction Stop } catch { @() })
            $AutoLabelPol  = @(try { Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue } catch { @() })

            # DLP
            $DLPPolicies   = @(try { Get-DlpCompliancePolicy -ErrorAction Stop } catch { @() })
            $AllDLPRules   = [System.Collections.ArrayList]::new()
            foreach ($pol in $DLPPolicies) {
                try {
                    $rules = Get-DlpComplianceRule -Policy $pol.Name -ErrorAction SilentlyContinue
                    foreach ($r in $rules) { $AllDLPRules.Add($r) | Out-Null }
                } catch { }
            }

            # Audit
            $AuditConfig      = try { Get-AdminAuditLogConfig -ErrorAction SilentlyContinue } catch { $null }
            $OrgConfig        = try { Get-OrganizationConfig -ErrorAction SilentlyContinue } catch { $null }
            $AuditRetPolicies = @(try { Get-UnifiedAuditLogRetentionPolicy -ErrorAction SilentlyContinue } catch { @() })
            $ProtAlerts       = @(try { Get-ProtectionAlert -ErrorAction SilentlyContinue } catch { @() })

            # Retention
            $RetentionPolicies = @(try { Get-RetentionCompliancePolicy -ErrorAction Stop } catch { @() })

            # eDiscovery
            $AllCases  = @(try { Get-ComplianceCase -CaseType Core     -ErrorAction SilentlyContinue } catch { @() }) +
                         @(try { Get-ComplianceCase -CaseType Advanced  -ErrorAction SilentlyContinue } catch { @() })
            $AllHolds  = [System.Collections.ArrayList]::new()
            foreach ($c in $AllCases) {
                try {
                    $holds = Get-CaseHoldPolicy -Case $c.Name -ErrorAction SilentlyContinue
                    foreach ($h in $holds) { $AllHolds.Add($h) | Out-Null }
                } catch { }
            }

            # Insider Risk (Graph)
            $IRMPolicies = @()
            try {
                $r = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/security/insiderRiskPolicies' -Method GET -ErrorAction Stop
                $IRMPolicies = $r.value
            } catch { }

            #endregion

            #region ── Evaluate Controls ──────────────────────────────────────────

            # Helper: audit retention policy max duration in days
            $MaxAuditRetDays = 90  # Exchange/E3 default
            foreach ($pol in $AuditRetPolicies) {
                $days = switch ($pol.RetentionDuration) {
                    'ThreeMonths'  { 90 }
                    'SixMonths'    { 180 }
                    'NineMonths'   { 270 }
                    'TwelveMonths' { 365 }
                    'TwoYears'     { 730 }
                    'FiveYears'    { 1825 }
                    'SevenYears'   { 2555 }
                    'TenYears'     { 3650 }
                    default        { 0 }
                }
                if ($days -gt $MaxAuditRetDays) { $MaxAuditRetDays = $days }
            }

            # Sensitivity label checks
            $HasLabels            = ($Labels.Count -gt 0)
            $HasEncryptionLabels  = [bool]($Labels | Where-Object { $_.EncryptionEnabled })
            $HasMandatoryLabeling = [bool]($LabelPolicies | Where-Object { $_.RequireSensitivityLabelOnSave })
            $HasDowngradeJust     = [bool]($LabelPolicies | Where-Object { $_.RequireDowngradeJustification })

            # DLP checks
            $HasEnforcedDLP       = [bool]($DLPPolicies | Where-Object { $_.Mode -eq 'Enable' })
            $HasBlockingRules     = [bool]($AllDLPRules  | Where-Object { $_.BlockAccess })

            # Audit checks
            $AuditEnabled         = [bool]($AuditConfig.UnifiedAuditLogIngestionEnabled)
            $MailboxAuditDefault  = ($OrgConfig -and $OrgConfig.AuditDisabled -eq $false)
            $AuditRetention12Mo   = ($MaxAuditRetDays -ge 365)
            $AuditRetention7Yr    = ($MaxAuditRetDays -ge 2555)
            $HasAuditAlerts       = [bool]($ProtAlerts | Where-Object {
                $_.Name -match 'audit|eDiscovery|mailbox|privilege' -and $_.Disabled -eq $false
            })
            $HasCyberAlerts       = [bool]($ProtAlerts | Where-Object { $_.Disabled -eq $false })

            # Retention / backup checks
            $HasRetentionPolicies = ($RetentionPolicies.Count -gt 0)
            $CoversKeyWorkloads   = [bool]($RetentionPolicies | Where-Object {
                ($_.Workload -join ',') -match 'Exchange' -and
                ($_.Workload -join ',') -match 'SharePoint' -and
                ($_.Workload -join ',') -match 'OneDrive'
            })
            $HasPreservationLock  = [bool]($RetentionPolicies | Where-Object { $_.RestrictiveRetention })

            # eDiscovery checks
            $HasActiveHolds       = [bool]($AllHolds | Where-Object { $_.Enabled })

            # Insider Risk
            $HasIRMPolicies       = ($IRMPolicies.Count -gt 0)

            #endregion

            #region ── Build Controls Table ───────────────────────────────────────

            # Status values: Pass | Fail | Partial | Manual
            # Framework tags: ISM | E8-Backup | PSPF

            $Controls = [System.Collections.ArrayList]::new()

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-0271'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'N/A'
                'Description' = 'Information is classified before being stored or transmitted'
                'Purview Check' = 'Sensitivity labels configured and published'
                'Status'      = if ($HasLabels) { 'Pass' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-0272'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'PSPF Req 59'
                'Description' = 'Labels applied to all information (mandatory labelling)'
                'Purview Check' = 'Mandatory labelling enabled in at least one label policy'
                'Status'      = if ($HasMandatoryLabeling) { 'Pass' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-0884'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'N/A'
                'Description' = 'Encryption applied to sensitive/protected information'
                'Purview Check' = 'At least one sensitivity label has encryption enabled'
                'Status'      = if ($HasEncryptionLabels) { 'Pass' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'PSPF-060'
                'Framework'   = 'PSPF'
                'E8 / PSPF'   = 'PSPF Req 60'
                'Description' = 'Label downgrade justification required (Australian Government)'
                'Purview Check' = 'RequireDowngradeJustification enabled in at least one label policy'
                'Status'      = if ($HasDowngradeJust) { 'Pass' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-1550'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'N/A'
                'Description' = 'DLP controls preventing unauthorised disclosure of sensitive data'
                'Purview Check' = 'At least one DLP policy in enforced (Enable) mode'
                'Status'      = if ($HasEnforcedDLP) { 'Pass' } elseif ($DLPPolicies.Count -gt 0) { 'Partial' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-1550'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'N/A'
                'Description' = 'DLP rules actively block access to sensitive content'
                'Purview Check' = 'At least one DLP rule with BlockAccess action'
                'Status'      = if ($HasBlockingRules) { 'Pass' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-0580'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'N/A'
                'Description' = 'Event logging policy implemented and active'
                'Purview Check' = 'Unified Audit Log ingestion enabled'
                'Status'      = if ($AuditEnabled) { 'Pass' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-0585'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'N/A'
                'Description' = 'Sufficient detail recorded in event logs'
                'Purview Check' = 'Mailbox auditing enabled by default for all users'
                'Status'      = if ($MailboxAuditDefault) { 'Pass' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-1998'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'N/A'
                'Description' = 'Event logs retained for at least 12 months'
                'Purview Check' = "Audit retention policy >= 365 days (current max: $MaxAuditRetDays days)"
                'Status'      = if ($AuditRetention12Mo) { 'Pass' } elseif ($AuditEnabled) { 'Fail' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-1989'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'N/A'
                'Description' = 'Event logs retained for at least 7 years (records systems)'
                'Purview Check' = "Audit retention policy >= 2555 days / 7 years (current max: $MaxAuditRetDays days)"
                'Status'      = if ($AuditRetention7Yr) { 'Pass' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-0109'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'E8 ML2, ML3'
                'Description' = 'Event logs analysed in timely manner to detect cyber security events'
                'Purview Check' = 'Active protection alerts configured for audit/eDiscovery/privilege activities'
                'Status'      = if ($HasAuditAlerts) { 'Pass' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-1228'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'E8 ML2, ML3'
                'Description' = 'Cyber security events analysed to identify incidents'
                'Purview Check' = 'Active protection alerts or Insider Risk policies configured'
                'Status'      = if ($HasCyberAlerts -or $HasIRMPolicies) { 'Pass' } elseif ($HasIRMPolicies) { 'Partial' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-1511'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'E8 Backup ML1'
                'Description' = 'Backups of important data retained and restorable'
                'Purview Check' = 'Retention policies covering Exchange, SharePoint, and OneDrive'
                'Status'      = if ($CoversKeyWorkloads) { 'Pass' } elseif ($HasRetentionPolicies) { 'Partial' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-1515'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'E8 Backup ML2'
                'Description' = 'Backups cannot be modified or deleted by unprivileged users'
                'Purview Check' = 'Preservation Lock (RestrictiveRetention) applied to at least one retention policy'
                'Status'      = if ($HasPreservationLock) { 'Pass' } else { 'Fail' }
            }) | Out-Null

            $Controls.Add([pscustomobject][ordered]@{
                'Control ID'  = 'ISM-0854'
                'Framework'   = 'ISM'
                'E8 / PSPF'   = 'N/A'
                'Description' = 'Legal hold capability exists to preserve evidence for investigations'
                'Purview Check' = 'At least one active eDiscovery case hold configured'
                'Status'      = if ($HasActiveHolds) { 'Pass' } elseif ($AllCases.Count -gt 0) { 'Partial' } else { 'Manual' }
            }) | Out-Null

            #endregion

            #region ── Score ──────────────────────────────────────────────────────

            $PassCount    = ($Controls | Where-Object { $_.Status -eq 'Pass' }).Count
            $PartialCount = ($Controls | Where-Object { $_.Status -eq 'Partial' }).Count
            $FailCount    = ($Controls | Where-Object { $_.Status -eq 'Fail' }).Count
            $ManualCount  = ($Controls | Where-Object { $_.Status -eq 'Manual' }).Count
            $TotalAuto    = $Controls.Count - $ManualCount
            $ScorePct     = if ($TotalAuto -gt 0) {
                [math]::Round((($PassCount + $PartialCount * 0.5) / $TotalAuto) * 100, 0)
            } else { 0 }

            #endregion

            #region ── Score Summary Table ────────────────────────────────────────

            $ScoreObj = [System.Collections.ArrayList]::new()
            $ScoreObj.Add([pscustomobject][ordered]@{
                'Total Controls Assessed'  = $Controls.Count
                'Pass'                     = $PassCount
                'Partial'                  = $PartialCount
                'Fail'                     = $FailCount
                'Manual Review Required'   = $ManualCount
                'ACSC Compliance Score'    = "$ScorePct%"
            }) | Out-Null

            if ($Healthcheck -and $script:HealthCheck.Purview.ACSC) {
                if ($ScorePct -lt 50) { $ScoreObj | Set-Style -Style Critical | Out-Null }
                elseif ($ScorePct -lt 75) { $ScoreObj | Set-Style -Style Warning | Out-Null }
            }

            $ScoreTableParams = @{ Name = "ACSC ISM Compliance Score - $TenantId"; List = $true; ColumnWidths = 45, 55 }
            if ($script:Report.ShowTableCaptions) { $ScoreTableParams['Caption'] = "- $($ScoreTableParams.Name)" }
            $ScoreObj | Table @ScoreTableParams
            BlankLine

            #endregion

            #region ── Full Controls Table ────────────────────────────────────────

            if ($Healthcheck -and $script:HealthCheck.Purview.ACSC) {
                $Controls | Where-Object { $_.Status -eq 'Fail' }    | Set-Style -Style Critical | Out-Null
                $Controls | Where-Object { $_.Status -eq 'Partial' } | Set-Style -Style Warning  | Out-Null
                $Controls | Where-Object { $_.Status -eq 'Manual' }  | Set-Style -Style Info     | Out-Null
            }

            $CtrlTableParams = @{ Name = "ACSC ISM Controls - $TenantId"; List = $false; ColumnWidths = 12, 10, 12, 32, 22, 12 }
            if ($script:Report.ShowTableCaptions) { $CtrlTableParams['Caption'] = "- $($CtrlTableParams.Name)" }
            $Controls | Table @CtrlTableParams
            BlankLine

            #endregion

            #region ── Failed / Partial Remediation Table ─────────────────────────

            $Remediation = $Controls | Where-Object { $_.Status -ne 'Pass' }
            if ($Remediation) {

                Section -Style Heading3 'ACSC Remediation Actions' {
                    Paragraph 'The following controls require remediation or manual verification to achieve ACSC ISM compliance. Address Fail items first, then Partial items, then confirm Manual items with your compliance administrator.'
                    BlankLine

                    $RemObj = [System.Collections.ArrayList]::new()
                    foreach ($c in ($Remediation | Sort-Object { switch ($_.Status) { 'Fail'{0} 'Partial'{1} 'Manual'{2} } })) {
                        $RemObj.Add([pscustomobject][ordered]@{
                            'Control ID'     = $c.'Control ID'
                            'Framework'      = $c.Framework
                            'Status'         = $c.Status
                            'Description'    = $c.Description
                            'Action Required' = switch ($c.Status) {
                                'Fail'    { 'Implement this control in Microsoft Purview to meet the ISM requirement.' }
                                'Partial' { 'Review current configuration and complete implementation across all required workloads.' }
                                'Manual'  { 'Manually verify this control — it cannot be fully assessed via Purview configuration data alone.' }
                                default   { 'Review and action as appropriate.' }
                            }
                        }) | Out-Null
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.ACSC) {
                        $RemObj | Where-Object { $_.Status -eq 'Fail' }    | Set-Style -Style Critical | Out-Null
                        $RemObj | Where-Object { $_.Status -eq 'Partial' } | Set-Style -Style Warning  | Out-Null
                        $RemObj | Where-Object { $_.Status -eq 'Manual' }  | Set-Style -Style Info     | Out-Null
                    }

                    $RemTableParams = @{ Name = "ACSC Remediation - $TenantId"; List = $false; ColumnWidths = 12, 10, 10, 34, 34 }
                    if ($script:Report.ShowTableCaptions) { $RemTableParams['Caption'] = "- $($RemTableParams.Name)" }
                    $RemObj | Table @RemTableParams
                }
            }

            #endregion

        } # end Section ACSC
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'ACSC Assessment'
    }
}
