function Get-AbrPurviewAssessment {
    <#
    .SYNOPSIS
    Used by As Built Report to generate a Microsoft Purview Optimization Assessment (POA) report.
    .DESCRIPTION
        When Options.ReportType = 'Assessment' in the JSON config, this function replaces the
        standard As Built documentation sections with a scored assessment report. Each workload
        is evaluated against 90+ POA controls derived from Microsoft's Purview Optimization
        Assessment framework. Live configuration data is collected and used to automatically
        determine implementation status for each control.
    .NOTES
        Version:        0.1.0
        Author:         Pai Wei Sing
        Assessment framework by: Muataz Awad, Microsoft
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory)]
        [string]$TenantId
    )

    begin {
        Write-PScriboMessage -Message "Running Purview Optimization Assessment for tenant $TenantId." | Out-Null
        Show-AbrDebugExecutionTime -Start -TitleMessage 'POA Assessment'
    }

    process {

        #region ── Data Collection ──────────────────────────────────────────────────

        Write-Host '  [Assessment] Collecting live configuration data...'

        # --- DLP ---
        $DLPPolicies = @(try { Get-DlpCompliancePolicy -ErrorAction Stop } catch { @() })
        $AllDLPRules = [System.Collections.ArrayList]::new()
        foreach ($pol in $DLPPolicies) {
            try {
                $rules = Get-DlpComplianceRule -Policy $pol.Name -ErrorAction SilentlyContinue
                foreach ($r in $rules) { $AllDLPRules.Add($r) | Out-Null }
            } catch { }
        }

        $Flag_DLP_HasEnforced       = [bool]($DLPPolicies | Where-Object { $_.Mode -eq 'Enable' })
        $Flag_DLP_HasEndpoint       = [bool]($DLPPolicies | Where-Object { ($_.Workload -join ',') -match 'Endpoint' })
        $Flag_DLP_HasCopilot        = [bool]($DLPPolicies | Where-Object { $_.AdaptiveScopes -or ($_.Workload -join ',') -match 'Copilot' })
        $Flag_DLP_HasNotifications  = [bool]($AllDLPRules  | Where-Object { $_.NotifyUser })
        $Flag_DLP_HasBlocking       = [bool]($AllDLPRules  | Where-Object { $_.BlockAccess })
        $Flag_DLP_HasEPHI           = $false
        $Flag_DLP_HasPII            = $false
        $Flag_DLP_HasFinancial      = $false
        $Flag_DLP_HasCustomSITs     = $false
        foreach ($r in $AllDLPRules) {
            foreach ($sit in $r.ContentContainsSensitiveInformation) {
                if ($sit.Name -match 'HIPAA|Health')            { $Flag_DLP_HasEPHI      = $true }
                if ($sit.Name -match 'Credit Card')             { $Flag_DLP_HasFinancial  = $true }
                if ($sit.Name -match 'Social Security|SSN|Tax') { $Flag_DLP_HasPII        = $true }
                if ($sit.Name -match 'Custom|^(?!U\.S\.|U\.K\.|E\.U\.)') { $Flag_DLP_HasCustomSITs = $true }
            }
        }

        # --- Sensitivity Labels ---
        $Labels        = @(try { Get-Label -ErrorAction Stop } catch { @() })
        $LabelPolicies = @(try { Get-LabelPolicy -ErrorAction Stop } catch { @() })
        $AutoLabelPol  = @(try { Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue } catch { @() })

        $Flag_LBL_HasLabels           = ($Labels.Count -gt 0)
        $Flag_LBL_HasEncryption       = [bool]($Labels | Where-Object { $_.EncryptionEnabled })
        $Flag_LBL_HasContentMarking   = [bool]($Labels | Where-Object { $_.ContentMarkingEnabled })
        $Flag_LBL_HasAutoLabeling     = [bool]($Labels | Where-Object { $_.AutoLabelingEnabled })
        $Flag_LBL_HasAutoLabelPolicies= ($AutoLabelPol.Count -gt 0)
        $Flag_LBL_HasEnforcedAutoLabel= [bool]($AutoLabelPol | Where-Object { $_.Mode -eq 'Enable' })
        $Flag_LBL_HasSubLabels        = [bool]($Labels | Where-Object { $_.ParentId })
        $Flag_LBL_HasMandatory        = [bool]($LabelPolicies | Where-Object { $_.RequireSensitivityLabelOnSave })
        $Flag_LBL_HasDefault          = [bool]($LabelPolicies | Where-Object { $_.DefaultLabelId })

        # Auto-label SIT classification
        $Flag_LBL_AutoLabelCustomSIT   = $false
        $Flag_LBL_AutoLabelPII         = $false
        $Flag_LBL_AutoLabelFinancial    = $false
        foreach ($alp in $AutoLabelPol) {
            $rules = try { Get-AutoSensitivityLabelRule -Policy $alp.Name -ErrorAction SilentlyContinue } catch { @() }
            foreach ($r in $rules) {
                foreach ($sit in $r.ContentContainsSensitiveInformation) {
                    if ($sit.Name -match 'Social Security|SSN|Tax|Passport|Driver') { $Flag_LBL_AutoLabelPII = $true }
                    if ($sit.Name -match 'Credit Card|Bank|Financial')              { $Flag_LBL_AutoLabelFinancial = $true }
                    if ($sit.Name -match 'Custom')                                   { $Flag_LBL_AutoLabelCustomSIT = $true }
                }
            }
        }

        # --- Retention / DLM ---
        $RetentionPolicies = @(try { Get-RetentionCompliancePolicy -ErrorAction Stop } catch { @() })
        $ComplianceTags    = @(try { Get-ComplianceTag -ErrorAction Stop } catch { @() })

        $Flag_RET_HasPolicies          = ($RetentionPolicies.Count -gt 0)
        $Flag_RET_HasPreservationLock  = [bool]($RetentionPolicies | Where-Object { $_.RestrictiveRetention })
        $Flag_RET_HasTeamsPolicy       = [bool]($RetentionPolicies | Where-Object { ($_.Workload -join ',') -match 'Teams' })
        $Flag_RET_HasDeletion          = [bool]($RetentionPolicies | Where-Object { $_.RetentionAction -eq 'Delete' })
        $Flag_RET_HasManualLabels      = ($ComplianceTags.Count -gt 0)
        $Flag_RET_HasAutoApplyLabels   = [bool]($ComplianceTags | Where-Object { $_.AutoLabelType })
        $Flag_RET_CoversAllWorkloads   = [bool]($RetentionPolicies | Where-Object {
            ($_.Workload -join ',') -match 'Exchange' -and
            ($_.Workload -join ',') -match 'SharePoint' -and
            ($_.Workload -join ',') -match 'OneDrive'
        })

        # --- Record Management ---
        $Flag_RM_HasRecordLabels       = [bool]($ComplianceTags | Where-Object { $_.IsRecordLabel })
        $Flag_RM_HasRegulatoryRecords  = [bool]($ComplianceTags | Where-Object { $_.RegulatoryRecord })
        $Flag_RM_HasDispositionReview  = [bool]($ComplianceTags | Where-Object { $_.ReviewerEmail })
        $Flag_RM_HasEventBased         = [bool]($ComplianceTags | Where-Object { $_.EventType })
        $Flag_RM_HasAutoApplyRecord    = [bool]($ComplianceTags | Where-Object { $_.IsRecordLabel -and $_.AutoLabelType })
        $Flag_RM_HasProofOfDisposal    = $Flag_RM_HasDispositionReview  # Disposition review = proof of disposal workflow

        # --- Audit ---
        $AdminAuditConfig = try { Get-AdminAuditLogConfig -ErrorAction SilentlyContinue } catch { $null }
        $OrgConfig        = try { Get-OrganizationConfig -ErrorAction SilentlyContinue } catch { $null }
        $AuditRetPolicies = @(try { Get-UnifiedAuditLogRetentionPolicy -ErrorAction SilentlyContinue } catch { @() })
        $ProtAlerts       = @(try { Get-ProtectionAlert -ErrorAction SilentlyContinue } catch { @() })

        $Flag_AUD_IsEnabled            = [bool]($AdminAuditConfig.UnifiedAuditLogIngestionEnabled)
        $Flag_AUD_HasRetentionPolicy   = ($AuditRetPolicies.Count -gt 1)   # >1 means custom policy beyond default
        $Flag_AUD_MailboxAuditDefault  = ($OrgConfig.AuditDisabled -eq $false)
        $Flag_AUD_HasAuditAlerts       = [bool]($ProtAlerts | Where-Object { $_.Name -match 'audit|eDiscovery|mailbox' })
        $Flag_AUD_HasAuditSearchProcess= [bool]($ProtAlerts | Where-Object { $_.Name -match 'audit' })

        # --- Communication Compliance ---
        $CCPolicies = @(try { Get-SupervisoryReviewPolicyV2 -ErrorAction Stop } catch { @() })

        $Flag_CC_HasPolicies           = ($CCPolicies.Count -gt 0)
        $Flag_CC_HasEnabledPolicies    = [bool]($CCPolicies | Where-Object { $_.Enabled })
        $Flag_CC_HasTeamsCoverage      = [bool]($CCPolicies | Where-Object {
            $rules = try { Get-SupervisoryReviewRule -Policy $_.Name -ErrorAction SilentlyContinue } catch { @() }
            $rules | Where-Object { $_.Condition -match 'Teams' }
        })

        # --- Insider Risk ---
        $IRMPolicies = @()
        try {
            $Uri      = 'https://graph.microsoft.com/beta/security/insiderRiskPolicies'
            $Response = Invoke-MgGraphRequest -Uri $Uri -Method GET -ErrorAction Stop
            $IRMPolicies = $Response.value
        } catch { }
        $IRMSettings = $null
        try {
            $IRMSettings = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/security/insiderRiskSettings' -Method GET -ErrorAction Stop
        } catch { }

        $Flag_IRM_HasPolicies     = ($IRMPolicies.Count -gt 0)
        $Flag_IRM_HasDataTheft    = [bool]($IRMPolicies | Where-Object { $_.policyTemplate -match 'DataTheft|Theft|Departing' })
        $Flag_IRM_HasDataLeak     = [bool]($IRMPolicies | Where-Object { $_.policyTemplate -match 'DataLeak|Leak|GeneralDataLeak' })
        $Flag_IRM_HasAnonymize    = [bool]($IRMPolicies | Where-Object { $_.anonymizationEnabled -eq $true })
        $Flag_IRM_AnalyticsOn     = ($IRMSettings -and $IRMSettings.analyticsEnabled)

        # --- eDiscovery ---
        $CoreCases     = @(try { Get-ComplianceCase -CaseType Core     -ErrorAction SilentlyContinue } catch { @() })
        $AdvancedCases = @(try { Get-ComplianceCase -CaseType Advanced  -ErrorAction SilentlyContinue } catch { @() })
        $CaseHolds     = @(try { Get-CaseHoldPolicy -ErrorAction SilentlyContinue } catch { @() })

        $Flag_EDI_HasCoreCases     = ($CoreCases.Count -gt 0)
        $Flag_EDI_HasAdvancedCases = ($AdvancedCases.Count -gt 0)
        $Flag_EDI_HasActiveHolds   = [bool]($CaseHolds | Where-Object { $_.Enabled })

        # --- Copilot ---
        $Flag_CPL_HasDLPPolicy = $Flag_DLP_HasCopilot  # Already computed above

        #endregion

        #region ── POA Question Bank ────────────────────────────────────────────────

        # Each question:  ID, text, status (Implemented | Partial | NotImplemented | Manual)
        # Status is auto-set from live flags where possible; 'Manual' requires human review.

        $POA = [ordered] @{

            'Data Loss Prevention' = @(
                [pscustomobject]@{ ID='POA-101'; Question='Do you have Custom Sensitive Information Types?';                                                                                          Status = if ($Flag_DLP_HasCustomSITs)    { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-102'; Question='Do you have DLP policies for personally identifiable information (PII)?';                                                               Status = if ($Flag_DLP_HasPII)           { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-103'; Question='Do you have DLP policies for sensitive financial data?';                                                                                Status = if ($Flag_DLP_HasFinancial)     { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-104'; Question='Do you have DLP policies for ePHI / HIPAA data?';                                                                                      Status = if ($Flag_DLP_HasEPHI)         { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-105'; Question='Do you have a process to review DLP alerts and reports?';                                                                              Status = 'Manual Review Required' }
                [pscustomobject]@{ ID='POA-106'; Question='Are DLP policies actively enforced (not just running in test/audit mode)?';                                                            Status = if ($Flag_DLP_HasEnforced)     { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-107'; Question='Are DLP policy exclusions regularly reviewed to ensure they remain minimal and justified?';                                            Status = 'Manual Review Required' }
                [pscustomobject]@{ ID='POA-108'; Question='Are DLP policies protecting data across all critical M365 locations, including endpoints (Endpoint DLP)?';                            Status = if ($Flag_DLP_HasEndpoint)     { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-109'; Question='Are user notifications and policy tips used to educate employees on data handling in real-time?';                                      Status = if ($Flag_DLP_HasNotifications){ 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-110'; Question='Are DLP rules configured to actively block access to or sharing of sensitive content?';                                               Status = if ($Flag_DLP_HasBlocking)     { 'Implemented' } else { 'Not Implemented' } }
            )

            'Sensitivity Labels' = @(
                [pscustomobject]@{ ID='POA-201'; Question='Are auto-labeling policies configured?';                                                                                               Status = if ($Flag_LBL_HasAutoLabelPolicies)   { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-202'; Question='Is encryption applied using sensitivity labels?';                                                                                      Status = if ($Flag_LBL_HasEncryption)          { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-203'; Question='Is content marking (headers, footers, watermarks) applied with labels?';                                                              Status = if ($Flag_LBL_HasContentMarking)      { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-204'; Question='Is a default label configured in any label policy?';                                                                                  Status = if ($Flag_LBL_HasDefault)             { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-205'; Question='Is mandatory labeling enforced in any label policy?';                                                                                 Status = if ($Flag_LBL_HasMandatory)           { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-206'; Question='Are auto-labeling policies in Enforce mode (not just Simulation)?';                                                                   Status = if ($Flag_LBL_HasEnforcedAutoLabel)   { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-207'; Question='Is auto-labeling based on Custom Sensitive Information Types configured?';                                                            Status = if ($Flag_LBL_AutoLabelCustomSIT)     { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-208'; Question='Is auto-labeling based on PII data configured?';                                                                                      Status = if ($Flag_LBL_AutoLabelPII)           { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-209'; Question='Is auto-labeling based on financial data configured?';                                                                                Status = if ($Flag_LBL_AutoLabelFinancial)     { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-210'; Question='Are sublabels used to create a more granular data classification schema?';                                                            Status = if ($Flag_LBL_HasSubLabels)           { 'Implemented' } else { 'Not Implemented' } }
            )

            'Records Management' = @(
                [pscustomobject]@{ ID='POA-301'; Question='Are retention labels used to declare content as a record?';                                                                            Status = if ($Flag_RM_HasRecordLabels)     { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-302'; Question='Are record labels auto-applied to content?';                                                                                          Status = if ($Flag_RM_HasAutoApplyRecord)  { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-303'; Question='Is event-based retention used to trigger retention from specific business events?';                                                   Status = if ($Flag_RM_HasEventBased)       { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-304'; Question='Is a disposition review process configured for records at end of retention period?';                                                  Status = if ($Flag_RM_HasDispositionReview){ 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-305'; Question='Is proof of disposal maintained for records to meet compliance requirements?';                                                        Status = if ($Flag_RM_HasProofOfDisposal) { 'Implemented' } else { 'Not Implemented' } }
            )

            'Data Lifecycle Management' = @(
                [pscustomobject]@{ ID='POA-401'; Question='Are retention policies covering all required workloads (Exchange, SharePoint, OneDrive)?';                                            Status = if ($Flag_RET_CoversAllWorkloads) { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-402'; Question='Are retention periods aligned with legal, regulatory, and business requirements?';                                                    Status = 'Manual Review Required' }
                [pscustomobject]@{ ID='POA-403'; Question='Is there a process to automatically delete data that is no longer needed?';                                                          Status = if ($Flag_RET_HasDeletion)        { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-404'; Question='Are specific retention policies configured for Microsoft Teams messages?';                                                            Status = if ($Flag_RET_HasTeamsPolicy)     { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-405'; Question='Are policies configured to automatically delete content at end of retention period?';                                                Status = if ($Flag_RET_HasDeletion)        { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-406'; Question='Are manual retention labels used for content with varying retention needs?';                                                          Status = if ($Flag_RET_HasManualLabels)    { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-407'; Question='Are retention labels automatically assigned to content?';                                                                              Status = if ($Flag_RET_HasAutoApplyLabels) { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-408'; Question='Are Teams meeting artifacts (recordings and transcripts) included in retention design?';                                             Status = 'Manual Review Required' }
                [pscustomobject]@{ ID='POA-409'; Question='Is retention verified prior to offboarding or archiving inactive mailboxes?';                                                        Status = 'Manual Review Required' }
                [pscustomobject]@{ ID='POA-410'; Question='Is Preservation Lock applied to any retention policies?';                                                                             Status = if ($Flag_RET_HasPreservationLock){ 'Implemented' } else { 'Not Implemented' } }
            )

            'Audit' = @(
                [pscustomobject]@{ ID='POA-501'; Question='Is unified audit logging enabled for the tenant?';                                                                                    Status = if ($Flag_AUD_IsEnabled)          { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-502'; Question='Is a custom audit log retention policy configured (beyond default 90-day retention)?';                                                Status = if ($Flag_AUD_HasRetentionPolicy) { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-503'; Question='Is there a process to review who is searching the audit logs?';                                                                      Status = if ($Flag_AUD_HasAuditSearchProcess) { 'Implemented' } else { 'Manual Review Required' } }
                [pscustomobject]@{ ID='POA-504'; Question='Is mailbox auditing enabled by default for all user mailboxes?';                                                                      Status = if ($Flag_AUD_MailboxAuditDefault) { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-505'; Question='Are alerts configured for high-risk audit activities (e.g., eDiscovery searches, mailbox permission changes)?';                      Status = if ($Flag_AUD_HasAuditAlerts)     { 'Implemented' } else { 'Not Implemented' } }
            )

            'Communication Compliance' = @(
                [pscustomobject]@{ ID='POA-601'; Question='Are active Communication Compliance policies configured?';                                                                            Status = if ($Flag_CC_HasPolicies)         { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-602'; Question='Is there a process for reviewing items flagged by Communication Compliance policies?';                                                Status = if ($Flag_CC_HasEnabledPolicies)  { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-603'; Question='Are policies scoped to cover all relevant communication channels (Teams, Exchange, Viva Engage)?';                                   Status = if ($Flag_CC_HasTeamsCoverage)    { 'Implemented' } else { 'Manual Review Required' } }
                [pscustomobject]@{ ID='POA-604'; Question='Are trainable classifiers or adaptive scopes used to refine detection of policy violations?';                                        Status = 'Manual Review Required' }
                [pscustomobject]@{ ID='POA-605'; Question='Is the Communication Compliance reviewer role tightly controlled and assigned only to authorized personnel?';                        Status = 'Manual Review Required' }
            )

            'Insider Risk Management' = @(
                [pscustomobject]@{ ID='POA-701'; Question='Are policies configured to detect departing employee data theft?';                                                                    Status = if ($Flag_IRM_HasDataTheft)       { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-702'; Question='Are policies configured to detect data leaks?';                                                                                      Status = if ($Flag_IRM_HasDataLeak)        { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-703'; Question='Are IRM indicators from M365 services (Audit, DLP) used to enrich risk scoring?';                                                   Status = if ($Flag_IRM_AnalyticsOn)        { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-704'; Question='Is there a defined workflow for triaging, investigating, and acting on IRM alerts and cases?';                                       Status = 'Manual Review Required' }
                [pscustomobject]@{ ID='POA-705'; Question='Is anonymization used in IRM policies to protect user privacy during initial investigations?';                                       Status = if ($Flag_IRM_HasAnonymize)       { 'Implemented' } else { 'Not Implemented' } }
            )

            'eDiscovery' = @(
                [pscustomobject]@{ ID='POA-801'; Question='Are Core eDiscovery cases used to support legal investigations?';                                                                     Status = if ($Flag_EDI_HasCoreCases)       { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-802'; Question='Are Advanced eDiscovery cases used for complex investigations?';                                                                      Status = if ($Flag_EDI_HasAdvancedCases)   { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-803'; Question='Are case holds actively used to preserve content for investigations?';                                                               Status = if ($Flag_EDI_HasActiveHolds)     { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-804'; Question='Is access to eDiscovery cases restricted to authorized personnel?';                                                                  Status = 'Manual Review Required' }
                [pscustomobject]@{ ID='POA-805'; Question='Does the organisation have a documented process for responding to eDiscovery requests?';                                              Status = 'Manual Review Required' }
            )

            'Microsoft 365 Copilot' = @(
                [pscustomobject]@{ ID='POA-901'; Question='Is DSPM for AI used to discover and secure AI usage across the organisation?';                                                       Status = 'Manual Review Required' }
                [pscustomobject]@{ ID='POA-902'; Question='Are sensitivity labels applied to content used by Copilot?';                                                                         Status = if ($Flag_LBL_HasLabels)          { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-903'; Question='Are DLP policies configured to prevent Copilot from processing sensitive content?';                                                  Status = if ($Flag_CPL_HasDLPPolicy)       { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-904'; Question='Is Insider Risk Management used to detect and mitigate risky Copilot behaviour?';                                                    Status = if ($Flag_IRM_HasPolicies)        { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-905'; Question='Is unified audit logging enabled to track Copilot interactions?';                                                                    Status = if ($Flag_AUD_IsEnabled)          { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-906'; Question='Are Communication Compliance policies in place for Copilot interactions?';                                                           Status = if ($Flag_CC_HasPolicies)         { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-907'; Question='Is eDiscovery used to manage search and deletion of Copilot data?';                                                                  Status = if ($Flag_EDI_HasCoreCases -or $Flag_EDI_HasAdvancedCases) { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-908'; Question='Are retention policies in place to manage the lifecycle of Copilot-generated data?';                                                 Status = if ($Flag_RET_HasPolicies)        { 'Implemented' } else { 'Not Implemented' } }
                [pscustomobject]@{ ID='POA-909'; Question='Is access to Microsoft 365 Copilot restricted to specific users or groups?';                                                        Status = 'Manual Review Required' }
                [pscustomobject]@{ ID='POA-910'; Question='Is there a process to monitor Copilot usage and refine security and compliance policies?';                                           Status = 'Manual Review Required' }
            )
        }

        #endregion

        #region ── Scoring ──────────────────────────────────────────────────────────

        $TotalImplemented    = 0
        $TotalPartial        = 0
        $TotalNotImplemented = 0
        $TotalManual         = 0
        $TotalQuestions      = 0

        foreach ($section in $POA.Keys) {
            foreach ($q in $POA[$section]) {
                $TotalQuestions++
                switch ($q.Status) {
                    'Implemented'          { $TotalImplemented++ }
                    'Partially Implemented'{ $TotalPartial++ }
                    'Not Implemented'      { $TotalNotImplemented++ }
                    'Manual Review Required'{ $TotalManual++ }
                }
            }
        }

        $AutoAnswered  = $TotalQuestions - $TotalManual
        $ScoreBase     = $TotalImplemented + ($TotalPartial * 0.5)
        $ScorePct      = if ($AutoAnswered -gt 0) { [math]::Round(($ScoreBase / $AutoAnswered) * 100, 1) } else { 0 }

        #endregion

        #region ── Report Output ────────────────────────────────────────────────────

        Section -Style Heading2 'Purview Optimization Assessment (POA)' {

            Paragraph "This assessment evaluates the Microsoft Purview compliance posture for $TenantId against $TotalQuestions controls across 9 workload areas. Live configuration data has been used to automatically determine implementation status for $AutoAnswered controls. $TotalManual controls require manual review."
            BlankLine

            #region Overall Score Table
            $ScoreObj = [System.Collections.ArrayList]::new()
            $scoreInObj = [ordered] @{
                'Total Controls Assessed'        = $TotalQuestions
                'Auto-Assessed Controls'         = $AutoAnswered
                'Manually Reviewed Required'     = $TotalManual
                'Implemented'                    = $TotalImplemented
                'Partially Implemented'          = $TotalPartial
                'Not Implemented'                = $TotalNotImplemented
                'Compliance Score (Auto-Assessed)' = "$ScorePct%"
            }
            $ScoreObj.Add([pscustomobject]$scoreInObj) | Out-Null

            $null = (& {
            if ($HealthCheck.Purview.DLP) {
                if ($ScorePct -lt 50) { $ScoreObj | Set-Style -Style Critical | Out-Null }
                elseif ($ScorePct -lt 75) { $ScoreObj | Set-Style -Style Warning | Out-Null }
            }
            })

            $ScoreTableParams = @{ Name = "Assessment Score - $TenantId"; List = $true; ColumnWidths = 45, 55 }
            $null = (& { if ($Report.ShowTableCaptions) { $ScoreTableParams['Caption'] = "- $($ScoreTableParams.Name)" } })
            $ScoreObj | Table @ScoreTableParams
            BlankLine
            #endregion

            #region Summary Table (one row per section)
            $SummaryObj = [System.Collections.ArrayList]::new()
            foreach ($section in $POA.Keys) {
                $questions = $POA[$section]
                $sImpl     = ($questions | Where-Object { $_.Status -eq 'Implemented' }).Count
                $sPartial  = ($questions | Where-Object { $_.Status -eq 'Partially Implemented' }).Count
                $sNotImpl  = ($questions | Where-Object { $_.Status -eq 'Not Implemented' }).Count
                $sManual   = ($questions | Where-Object { $_.Status -eq 'Manual Review Required' }).Count
                $sTotal    = $questions.Count
                $sAuto     = $sTotal - $sManual
                $sPct      = if ($sAuto -gt 0) { [math]::Round((($sImpl + $sPartial * 0.5) / $sAuto) * 100, 0) } else { '--' }

                $summInObj = [ordered] @{
                    'Workload'                 = $section
                    'Controls'                 = $sTotal
                    'Implemented'              = $sImpl
                    'Partial'                  = $sPartial
                    'Not Implemented'          = $sNotImpl
                    'Manual Review'            = $sManual
                    'Score'                    = if ($sPct -ne '--') { "$sPct%" } else { 'N/A' }
                }
                $SummaryObj.Add([pscustomobject]$summInObj) | Out-Null
            }

            $null = (& {
            if ($HealthCheck.Purview.DLP) {
                $SummaryObj | Where-Object { [int]($_.Score -replace '%','') -lt 50 -and $_.Score -ne 'N/A' } | Set-Style -Style Critical | Out-Null
                $SummaryObj | Where-Object { [int]($_.Score -replace '%','') -lt 75 -and [int]($_.Score -replace '%','') -ge 50 } | Set-Style -Style Warning | Out-Null
            }
            })

            $SummaryTableParams = @{ Name = "Assessment Summary by Workload - $TenantId"; List = $false; ColumnWidths = 26, 9, 12, 9, 15, 14, 15 }
            $null = (& { if ($Report.ShowTableCaptions) { $SummaryTableParams['Caption'] = "- $($SummaryTableParams.Name)" } })
            $SummaryObj | Table @SummaryTableParams
            BlankLine
            #endregion

            #region Per-Workload Detail Sections
            foreach ($section in $POA.Keys) {
                Section -Style Heading3 $section {

                    $questions = $POA[$section]
                    $QObj = [System.Collections.ArrayList]::new()

                    foreach ($q in $questions) {
                        $qInObj = [ordered] @{
                            'POA ID'   = $q.ID
                            'Control'  = $q.Question
                            'Status'   = $q.Status
                        }
                        $QObj.Add([pscustomobject]$qInObj) | Out-Null
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.DLP) {
                        $QObj | Where-Object { $_.Status -eq 'Not Implemented' }       | Set-Style -Style Critical | Out-Null
                        $QObj | Where-Object { $_.Status -eq 'Partially Implemented' } | Set-Style -Style Warning  | Out-Null
                        $QObj | Where-Object { $_.Status -eq 'Manual Review Required'} | Set-Style -Style Info     | Out-Null
                    }
                    })

                    $QTableParams = @{ Name = "$section Controls - $TenantId"; List = $false; ColumnWidths = 12, 68, 20 }
                    $null = (& { if ($Report.ShowTableCaptions) { $QTableParams['Caption'] = "- $($QTableParams.Name)" } })
                    $QObj | Table @QTableParams
                }
            }
            #endregion

            #region Remediation Plan
            Section -Style Heading3 'Remediation Plan' {

                Paragraph "The following remediation plan lists all controls that are Not Implemented or require Manual Review, prioritised by workload. Address Critical items first to improve the compliance score. Items marked Manual Review Required must be validated by an authorised administrator."
                BlankLine

                # Build remediation table — exclude already Implemented
                $RemObj = [System.Collections.ArrayList]::new()

                # Priority ordering: Not Implemented first, then Manual Review Required
                $priorityOrder = @('Not Implemented', 'Manual Review Required', 'Partially Implemented')

                foreach ($status in $priorityOrder) {
                    foreach ($section in $POA.Keys) {
                        foreach ($q in $POA[$section]) {
                            if ($q.Status -ne $status) { continue }

                            $remInObj = [ordered] @{
                                'POA ID'     = $q.ID
                                'Workload'   = $section
                                'Control'    = $q.Question
                                'Status'     = $q.Status
                                'Action Required' = switch ($q.Status) {
                                    'Not Implemented'        { 'Implement this control in the Microsoft Purview compliance portal.' }
                                    'Partially Implemented'  { 'Review current configuration and complete implementation.' }
                                    'Manual Review Required' { 'Manually verify this control with your compliance administrator.' }
                                    default                  { 'Review and action as appropriate.' }
                                }
                            }
                            $RemObj.Add([pscustomobject]$remInObj) | Out-Null
                        }
                    }
                }

                if ($RemObj.Count -gt 0) {
                    $null = (& {
                    if ($HealthCheck.Purview.DLP) {
                        $RemObj | Where-Object { $_.Status -eq 'Not Implemented' }       | Set-Style -Style Critical | Out-Null
                        $RemObj | Where-Object { $_.Status -eq 'Partially Implemented' } | Set-Style -Style Warning  | Out-Null
                        $RemObj | Where-Object { $_.Status -eq 'Manual Review Required'} | Set-Style -Style Info     | Out-Null
                    }
                    })

                    $RemTableParams = @{ Name = "Remediation Plan - $TenantId"; List = $false; ColumnWidths = 10, 18, 32, 16, 24 }
                    $null = (& { if ($Report.ShowTableCaptions) { $RemTableParams['Caption'] = "- $($RemTableParams.Name)" } })
                    $RemObj | Table @RemTableParams
                } else {
                    Paragraph "All controls have been implemented. No remediation actions are required."
                }
            }
            #endregion

        } # end Section POA

        #endregion
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'POA Assessment'
    }
}
