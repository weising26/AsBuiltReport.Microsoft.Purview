function Get-AbrPurviewRetentionPolicy {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Retention Policy information.
    .DESCRIPTION
        Collects and reports on Retention Policies and Retention Labels configured
        in Microsoft Purview, including retention durations and actions.
    .NOTES
        Version:        0.1.0
        Author:         Pai Wei Sing
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter (
            Position = 0,
            Mandatory)]
        [string]
        $TenantId
    )

    begin {
        Write-PScriboMessage -Message "Collecting Microsoft Purview Retention Policy information for tenant $TenantId." | Out-Null
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Retention Policies'
    }

    process {
        # Retention Policies
        try {
            $RetentionPolicies = Get-RetentionCompliancePolicy -ErrorAction Stop

            if ($RetentionPolicies) {
                Section -Style Heading3 'Retention Policies' {

                    #region Coverage Summary
                    $HasPreservationLock = $RetentionPolicies | Where-Object { $_.RestrictiveRetention }
                    $HasAdaptiveScope    = $RetentionPolicies | Where-Object { $_.AdaptiveScopeLocation }

                    $CovObj = [System.Collections.ArrayList]::new()
                        $_pre_RetentionPoliciesCon_43 = if ($RetentionPolicies.Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_HasPreservationLockP_44 = if (@($HasPreservationLock).Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_UsesAdaptiveScopes_45 = if (@($HasAdaptiveScope).Count -gt 0) { 'Yes' } else { 'No' }
                    $covInObj = [ordered] @{
                        'Retention Policies Configured' = $_pre_RetentionPoliciesCon_43
                        'Has Preservation Lock Policy' = $_pre_HasPreservationLockP_44
                        'Uses Adaptive Scopes' = $_pre_UsesAdaptiveScopes_45
                    }
                    $CovObj.Add([pscustomobject]$covInObj) | Out-Null

                    if ($Healthcheck -and $script:HealthCheck.Purview.Retention) {
                        $CovObj | Where-Object { $_.'Retention Policies Configured' -eq 'No' } | Set-Style -Style Critical | Out-Null
                    }

                    $CovTableParams = @{ Name = "Retention Coverage Summary - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    if ($script:Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" }
                    $CovObj | Table @CovTableParams
                    #endregion

                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Policy in $RetentionPolicies) {
                        try {
                             $_pre_Enabled_67 = if ($Policy.Enabled) { 'Yes' } else { 'No' }
                             $_pre_PreservationLock_72 = if ($Policy.RestrictiveRetention) { 'Yes' } else { 'No' }
                            $inObj = [ordered] @{
                             'Name'              = $Policy.Name
                             'Enabled' = $_pre_Enabled_67
                             'Retention Action'  = $script:TextInfo.ToTitleCase($Policy.RetentionAction)
                             'Retention Duration'= $Policy.RetentionDuration
                             'Workload'          = ($Policy.Workload -join ', ')
                             'Adaptive Scope'    = $Policy.AdaptiveScopeLocation
                             'Preservation Lock' = $_pre_PreservationLock_72
                             'Created'           = $Policy.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Retention Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.Retention) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                    }

                    $TableParams = @{
                        Name         = "Retention Policies - $TenantId"
                        List         = $false
                        ColumnWidths = 18, 8, 13, 13, 16, 10, 12, 10
                    }
                    if ($script:Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams

                    #region ACSC Inline Check — Retention Policies
                    if ($script:InfoLevel.Retention -ge 3) {
                        $CoversKeyWorkloads  = [bool]($RetentionPolicies | Where-Object {
                            ($_.Workload -join ',') -match 'Exchange' -and
                            ($_.Workload -join ',') -match 'SharePoint' -and
                            ($_.Workload -join ',') -match 'OneDrive'
                        })
                        $HasPreservationLock = [bool]($RetentionPolicies | Where-Object { $_.RestrictiveRetention })
                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'Retention Policies' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-1511'
                                E8          = 'E8 Backup ML1'
                                Description = 'Backups of important data retained and restorable'
                                Check       = 'Retention policies covering Exchange, SharePoint, and OneDrive'
                                Status      = if ($CoversKeyWorkloads) { 'Pass' } elseif ($RetentionPolicies.Count -gt 0) { 'Partial' } else { 'Fail' }
                            }
                            [pscustomobject]@{
                                ControlId   = 'ISM-1515'
                                E8          = 'E8 Backup ML2'
                                Description = 'Backups cannot be modified or deleted by unprivileged users'
                                Check       = 'Preservation Lock (RestrictiveRetention) applied to at least one retention policy'
                                Status      = if ($HasPreservationLock) { 'Pass' } else { 'Fail' }
                            }
                        )
                    }
                    #endregion

                    # Retention Rules per policy
                    if ($script:InfoLevel.Retention -ge 2) {
                        foreach ($Policy in $RetentionPolicies) {
                                 try {
                                  $Rules = Get-RetentionComplianceRule -Policy $Policy.Name -ErrorAction SilentlyContinue
                                  if ($Rules) {
                                   Section -ExcludeFromTOC -Style NOTOCHeading4 "Rules: $($Policy.Name)" {
                                    $RuleObj = [System.Collections.ArrayList]::new()
                                    foreach ($Rule in $Rules) {
                                     try {
                                      $ruleInObj = [ordered] @{
                                       'Rule Name'           = $Rule.Name
                                       'Retention Duration'  = $Rule.RetentionDuration
                                       'Retention Action'    = $script:TextInfo.ToTitleCase($Rule.RetentionComplianceAction)
                                       'Content Match Query' = $Rule.ContentMatchQuery
                                      }
                                      $RuleObj.Add([pscustomobject]$ruleInObj) | Out-Null
                                     } catch {
                                      Write-PScriboMessage -IsWarning -Message "Retention Rule '$($Rule.Name)': $($_.Exception.Message)" | Out-Null
                                     }
                                    }
                                    $RuleTableParams = @{
                                     Name         = "Retention Rules - $($Policy.Name)"
                                     List         = $false
                                     ColumnWidths = 28, 18, 18, 36
                                    }
                                    if ($script:Report.ShowTableCaptions) {
                                     $RuleTableParams['Caption'] = "- $($RuleTableParams.Name)"
                                    }
                                    $RuleObj | Sort-Object -Property 'Rule Name' | Table @RuleTableParams
                                   }
                                  }
                                 } catch {
                                  Write-PScriboMessage -IsWarning -Message "Retention Rules for '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                                 }
                                }
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Retention Policy information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Retention Policy Section: $($_.Exception.Message)" | Out-Null
        }

        # Retention Labels
        try {
            $RetentionLabels = Get-ComplianceTag -ErrorAction Stop

            if ($RetentionLabels) {
                Section -Style Heading3 'Retention Labels' {

                    #region Coverage Summary
                    $HasRecordLabels       = $RetentionLabels | Where-Object { $_.IsRecordLabel }
                    $HasRegulatoryRecords  = $RetentionLabels | Where-Object { $_.RegulatoryRecord }
                    $HasDispositionReview  = $RetentionLabels | Where-Object { $_.ReviewerEmail }
                    $HasEventBasedLabels   = $RetentionLabels | Where-Object { $_.EventType }

                    $LabelCovObj = [System.Collections.ArrayList]::new()
                        $_pre_RetentionLabelsConfi_184 = if ($RetentionLabels.Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_RecordLabelsConfigur_185 = if (@($HasRecordLabels).Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_RegulatoryRecordsCon_186 = if (@($HasRegulatoryRecords).Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_DispositionReviewCon_187 = if (@($HasDispositionReview).Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_EventBasedRetentionL_188 = if (@($HasEventBasedLabels).Count -gt 0) { 'Yes' } else { 'No' }
                    $labelCovInObj = [ordered] @{
                        'Retention Labels Configured' = $_pre_RetentionLabelsConfi_184
                        'Record Labels Configured' = $_pre_RecordLabelsConfigur_185
                        'Regulatory Records Configured' = $_pre_RegulatoryRecordsCon_186
                        'Disposition Review Configured' = $_pre_DispositionReviewCon_187
                        'Event-Based Retention Labels' = $_pre_EventBasedRetentionL_188
                    }
                    $LabelCovObj.Add([pscustomobject]$labelCovInObj) | Out-Null

                    if ($Healthcheck -and $script:HealthCheck.Purview.Retention) {
                        $LabelCovObj | Where-Object { $_.'Retention Labels Configured' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }

                    $LabelCovTableParams = @{ Name = "Retention Label Coverage - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    if ($script:Report.ShowTableCaptions) { $LabelCovTableParams['Caption'] = "- $($LabelCovTableParams.Name)" }
                    $LabelCovObj | Table @LabelCovTableParams
                    #endregion

                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Label in $RetentionLabels) {
                        try {
                             $_pre_RecordLabel_215 = if ($Label.IsRecordLabel) { 'Yes' } else { 'No' }
                             $_pre_Regulatory_216 = if ($Label.RegulatoryRecord) { 'Yes' } else { 'No' }
                             $_pre_DispositionReview_217 = if ($null -ne $Label.ReviewerEmail -and $Label.ReviewerEmail -ne '') { 'Yes' } else { 'No' }
                             $_pre_EventType_218 = if ($Label.EventType) { $Label.EventType } else { '--' }
                            $inObj = [ordered] @{
                             'Name'               = $Label.Name
                             'Retention Action'   = $script:TextInfo.ToTitleCase($Label.RetentionAction)
                             'Retention Duration' = $Label.RetentionDuration
                             'Retention Type'     = $script:TextInfo.ToTitleCase($Label.RetentionType)
                             'Record Label' = $_pre_RecordLabel_215
                             'Regulatory' = $_pre_Regulatory_216
                             'Disposition Review' = $_pre_DispositionReview_217
                             'Event Type' = $_pre_EventType_218
                             'Created'            = $Label.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Retention Label '$($Label.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $TableParams = @{
                        Name         = "Retention Labels - $TenantId"
                        List         = $false
                        ColumnWidths = 18, 13, 13, 12, 9, 10, 10, 8, 7
                    }
                    if ($script:Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Retention Label information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Retention Label Section: $($_.Exception.Message)" | Out-Null
        }

        #region Mailbox Archiving (MCCA check-IG101)
        try {
            # Get-EXOMailbox is faster/safer than Get-Mailbox at scale; fall back to Get-Mailbox
            $AllMailboxes   = $null
            $ArchivedCount  = 0
            $TotalCount     = 0
            try {
                $AllMailboxes  = Get-EXOMailbox -ResultSize Unlimited -PropertySets Archive -ErrorAction Stop
            } catch {
                $AllMailboxes  = Get-Mailbox -ResultSize Unlimited -ErrorAction SilentlyContinue
            }

            if ($AllMailboxes) {
                $TotalCount    = @($AllMailboxes).Count
                $ArchivedCount = @($AllMailboxes | Where-Object { $_.ArchiveStatus -eq 'Active' }).Count
                $AutoExpandCount = @($AllMailboxes | Where-Object { $_.AutoExpandingArchiveEnabled -eq $true }).Count
                $ArchivePct    = if ($TotalCount -gt 0) { [math]::Round(($ArchivedCount / $TotalCount) * 100, 1) } else { 0 }

                Section -Style Heading3 'Mailbox Archiving' {
                    Paragraph "In-Place Archive (online archive) extends mailbox storage and supports long-term retention. MCCA recommends enabling archiving across all mailboxes to support information governance policies."
                    BlankLine

                    $_pre_TotalMailboxes  = $TotalCount
                    $_pre_ArchiveEnabled  = $ArchivedCount
                    $_pre_ArchivePct      = "$ArchivePct%"
                    $_pre_AutoExpanding   = $AutoExpandCount
                    $_pre_ArchiveStatus   = if ($ArchivePct -ge 90) { 'Good' } elseif ($ArchivePct -ge 50) { 'Partial' } else { 'Low Coverage' }

                    $archInObj = [ordered] @{
                        'Total Mailboxes'                = $_pre_TotalMailboxes
                        'Mailboxes with Archive Enabled' = $_pre_ArchiveEnabled
                        'Archive Coverage'               = $_pre_ArchivePct
                        'Auto-Expanding Archive Enabled' = $_pre_AutoExpanding
                        'Coverage Status'                = $_pre_ArchiveStatus
                    }
                    $ArchObj = [System.Collections.ArrayList]::new()
                    $ArchObj.Add([pscustomobject]$archInObj) | Out-Null

                    if ($Healthcheck -and $script:HealthCheck.Purview.Retention) {
                        $ArchObj | Where-Object { $ArchivePct -lt 50 }  | Set-Style -Style Critical | Out-Null
                        $ArchObj | Where-Object { $ArchivePct -lt 90 -and $ArchivePct -ge 50 } | Set-Style -Style Warning | Out-Null
                    }

                    $ArchTableParams = @{ Name = "Mailbox Archiving Coverage - $TenantId"; List = $true; ColumnWidths = 45, 55 }
                    if ($script:Report.ShowTableCaptions) { $ArchTableParams['Caption'] = "- $($ArchTableParams.Name)" }
                    $ArchObj | Table @ArchTableParams

                    if ($script:InfoLevel.Retention -ge 3) {
                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'Mailbox Archiving' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-1511'
                                E8          = 'N/A'
                                Description = 'Long-term email retention supported through online archiving'
                                Check       = 'In-Place Archive enabled on 90%+ of mailboxes'
                                Status      = if ($ArchivePct -ge 90) { 'Pass' } elseif ($ArchivePct -ge 50) { 'Partial' } else { 'Fail' }
                            }
                        )
                    }
                }
            } else {
                Write-PScriboMessage -Message "No mailbox information found for $TenantId. Disabling mailbox archive section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Mailbox Archiving Section: $($_.Exception.Message)" | Out-Null
        }
        #endregion

        #region MRM Policies — Exchange-native Messaging Records Management (MCCA check-IG102)
        try {
            $MRMPolicies = Get-RetentionPolicy -ErrorAction SilentlyContinue

            if ($MRMPolicies) {
                Section -Style Heading3 'Exchange MRM Retention Policies' {
                    Paragraph "Exchange Messaging Records Management (MRM) retention policies are Exchange-native and separate from Microsoft Purview unified retention. Many tenants run both systems in parallel during migration."
                    BlankLine

                    $MRMObj = [System.Collections.ArrayList]::new()
                    foreach ($Policy in $MRMPolicies) {
                        try {
                            $Tags = @()
                            try { $Tags = Get-RetentionPolicyTag -RetentionPolicy $Policy.Name -ErrorAction SilentlyContinue } catch {}
                            $_pre_IsDefault  = if ($Policy.IsDefault) { 'Yes' } else { 'No' }
                            $_pre_TagCount   = $Tags.Count
                            $_pre_RetainAged = if ($Tags | Where-Object { $_.RetentionAction -eq 'MoveToArchive' }) { 'Yes' } else { 'No' }
                            $_pre_Delete     = if ($Tags | Where-Object { $_.RetentionAction -eq 'DeleteAndAllowRecovery' -or $_.RetentionAction -eq 'PermanentlyDelete' }) { 'Yes' } else { 'No' }
                            $mrmInObj = [ordered] @{
                                'Policy Name'         = $Policy.Name
                                'Is Default Policy'   = $_pre_IsDefault
                                'Retention Tags'      = $_pre_TagCount
                                'Has Archive Tag'     = $_pre_RetainAged
                                'Has Delete Tag'      = $_pre_Delete
                            }
                            $MRMObj.Add([pscustomobject]$mrmInObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "MRM Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.Retention) {
                        # Flag if only the default policy exists and no custom MRM policies are configured
                        $CustomMRM = @($MRMPolicies | Where-Object { -not $_.IsDefault })
                        if ($CustomMRM.Count -eq 0) {
                            $MRMObj | Set-Style -Style Warning | Out-Null
                        }
                    }

                    $MRMTableParams = @{ Name = "Exchange MRM Retention Policies - $TenantId"; List = $false; ColumnWidths = 36, 16, 14, 17, 17 }
                    if ($script:Report.ShowTableCaptions) { $MRMTableParams['Caption'] = "- $($MRMTableParams.Name)" }
                    $MRMObj | Sort-Object -Property 'Policy Name' | Table @MRMTableParams

                    if ($script:InfoLevel.Retention -ge 3) {
                        $_hasMRMCustom = (@($MRMPolicies | Where-Object { -not $_.IsDefault })).Count -gt 0
                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'Exchange MRM Policies' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-1511'
                                E8          = 'N/A'
                                Description = 'Email lifecycle management enforced via retention policies'
                                Check       = 'At least one custom Exchange MRM retention policy configured'
                                Status      = if ($_hasMRMCustom) { 'Pass' } else { 'Partial' }
                            }
                        )
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Exchange MRM Retention Policy information found for $TenantId." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "MRM Retention Policy Section: $($_.Exception.Message)" | Out-Null
        }
        #endregion
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Retention Policies'
    }
}
