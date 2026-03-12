function Get-AbrPurviewRecordManagement {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Records Management information.
    .DESCRIPTION
        Collects and reports on Retention Labels configured as Record or Regulatory Record
        labels in Microsoft Purview, including disposition review, event-based retention,
        and file plan properties.
    .NOTES
        Version:        0.1.0
        Author:         Pai Wei Sing
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory)]
        [string]$TenantId
    )

    begin {
        Write-PScriboMessage -Message "Collecting Microsoft Purview Records Management information for tenant $TenantId." | Out-Null
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Records Management'
    }

    process {
        try {
            $AllLabels = Get-ComplianceTag -ErrorAction Stop

            if ($AllLabels) {
                Section -Style Heading3 'Records Management' {

                    #region Coverage Summary
                    $RecordLabels      = $AllLabels | Where-Object { $_.IsRecordLabel }
                    $RegulatoryLabels  = $AllLabels | Where-Object { $_.RegulatoryRecord }
                    $DispositionLabels = $AllLabels | Where-Object { $_.ReviewerEmail }
                    $EventLabels       = $AllLabels | Where-Object { $_.EventType }

                    $CovObj = [System.Collections.ArrayList]::new()
                        $_pre_RecordLabelsConfigur_42 = if (@($RecordLabels).Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_RegulatoryRecordsCon_43 = if (@($RegulatoryLabels).Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_DispositionReviewCon_44 = if (@($DispositionLabels).Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_EventBasedRetentionC_45 = if (@($EventLabels).Count -gt 0) { 'Yes' } else { 'No' }
                    $covInObj = [ordered] @{
                        'Record Labels Configured' = $_pre_RecordLabelsConfigur_42
                        'Regulatory Records Configured' = $_pre_RegulatoryRecordsCon_43
                        'Disposition Review Configured' = $_pre_DispositionReviewCon_44
                        'Event-Based Retention Configured' = $_pre_EventBasedRetentionC_45
                    }
                    $CovObj.Add([pscustomobject]$covInObj) | Out-Null

                    if ($Healthcheck -and $script:HealthCheck.Purview.RecordManagement) {
                        $CovObj | Where-Object { $_.'Record Labels Configured' -eq 'No' }      | Set-Style -Style Warning | Out-Null
                        $CovObj | Where-Object { $_.'Disposition Review Configured' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }

                    $CovTableParams = @{ Name = "Records Management Coverage - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    if ($script:Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" }
                    $CovObj | Table @CovTableParams
                    #endregion

                    #region All Labels Summary Table
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Label in $AllLabels) {
                        try {
                            $labelType = if ($Label.RegulatoryRecord) { 'Regulatory Record' } elseif ($Label.IsRecordLabel) { 'Record' } else { 'Retention' }
                            $retPeriod = if ($Label.RetentionDuration -and $Label.RetentionDurationDisplayHint) { "$($Label.RetentionDuration) $($Label.RetentionDurationDisplayHint)" } elseif ($Label.RetentionDuration) { $Label.RetentionDuration } else { '--' }
                                $_pre_DispositionReview_74 = if ($null -ne $Label.ReviewerEmail -and $Label.ReviewerEmail -ne '') { 'Yes' } else { 'No' }
                                $_pre_EventType_75 = if ($Label.EventType) { $Label.EventType } else { '--' }
                            $inObj = [ordered] @{
                                'Name'               = $Label.Name
                                'Type'               = $labelType
                                'Retention Action'   = $script:TextInfo.ToTitleCase($Label.RetentionAction)
                                'Retention Period'   = $retPeriod
                                'Disposition Review' = $_pre_DispositionReview_74
                                'Event Type' = $_pre_EventType_75
                                'Created'            = $Label.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Record Management Label '$($Label.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.RecordManagement) {
                        # Highlight regulatory records — highest scrutiny
                        $OutObj | Where-Object { $_.'Type' -eq 'Regulatory Record' } | Set-Style -Style Info | Out-Null
                    }

                    $TableParams = @{ Name = "Records Management Labels - $TenantId"; List = $false; ColumnWidths = 20, 15, 14, 16, 12, 14, 9 }
                    if ($script:Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                    #endregion

                    #region Per-Label Detail (InfoLevel 2+)
                    if ($script:InfoLevel.RecordManagement -ge 2) {
                        foreach ($Label in ($AllLabels | Sort-Object Name)) {
                            try {
                                Section -Style Heading4 $Label.Name {

                                    Paragraph "The $($Label.Name) retention/record label is configured as follows."
                                    BlankLine

                                    $lblLastMod = if ($Label.WhenChangedUTC) { $Label.WhenChangedUTC.ToString('yyyy-MM-dd') } else { '--' }
                                    $DetObj = [System.Collections.ArrayList]::new()
                                        $_pre_DisplayName_109 = if ($Label.DisplayName) { $Label.DisplayName } else { '--' }
                                        $_pre_RetentionPeriodDispl_113 = if ($Label.RetentionDurationDisplayHint) { $Label.RetentionDurationDisplayHint } else { '--' }
                                        $_pre_IsRecordLabel_115 = if ($Label.IsRecordLabel) { 'Yes' } else { 'No' }
                                        $_pre_RegulatoryRecord_116 = if ($Label.RegulatoryRecord) { 'Yes' } else { 'No' }
                                        $_pre_ReviewerEmails_118 = if ($Label.ReviewerEmail) { ($Label.ReviewerEmail -join ', ') } else { '--' }
                                        $_pre_EventType_119 = if ($Label.EventType) { $Label.EventType } else { '--' }
                                        $_pre_AutoLabelType_120 = if ($Label.AutoLabelType) { $Label.AutoLabelType } else { '--' }
                                        $_pre_ComplianceType_121 = if ($Label.ComplianceType) { $Label.ComplianceType } else { '--' }
                                        $_pre_FilePlanProperty_122 = if ($Label.FilePlanProperty) { $Label.FilePlanProperty } else { '--' }
                                        $_pre_Description_123 = if ($Label.Comment) { $Label.Comment } else { '--' }
                                        $_pre_CreatedBy_124 = if ($Label.CreatedBy) { $Label.CreatedBy } else { '--' }
                                        $_preDispReview = if ($Label.ReviewerEmail) { 'Yes' } else { 'No' }
                                    $detInObj = [ordered] @{
                                        'Name'                      = $Label.Name
                                        'Display Name' = $_pre_DisplayName_109
                                        'Type'                      = $labelType
                                        'Retention Action'          = $script:TextInfo.ToTitleCase($Label.RetentionAction)
                                        'Retention Duration'        = $Label.RetentionDuration
                                        'Retention Period Display' = $_pre_RetentionPeriodDispl_113
                                        'Retention Type'            = $script:TextInfo.ToTitleCase($Label.RetentionType)
                                        'Is Record Label' = $_pre_IsRecordLabel_115
                                        'Regulatory Record' = $_pre_RegulatoryRecord_116
                                        'Disposition Review'        = $_preDispReview
                                        'Reviewer Email(s)' = $_pre_ReviewerEmails_118
                                        'Event Type' = $_pre_EventType_119
                                        'Auto-Label Type' = $_pre_AutoLabelType_120
                                        'Compliance Type' = $_pre_ComplianceType_121
                                        'File Plan Property' = $_pre_FilePlanProperty_122
                                        'Description' = $_pre_Description_123
                                        'Created By' = $_pre_CreatedBy_124
                                        'Last Modified'             = $lblLastMod
                                    }
                                    $DetObj.Add([pscustomobject]$detInObj) | Out-Null

                                    $DetTableParams = @{ Name = "Label Detail - $($Label.Name)"; List = $true; ColumnWidths = 40, 60 }
                                    if ($script:Report.ShowTableCaptions) { $DetTableParams['Caption'] = "- $($DetTableParams.Name)" }
                                    $DetObj | Table @DetTableParams
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "Record Label Detail '$($Label.Name)': $($_.Exception.Message)" | Out-Null
                            }
                        }
                    }
                    #endregion
                }
            } else {
                Write-PScriboMessage -Message "No Retention/Record Label information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Records Management Section: $($_.Exception.Message)" | Out-Null
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Records Management'
    }
}
