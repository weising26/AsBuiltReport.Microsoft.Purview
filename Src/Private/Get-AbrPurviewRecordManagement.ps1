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
                    $covInObj = [ordered] @{
                        'Record Labels Configured'           = ($null -ne $RecordLabels)
                        'Regulatory Records Configured'      = ($null -ne $RegulatoryLabels)
                        'Disposition Review Configured'      = ($null -ne $DispositionLabels)
                        'Event-Based Retention Configured'   = ($null -ne $EventLabels)
                    }
                    $CovObj.Add([pscustomobject](ConvertTo-HashToYN $covInObj)) | Out-Null

                    $null = (& {
                    if ($HealthCheck.Purview.Retention) {
                        $CovObj | Where-Object { $_.'Record Labels Configured' -eq 'No' }      | Set-Style -Style Warning | Out-Null
                        $CovObj | Where-Object { $_.'Disposition Review Configured' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $CovTableParams = @{ Name = "Records Management Coverage - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    $null = (& { if ($Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" } })
                    $CovObj | Table @CovTableParams
                    #endregion

                    #region All Labels Summary Table
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Label in $AllLabels) {
                        try {
                            $inObj = [ordered] @{
                                'Name'               = $Label.Name
                                'Type'               = if ($Label.RegulatoryRecord) { 'Regulatory Record' } elseif ($Label.IsRecordLabel) { 'Record' } else { 'Retention' }
                                'Retention Action'   = $TextInfo.ToTitleCase($Label.RetentionAction)
                                'Retention Period'   = if ($Label.RetentionDuration -and $Label.RetentionDurationDisplayHint) {
                                                           "$($Label.RetentionDuration) $($Label.RetentionDurationDisplayHint)"
                                                       } elseif ($Label.RetentionDuration) {
                                                           $Label.RetentionDuration
                                                       } else { '--' }
                                'Disposition Review' = ($null -ne $Label.ReviewerEmail -and $Label.ReviewerEmail -ne '')
                                'Event Type'         = if ($Label.EventType) { $Label.EventType } else { '--' }
                                'Created'            = $Label.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Record Management Label '$($Label.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.Retention) {
                        # Highlight regulatory records — highest scrutiny
                        $OutObj | Where-Object { $_.'Type' -eq 'Regulatory Record' } | Set-Style -Style Info | Out-Null
                    }
                    })

                    $TableParams = @{ Name = "Records Management Labels - $TenantId"; List = $false; ColumnWidths = 20, 15, 14, 16, 12, 14, 9 }
                    $null = (& { if ($Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" } })
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                    #endregion

                    #region Per-Label Detail (InfoLevel 2+)
                    if ($InfoLevel.Retention -ge 2) {
                        foreach ($Label in ($AllLabels | Sort-Object Name)) {
                            try {
                                Section -Style Heading4 $Label.Name {

                                    Paragraph "Logicalis implemented the $($Label.Name) retention/record label with the following configuration."
                                    BlankLine

                                    $DetObj = [System.Collections.ArrayList]::new()
                                    $detInObj = [ordered] @{
                                        'Name'                      = $Label.Name
                                        'Display Name'              = if ($Label.DisplayName) { $Label.DisplayName } else { '--' }
                                        'Type'                      = if ($Label.RegulatoryRecord) { 'Regulatory Record' } elseif ($Label.IsRecordLabel) { 'Record' } else { 'Retention' }
                                        'Retention Action'          = $TextInfo.ToTitleCase($Label.RetentionAction)
                                        'Retention Duration'        = $Label.RetentionDuration
                                        'Retention Period Display'  = if ($Label.RetentionDurationDisplayHint) { $Label.RetentionDurationDisplayHint } else { '--' }
                                        'Retention Type'            = $TextInfo.ToTitleCase($Label.RetentionType)
                                        'Is Record Label'           = $Label.IsRecordLabel
                                        'Regulatory Record'         = $Label.RegulatoryRecord
                                        'Disposition Review'        = ($null -ne $Label.ReviewerEmail -and $Label.ReviewerEmail -ne '')
                                        'Reviewer Email(s)'         = if ($Label.ReviewerEmail) { ($Label.ReviewerEmail -join ', ') } else { '--' }
                                        'Event Type'                = if ($Label.EventType) { $Label.EventType } else { '--' }
                                        'Auto-Label Type'           = if ($Label.AutoLabelType) { $Label.AutoLabelType } else { '--' }
                                        'Compliance Type'           = if ($Label.ComplianceType) { $Label.ComplianceType } else { '--' }
                                        'File Plan Property'        = if ($Label.FilePlanProperty) { $Label.FilePlanProperty } else { '--' }
                                        'Description'               = if ($Label.Comment) { $Label.Comment } else { '--' }
                                        'Created By'                = if ($Label.CreatedBy) { $Label.CreatedBy } else { '--' }
                                        'Last Modified'             = if ($Label.WhenChangedUTC) { $Label.WhenChangedUTC.ToString('yyyy-MM-dd') } else { '--' }
                                    }
                                    $DetObj.Add([pscustomobject](ConvertTo-HashToYN $detInObj)) | Out-Null

                                    $DetTableParams = @{ Name = "Label Detail - $($Label.Name)"; List = $true; ColumnWidths = 40, 60 }
                                    $null = (& { if ($Report.ShowTableCaptions) { $DetTableParams['Caption'] = "- $($DetTableParams.Name)" } })
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
