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
                    $covInObj = [ordered] @{
                        'Retention Policies Configured'    = ($RetentionPolicies.Count -gt 0)
                        'Has Preservation Lock Policy'     = ($null -ne $HasPreservationLock)
                        'Uses Adaptive Scopes'             = ($null -ne $HasAdaptiveScope)
                    }
                    $CovObj.Add([pscustomobject](ConvertTo-HashToYN $covInObj)) | Out-Null

                    $null = (& {
                    if ($HealthCheck.Purview.Retention) {
                        $CovObj | Where-Object { $_.'Retention Policies Configured' -eq 'No' } | Set-Style -Style Critical | Out-Null
                    }
                    })

                    $CovTableParams = @{ Name = "Retention Coverage Summary - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    $null = (& { if ($Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" } })
                    $CovObj | Table @CovTableParams
                    #endregion

                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Policy in $RetentionPolicies) {
                        try {
                            $inObj = [ordered] @{
                                'Name'              = $Policy.Name
                                'Enabled'           = $Policy.Enabled
                                'Retention Action'  = $TextInfo.ToTitleCase($Policy.RetentionAction)
                                'Retention Duration'= $Policy.RetentionDuration
                                'Workload'          = ($Policy.Workload -join ', ')
                                'Adaptive Scope'    = $Policy.AdaptiveScopeLocation
                                'Preservation Lock' = $Policy.RestrictiveRetention
                                'Created'           = $Policy.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Retention Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.Retention) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                    }
                    })

                    $TableParams = @{
                        Name         = "Retention Policies - $TenantId"
                        List         = $false
                        ColumnWidths = 18, 8, 13, 13, 16, 10, 12, 10
                    }
                    $null = (& {
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    })
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams

                    # Retention Rules per policy
                    if ($InfoLevel.Retention -ge 2) {
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
                                                                        'Retention Action'    = $TextInfo.ToTitleCase($Rule.RetentionComplianceAction)
                                                                        'Content Match Query' = $Rule.ContentMatchQuery
                                                                    }
                                                                    $RuleObj.Add([pscustomobject](ConvertTo-HashToYN $ruleInObj)) | Out-Null
                                                                } catch {
                                                                    Write-PScriboMessage -IsWarning -Message "Retention Rule '$($Rule.Name)': $($_.Exception.Message)" | Out-Null
                                                                }
                                                            }
                                                            $RuleTableParams = @{
                                                                Name         = "Retention Rules - $($Policy.Name)"
                                                                List         = $false
                                                                ColumnWidths = 28, 18, 18, 36
                                                            }
                                                            $null = (& {
                                                            if ($Report.ShowTableCaptions) {
                                                                $RuleTableParams['Caption'] = "- $($RuleTableParams.Name)"
                                                            }
                                                            })
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
                    $labelCovInObj = [ordered] @{
                        'Retention Labels Configured'    = ($RetentionLabels.Count -gt 0)
                        'Record Labels Configured'       = ($null -ne $HasRecordLabels)
                        'Regulatory Records Configured'  = ($null -ne $HasRegulatoryRecords)
                        'Disposition Review Configured'  = ($null -ne $HasDispositionReview)
                        'Event-Based Retention Labels'   = ($null -ne $HasEventBasedLabels)
                    }
                    $LabelCovObj.Add([pscustomobject](ConvertTo-HashToYN $labelCovInObj)) | Out-Null

                    $null = (& {
                    if ($HealthCheck.Purview.Retention) {
                        $LabelCovObj | Where-Object { $_.'Retention Labels Configured' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $LabelCovTableParams = @{ Name = "Retention Label Coverage - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    $null = (& { if ($Report.ShowTableCaptions) { $LabelCovTableParams['Caption'] = "- $($LabelCovTableParams.Name)" } })
                    $LabelCovObj | Table @LabelCovTableParams
                    #endregion

                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Label in $RetentionLabels) {
                        try {
                            $inObj = [ordered] @{
                                'Name'               = $Label.Name
                                'Retention Action'   = $TextInfo.ToTitleCase($Label.RetentionAction)
                                'Retention Duration' = $Label.RetentionDuration
                                'Retention Type'     = $TextInfo.ToTitleCase($Label.RetentionType)
                                'Record Label'       = $Label.IsRecordLabel
                                'Regulatory'         = $Label.RegulatoryRecord
                                'Disposition Review' = ($null -ne $Label.ReviewerEmail -and $Label.ReviewerEmail -ne '')
                                'Event Type'         = if ($Label.EventType) { $Label.EventType } else { '--' }
                                'Created'            = $Label.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Retention Label '$($Label.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $TableParams = @{
                        Name         = "Retention Labels - $TenantId"
                        List         = $false
                        ColumnWidths = 18, 13, 13, 12, 9, 10, 10, 8, 7
                    }
                    $null = (& {
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    })
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Retention Label information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Retention Label Section: $($_.Exception.Message)" | Out-Null
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Retention Policies'
    }
}
