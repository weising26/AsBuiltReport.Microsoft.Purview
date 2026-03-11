function Get-AbrPurviewRetentionPolicy {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Retention Policy information.
    .DESCRIPTION
        Collects and reports on Retention Policies and Retention Labels configured
        in Microsoft Purview, including retention durations and actions.
    .NOTES
        Version:        0.1.0
        Author:         Jonathan Colon
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
        Write-PScriboMessage -Message "Collecting Microsoft Purview Retention Policy information for tenant $TenantId."
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Retention Policies'
    }

    process {
        # Retention Policies
        try {
            $RetentionPolicies = Get-RetentionCompliancePolicy -ErrorAction Stop

            if ($RetentionPolicies) {
                Section -Style Heading3 'Retention Policies' {
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
                                'Created'           = $Policy.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Retention Policy '$($Policy.Name)': $($_.Exception.Message)"
                        }
                    }

                    if ($HealthCheck.Purview.Retention) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical
                    }

                    $TableParams = @{
                        Name         = "Retention Policies - $TenantId"
                        List         = $false
                        ColumnWidths = 20, 10, 15, 15, 18, 12, 10
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams

                    # Retention Rules per policy
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
                                            Write-PScriboMessage -IsWarning -Message "Retention Rule '$($Rule.Name)': $($_.Exception.Message)"
                                        }
                                    }
                                    $RuleTableParams = @{
                                        Name         = "Retention Rules - $($Policy.Name)"
                                        List         = $false
                                        ColumnWidths = 28, 18, 18, 36
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $RuleTableParams['Caption'] = "- $($RuleTableParams.Name)"
                                    }
                                    $RuleObj | Sort-Object -Property 'Rule Name' | Table @RuleTableParams
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Retention Rules for '$($Policy.Name)': $($_.Exception.Message)"
                        }
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Retention Policy information found for $TenantId. Disabling section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Retention Policy Section: $($_.Exception.Message)"
        }

        # Retention Labels
        try {
            $RetentionLabels = Get-ComplianceTag -ErrorAction Stop

            if ($RetentionLabels) {
                Section -Style Heading3 'Retention Labels' {
                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Label in $RetentionLabels) {
                        try {
                            $inObj = [ordered] @{
                                'Name'              = $Label.Name
                                'Retention Action'  = $TextInfo.ToTitleCase($Label.RetentionAction)
                                'Retention Duration'= $Label.RetentionDuration
                                'Retention Type'    = $TextInfo.ToTitleCase($Label.RetentionType)
                                'Record Label'      = $Label.IsRecordLabel
                                'Regulatory'        = $Label.IsRecordUnlockedAsDefault
                                'Created'           = $Label.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Retention Label '$($Label.Name)': $($_.Exception.Message)"
                        }
                    }

                    $TableParams = @{
                        Name         = "Retention Labels - $TenantId"
                        List         = $false
                        ColumnWidths = 22, 15, 15, 15, 11, 12, 10
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Retention Label information found for $TenantId. Disabling section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Retention Label Section: $($_.Exception.Message)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Retention Policies'
    }
}