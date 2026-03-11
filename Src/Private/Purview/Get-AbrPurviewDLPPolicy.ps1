function Get-AbrPurviewDLPPolicy {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview DLP Policy information.
    .DESCRIPTION
        Collects and reports on Data Loss Prevention policies configured in Microsoft Purview,
        including policy mode, workloads covered, and enabled state.
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
        Write-PScriboMessage -Message "Collecting Microsoft Purview DLP Policy information for tenant $TenantId."
        Show-AbrDebugExecutionTime -Start -TitleMessage 'DLP Policies'
    }

    process {
        try {
            $DLPPolicies = Get-DlpCompliancePolicy -ErrorAction Stop

            if ($DLPPolicies) {
                Section -Style Heading3 'Data Loss Prevention Policies' {
                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Policy in $DLPPolicies) {
                        try {
                            $inObj = [ordered] @{
                                'Name'          = $Policy.Name
                                'Mode'          = $TextInfo.ToTitleCase($Policy.Mode)
                                'Enabled'       = $Policy.Enabled
                                'Workload'      = ($Policy.Workload -join ', ')
                                'Created'       = $Policy.WhenCreated.ToString('yyyy-MM-dd')
                                'Last Modified' = $Policy.WhenChanged.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "DLP Policy '$($Policy.Name)': $($_.Exception.Message)"
                        }
                    }

                    if ($HealthCheck.Purview.DLP) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical
                        $OutObj | Where-Object { $_.'Mode' -ne 'Enforce' } | Set-Style -Style Warning
                    }

                    $TableParams = @{
                        Name         = "DLP Policies - $TenantId"
                        List         = $false
                        ColumnWidths = 25, 12, 10, 25, 14, 14
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams

                    # DLP Policy Rules sub-section
                    foreach ($Policy in $DLPPolicies) {
                        try {
                            $DLPRules = Get-DlpComplianceRule -Policy $Policy.Name -ErrorAction SilentlyContinue
                            if ($DLPRules) {
                                Section -ExcludeFromTOC -Style NOTOCHeading4 "Rules: $($Policy.Name)" {
                                    $RuleObj = [System.Collections.ArrayList]::new()
                                    foreach ($Rule in $DLPRules) {
                                        try {
                                            $ruleInObj = [ordered] @{
                                                'Rule Name'          = $Rule.Name
                                                'Disabled'           = $Rule.Disabled
                                                'Severity'           = $TextInfo.ToTitleCase($Rule.ReportSeverityLevel)
                                                'Block Access'       = $Rule.BlockAccess
                                                'Notify User'        = ($Rule.NotifyUser -join ', ')
                                            }
                                            $RuleObj.Add([pscustomobject](ConvertTo-HashToYN $ruleInObj)) | Out-Null
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "DLP Rule '$($Rule.Name)': $($_.Exception.Message)"
                                        }
                                    }
                                    if ($HealthCheck.Purview.DLP) {
                                        $RuleObj | Where-Object { $_.'Disabled' -eq 'Yes' } | Set-Style -Style Warning
                                    }
                                    $RuleTableParams = @{
                                        Name         = "DLP Rules - $($Policy.Name)"
                                        List         = $false
                                        ColumnWidths = 30, 12, 15, 15, 28
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $RuleTableParams['Caption'] = "- $($RuleTableParams.Name)"
                                    }
                                    $RuleObj | Sort-Object -Property 'Rule Name' | Table @RuleTableParams
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "DLP Rules for '$($Policy.Name)': $($_.Exception.Message)"
                        }
                    }
                }
            } else {
                Write-PScriboMessage -Message "No DLP Policy information found for $TenantId. Disabling section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "DLP Policy Section: $($_.Exception.Message)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'DLP Policies'
    }
}