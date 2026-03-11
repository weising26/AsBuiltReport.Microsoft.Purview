function Get-AbrPurviewCommunicationCompliance {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Communication Compliance information.
    .DESCRIPTION
        Collects and reports on Communication Compliance policies configured in
        Microsoft Purview, including supervised users and reviewers.
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
        Write-PScriboMessage -Message "Collecting Microsoft Purview Communication Compliance information for tenant $TenantId." | Out-Null
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Communication Compliance'
    }

    process {
        try {
            $CCPolicies = Get-SupervisoryReviewPolicyV2 -ErrorAction Stop

            if ($CCPolicies) {
                Section -Style Heading3 'Communication Compliance Policies' {
                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Policy in $CCPolicies) {
                        try {
                            $inObj = [ordered] @{
                                'Policy Name'         = $Policy.Name
                                'Enabled'             = $Policy.Enabled
                                'Reviewers'           = ($Policy.Reviewers -join ', ')
                                'Reviewer Emails'     = if ($Policy.ReviewerEmailAddresses) { ($Policy.ReviewerEmailAddresses -join ', ') } else { '--' }
                                'Users'               = ($Policy.Users -join ', ')
                                'Groups'              = ($Policy.Groups -join ', ')
                                'Created'             = $Policy.WhenCreated.ToString('yyyy-MM-dd')
                                'Last Modified'       = $Policy.WhenChanged.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Communication Compliance Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.CommunicationCompliance) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                    }
                    })

                    $TableParams = @{
                        Name         = "Communication Compliance Policies - $TenantId"
                        List         = $false
                        ColumnWidths = 18, 8, 14, 16, 12, 12, 10, 10
                    }
                    $null = (& {
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    })
                    $OutObj | Sort-Object -Property 'Policy Name' | Table @TableParams

                    # Rules per policy
                    if ($InfoLevel.CommunicationCompliance -ge 2) {
                        foreach ($Policy in $CCPolicies) {
                                                try {
                                                    $Rules = Get-SupervisoryReviewRule -Policy $Policy.Name -ErrorAction SilentlyContinue
                                                    if ($Rules) {
                                                        Section -ExcludeFromTOC -Style NOTOCHeading4 "Rules: $($Policy.Name)" {
                                                            $RuleObj = [System.Collections.ArrayList]::new()
                                                            foreach ($Rule in $Rules) {
                                                                try {
                                                                    $ruleInObj = [ordered] @{
                                                                        'Rule Name'         = $Rule.Name
                                                                        'Sample Rate (%)'   = $Rule.SamplingRate
                                                                        'Condition'         = $Rule.Condition
                                                                        'Direction'         = $TextInfo.ToTitleCase($Rule.Direction)
                                                                    }
                                                                    $RuleObj.Add([pscustomobject](ConvertTo-HashToYN $ruleInObj)) | Out-Null
                                                                } catch {
                                                                    Write-PScriboMessage -IsWarning -Message "CC Rule '$($Rule.Name)': $($_.Exception.Message)" | Out-Null
                                                                }
                                                            }
                                                            $RuleTableParams = @{
                                                                Name         = "Communication Compliance Rules - $($Policy.Name)"
                                                                List         = $false
                                                                ColumnWidths = 28, 15, 42, 15
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
                                                    Write-PScriboMessage -IsWarning -Message "CC Rules for '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                                                }
                                            }
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Communication Compliance Policy information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Communication Compliance Section: $($_.Exception.Message)" | Out-Null
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Communication Compliance'
    }
}
