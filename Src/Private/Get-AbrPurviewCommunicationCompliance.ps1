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
                             $_pre_Enabled_41 = if ($Policy.Enabled) { 'Yes' } else { 'No' }
                             $_pre_ReviewerEmails_43 = if ($Policy.ReviewerEmailAddresses) { ($Policy.ReviewerEmailAddresses -join ', ') } else { '--' }
                            $inObj = [ordered] @{
                             'Policy Name'         = $Policy.Name
                             'Enabled' = $_pre_Enabled_41
                             'Reviewers'           = ($Policy.Reviewers -join ', ')
                             'Reviewer Emails' = $_pre_ReviewerEmails_43
                             'Users'               = ($Policy.Users -join ', ')
                             'Groups'              = ($Policy.Groups -join ', ')
                             'Created'             = $Policy.WhenCreated.ToString('yyyy-MM-dd')
                             'Last Modified'       = $Policy.WhenChanged.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Communication Compliance Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.CommunicationCompliance) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                        # Flag policies scoped to specific users/groups rather than all users (MCCA check-CC102)
                        $OutObj | Where-Object {
                            ($_.'Users' -ne '' -and $_.'Users' -ne '--') -or
                            ($_.'Groups' -ne '' -and $_.'Groups' -ne '--')
                        } | Set-Style -Style Warning | Out-Null
                    }

                    $TableParams = @{
                        Name         = "Communication Compliance Policies - $TenantId"
                        List         = $false
                        ColumnWidths = 18, 8, 14, 16, 12, 12, 10, 10
                    }
                    if ($script:Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Policy Name' | Table @TableParams

                    #region Coverage summary and ACSC check (MCCA check-CC101 / CC102)
                    if ($script:InfoLevel.CommunicationCompliance -ge 3) {
                        $EnabledPolicies   = @($CCPolicies | Where-Object { $_.Enabled })
                        $OrgWidePolicies   = @($CCPolicies | Where-Object {
                            $_.Enabled -and
                            (-not $_.Users -or $_.Users.Count -eq 0) -and
                            (-not $_.Groups -or $_.Groups.Count -eq 0)
                        })
                        $_ccHasPolicy      = $EnabledPolicies.Count -gt 0
                        $_ccHasOrgWide     = $OrgWidePolicies.Count -gt 0

                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'Communication Compliance' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-1228'
                                E8          = 'N/A'
                                Description = 'Inappropriate and policy-violating communications detected'
                                Check       = 'At least one enabled Communication Compliance policy configured'
                                Status      = if ($_ccHasPolicy) { 'Pass' } else { 'Fail' }
                            },
                            [pscustomobject]@{
                                ControlId   = 'ISM-1228'
                                E8          = 'N/A'
                                Description = 'Communication Compliance policy covers entire organisation'
                                Check       = 'At least one policy is not scoped to specific users or groups only'
                                Status      = if ($_ccHasOrgWide) { 'Pass' } elseif ($_ccHasPolicy) { 'Partial' } else { 'Fail' }
                            }
                        )
                    }
                    #endregion

                    # Rules per policy
                    if ($script:InfoLevel.CommunicationCompliance -ge 2) {
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
                                       'Direction'         = $script:TextInfo.ToTitleCase($Rule.Direction)
                                      }
                                      $RuleObj.Add([pscustomobject]$ruleInObj) | Out-Null
                                     } catch {
                                      Write-PScriboMessage -IsWarning -Message "CC Rule '$($Rule.Name)': $($_.Exception.Message)" | Out-Null
                                     }
                                    }
                                    $RuleTableParams = @{
                                     Name         = "Communication Compliance Rules - $($Policy.Name)"
                                     List         = $false
                                     ColumnWidths = 28, 15, 42, 15
                                    }
                                    if ($script:Report.ShowTableCaptions) {
                                     $RuleTableParams['Caption'] = "- $($RuleTableParams.Name)"
                                    }
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
