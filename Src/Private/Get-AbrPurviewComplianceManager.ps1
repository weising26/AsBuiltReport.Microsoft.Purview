function Get-AbrPurviewComplianceManager {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Compliance Manager information.
    .DESCRIPTION
        Collects and reports on Compliance Manager assessments and improvement actions
        via the Microsoft Graph API.
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
        Write-PScriboMessage -Message "Collecting Microsoft Purview Compliance Manager information for tenant $TenantId." | Out-Null
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Compliance Manager'
    }

    process {
        # Compliance Manager Assessments via Graph
        # Check Graph is connected before attempting API calls
        if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
            Write-PScriboMessage -IsWarning -Message "Skipping Compliance Manager section: No active Microsoft Graph session." | Out-Null
            return
        }

        try {
            $Uri = "https://graph.microsoft.com/beta/compliance/complianceManager/assessments"
            $Response = Invoke-MgGraphRequest -Uri $Uri -Method GET -ErrorAction Stop
            $Assessments = $Response.value

            if ($Assessments) {
                Section -Style Heading3 'Compliance Manager Assessments' {
                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Assessment in $Assessments) {
                        try {
                            $inObj = [ordered] @{
                                'Assessment Name'       = $Assessment.displayName
                                'Status'                = $TextInfo.ToTitleCase($Assessment.status)
                                'Compliance Score'      = "$($Assessment.complianceScore)%"
                                'In Scope Services'     = ($Assessment.inScopeServices -join ', ')
                                'Created'               = if ($Assessment.createdDateTime) { ([datetime]$Assessment.createdDateTime).ToString('yyyy-MM-dd') } else { 'N/A' }
                                'Last Modified'         = if ($Assessment.lastModifiedDateTime) { ([datetime]$Assessment.lastModifiedDateTime).ToString('yyyy-MM-dd') } else { 'N/A' }
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Compliance Assessment '$($Assessment.displayName)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.ComplianceManager) {
                        $OutObj | Where-Object { [int]($_..'Compliance Score' -replace '%', '') -lt 50 } | Set-Style -Style Critical | Out-Null
                        $OutObj | Where-Object { [int]($_..'Compliance Score' -replace '%', '') -lt 75 -and [int]($_..'Compliance Score' -replace '%', '') -ge 50 } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $TableParams = @{
                        Name         = "Compliance Manager Assessments - $TenantId"
                        List         = $false
                        ColumnWidths = 25, 12, 14, 23, 13, 13
                    }
                    $null = (& {
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    })
                    $OutObj | Sort-Object -Property 'Compliance Score' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Compliance Manager Assessment information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Compliance Manager Section: $($_.Exception.Message)" | Out-Null
        }

        # Improvement Actions Summary
        try {
            $ActionsUri = "https://graph.microsoft.com/beta/compliance/complianceManager/improvementActions?`$top=50&`$orderby=score desc"
            $ActionsResponse = Invoke-MgGraphRequest -Uri $ActionsUri -Method GET -ErrorAction Stop
            $ImprovementActions = $ActionsResponse.value

            if ($ImprovementActions) {
                Section -Style Heading3 'Top Improvement Actions' {
                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Action in $ImprovementActions) {
                        try {
                            $inObj = [ordered] @{
                                'Action Name'       = $Action.displayName
                                'Status'            = $TextInfo.ToTitleCase($Action.implementationStatus)
                                'Score'             = $Action.score
                                'Max Score'         = $Action.maxScore
                                'Category'          = $TextInfo.ToTitleCase($Action.actionType)
                                'Control Category'  = $Action.controlCategory
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Improvement Action '$($Action.displayName)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.ComplianceManager) {
                        $OutObj | Where-Object { $_.'Status' -eq 'NotImplemented' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $TableParams = @{
                        Name         = "Top Improvement Actions - $TenantId"
                        List         = $false
                        ColumnWidths = 30, 15, 10, 10, 17, 18
                    }
                    $null = (& {
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    })
                    $OutObj | Sort-Object -Property 'Score' -Descending | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Improvement Action information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Improvement Actions Section: $($_.Exception.Message)" | Out-Null
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Compliance Manager'
    }
}
