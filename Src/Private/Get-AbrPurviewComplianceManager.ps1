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
        # Compliance Manager assessments/scores have no public Graph or PowerShell API.
        # We surface Microsoft Secure Score (Graph v1.0) as a related posture indicator.

        try {
            if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
                Write-PScriboMessage -IsWarning -Message "Skipping Secure Score: No active Microsoft Graph session." | Out-Null
            } else {
                $SecureScoreResp = Invoke-MgGraphRequest `
                    -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1" `
                    -Method GET -ErrorAction SilentlyContinue -SkipHttpErrorCheck

                $Score = if ($SecureScoreResp -and -not $SecureScoreResp.error) {
                    $SecureScoreResp.value | Select-Object -First 1
                } else { $null }

                Section -Style Heading3 'Microsoft Secure Score & Compliance Manager' {
                    if ($Score) {
                        $scoreDate = if ($Score.createdDateTime) { ([datetime]$Score.createdDateTime).ToString('yyyy-MM-dd') } else { 'N/A' }
                        $scorePct  = if ($Score.maxScore -gt 0) { "$([math]::Round(($Score.currentScore / $Score.maxScore) * 100, 1))%" } else { 'N/A' }
                        $allTenantsAvg = $Score.averageComparativeScores | Where-Object { $_.basis -eq 'allTenants' }
                        $avgScore = if ($allTenantsAvg) { "$($allTenantsAvg.averageScore) (all tenants avg)" } else { 'N/A' }

                        $scoreInObj = [ordered] @{
                            'Current Score'    = "$($Score.currentScore) / $($Score.maxScore)"
                            'Score Percentage' = $scorePct
                            'All Tenants Avg'  = $avgScore
                            'As Of'            = $scoreDate
                        }
                        $ScoreObj = [System.Collections.ArrayList]::new()
                        $ScoreObj.Add([pscustomobject]$scoreInObj) | Out-Null

                        if ($Healthcheck -and $script:HealthCheck.Purview.ComplianceManager) {
                            $ScoreObj | Where-Object {
                                $_pre_pct = $_."Score Percentage" -replace "%",""; $_pre_pct -ne "N/A" -and [double]$_pre_pct -lt 50
                            } | Set-Style -Style Critical | Out-Null
                            $ScoreObj | Where-Object {
                                $_pre_pct = $_."Score Percentage" -replace "%",""; $_pre_pct -ne "N/A" -and [double]$_pre_pct -lt 75 -and [double]$_pre_pct -ge 50
                            } | Set-Style -Style Warning | Out-Null
                        }

                        $ScoreTableParams = @{ Name = "Microsoft Secure Score - $TenantId"; List = $true; ColumnWidths = 40, 60 }
                        if ($script:Report.ShowTableCaptions) { $ScoreTableParams["Caption"] = "- $($ScoreTableParams.Name)" }
                        $ScoreObj | Table @ScoreTableParams
                        BlankLine
                    }
                    Paragraph "Note: Compliance Manager assessment scores and improvement actions are not available via a public API. Review your full compliance posture at: https://purview.microsoft.com/compliancemanager/"
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Compliance Manager Section: $($_.Exception.Message)" | Out-Null
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Compliance Manager'
    }
}
