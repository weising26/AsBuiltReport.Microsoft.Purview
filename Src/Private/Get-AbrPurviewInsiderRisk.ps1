function Get-AbrPurviewInsiderRisk {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Insider Risk Management information.
    .DESCRIPTION
        Collects and reports on Insider Risk Management policies configured in
        Microsoft Purview, using the Microsoft Graph API.
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
        Write-PScriboMessage -Message "Collecting Microsoft Purview Insider Risk Management information for tenant $TenantId." | Out-Null
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Insider Risk'
    }

    process {
        # Check Graph is connected before attempting API calls
        if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
            Write-PScriboMessage -IsWarning -Message "Skipping Insider Risk section: No active Microsoft Graph session." | Out-Null
            return
        }

        try {
            # Insider Risk policies via Security & Compliance PowerShell
            $InsiderRiskPolicies = @(Get-InsiderRiskPolicy -ErrorAction SilentlyContinue)

            if ($InsiderRiskPolicies) {
                Section -Style Heading3 'Insider Risk Management Policies' {

                    #region Coverage flags pre-scan
                    # InsiderRiskScenario real enum values:
                    # IntellectualPropertyTheft, DepartingEmployeeSPV, LeakOfInformation,
                    # DisgruntledEmployeeDataLeak, HighValueEmployeeDataLeak, SecurityPolicyViolation,
                    # WorkplaceThreat, RiskyAIUsage etc.
                    $HasDataTheftPolicy = $InsiderRiskPolicies | Where-Object { $_.InsiderRiskScenario -match 'Theft|DepartingEmployeeSPV|HighValueEmployee' }
                    $HasDataLeakPolicy  = $InsiderRiskPolicies | Where-Object { $_.InsiderRiskScenario -match 'LeakOfInformation|DataLeak|UnacceptableUsage' }
                    # TenantSettings contains anonymization config as a JSON string
                    $HasAnonymization   = $InsiderRiskPolicies | Where-Object { $_.TenantSettings -match 'Anonymization' }

                    $CovObj = [System.Collections.ArrayList]::new()
                        $_pre_PoliciesConfigured_52 = if ($InsiderRiskPolicies.Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_DataTheftPolicy_53 = if ($null -ne $HasDataTheftPolicy) { 'Yes' } else { 'No' }
                        $_pre_DataLeakPolicy_54 = if ($null -ne $HasDataLeakPolicy) { 'Yes' } else { 'No' }
                        $_pre_AnonymizationEnabled_55 = if ($null -ne $HasAnonymization) { 'Yes' } else { 'No' }
                    $covInObj = [ordered] @{
                        'Policies Configured' = $_pre_PoliciesConfigured_52
                        'Data Theft Policy' = $_pre_DataTheftPolicy_53
                        'Data Leak Policy' = $_pre_DataLeakPolicy_54
                        'Anonymization Enabled' = $_pre_AnonymizationEnabled_55
                    }
                    $CovObj.Add([pscustomobject]$covInObj) | Out-Null

                    if ($Healthcheck -and $script:HealthCheck.Purview.InsiderRisk) {
                        $CovObj | Where-Object { $_.'Policies Configured' -eq 'No' } | Set-Style -Style Critical | Out-Null
                        $CovObj | Where-Object { $_.'Anonymization Enabled' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }

                    $CovTableParams = @{ Name = "Insider Risk Coverage - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    if ($script:Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" }
                    $CovObj | Table @CovTableParams
                    #endregion

                    $OutObj = [System.Collections.ArrayList]::new()

                    # Filter out internal TenantSetting objects - only show real policies
                    $ActualPolicies = $InsiderRiskPolicies | Where-Object { $_.InsiderRiskScenario -ne 'TenantSetting' -and $_.Type -ne 'TenantSetting' }

                    foreach ($Policy in $ActualPolicies) {
                        try {
                            $irmCreated  = if ($Policy.WhenCreatedUTC) { $Policy.WhenCreatedUTC.ToString('yyyy-MM-dd') } else { 'N/A' }
                            $irmModified = if ($Policy.WhenChangedUTC) { $Policy.WhenChangedUTC.ToString('yyyy-MM-dd') } else { 'N/A' }
                            $_pre_Anonymized_83 = if ($Policy.TenantSettings -match 'Anonymization.*true') { 'Yes' } else { 'No' }
                            $inObj = [ordered] @{
                                'Policy Name'   = $Policy.Name
                                'Scenario'      = $Policy.InsiderRiskScenario
                                'Status'        = if ($Policy.Enabled) { 'Enabled' } else { 'Disabled' }
                                'Mode'          = $Policy.Mode
                                'Anonymized'    = $_pre_Anonymized_83
                                'Created'       = $irmCreated
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Insider Risk Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.InsiderRisk) {
                        $OutObj | Where-Object { $_.'Status' -ne 'Enabled' } | Set-Style -Style Warning | Out-Null
                    }

                    $TableParams = @{
                        Name         = "Insider Risk Policies - $TenantId"
                        List         = $false
                        ColumnWidths = 24, 24, 10, 12, 12, 18
                    }
                    if ($script:Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Policy Name' | Table @TableParams

                    #region ACSC Inline Check — Insider Risk Policies
                    if ($script:InfoLevel.InsiderRisk -ge 3) {
                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'Insider Risk Policies' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-1228'
                                E8          = 'E8 ML2, ML3'
                                Description = 'Cyber security events analysed to identify incidents'
                                Check       = 'Insider Risk Management policies configured to detect anomalous behaviour'
                                Status      = if ($InsiderRiskPolicies.Count -gt 0) { 'Pass' } else { 'Fail' }
                            }
                        )
                    }
                    #endregion
                }
            } else {
                Write-PScriboMessage -Message "No Insider Risk Policy information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Insider Risk Policy Section: $($_.Exception.Message)" | Out-Null
        }


        # Insider Risk Global Settings have no public PowerShell cmdlet.
        # Settings are only configurable via the Microsoft Purview portal.
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Insider Risk'
    }
}
