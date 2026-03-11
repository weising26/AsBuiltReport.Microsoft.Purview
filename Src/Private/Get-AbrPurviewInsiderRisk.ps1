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
            # Insider Risk policies are available via Graph API beta endpoint
            $Uri = "https://graph.microsoft.com/beta/security/insiderRiskPolicies"
            $Response = Invoke-MgGraphRequest -Uri $Uri -Method GET -ErrorAction Stop
            $InsiderRiskPolicies = $Response.value

            if ($InsiderRiskPolicies) {
                Section -Style Heading3 'Insider Risk Management Policies' {

                    #region Coverage flags pre-scan
                    $HasDataTheftPolicy = $InsiderRiskPolicies | Where-Object { $_.policyTemplate -match 'DataTheft|Theft' }
                    $HasDataLeakPolicy  = $InsiderRiskPolicies | Where-Object { $_.policyTemplate -match 'DataLeak|Leak' }
                    $HasAnonymization   = $InsiderRiskPolicies | Where-Object { $_.anonymizationEnabled -eq $true }

                    $CovObj = [System.Collections.ArrayList]::new()
                    $covInObj = [ordered] @{
                        'Policies Configured'           = ($InsiderRiskPolicies.Count -gt 0)
                        'Data Theft Policy'             = ($null -ne $HasDataTheftPolicy)
                        'Data Leak Policy'              = ($null -ne $HasDataLeakPolicy)
                        'Anonymization Enabled'         = ($null -ne $HasAnonymization)
                    }
                    $CovObj.Add([pscustomobject](ConvertTo-HashToYN $covInObj)) | Out-Null

                    $null = (& {
                    if ($HealthCheck.Purview.InsiderRisk) {
                        $CovObj | Where-Object { $_.'Policies Configured' -eq 'No' } | Set-Style -Style Critical | Out-Null
                        $CovObj | Where-Object { $_.'Anonymization Enabled' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $CovTableParams = @{ Name = "Insider Risk Coverage - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    $null = (& { if ($Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" } })
                    $CovObj | Table @CovTableParams
                    #endregion

                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Policy in $InsiderRiskPolicies) {
                        try {
                            $inObj = [ordered] @{
                                'Policy Name'   = $Policy.displayName
                                'Status'        = $TextInfo.ToTitleCase($Policy.status)
                                'Policy Type'   = $TextInfo.ToTitleCase($Policy.policyTemplate)
                                'Anonymized'    = if ($Policy.anonymizationEnabled) { $Policy.anonymizationEnabled } else { $false }
                                'Created'       = if ($Policy.createdDateTime) { ([datetime]$Policy.createdDateTime).ToString('yyyy-MM-dd') } else { 'N/A' }
                                'Last Modified' = if ($Policy.lastModifiedDateTime) { ([datetime]$Policy.lastModifiedDateTime).ToString('yyyy-MM-dd') } else { 'N/A' }
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Insider Risk Policy '$($Policy.displayName)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.InsiderRisk) {
                        $OutObj | Where-Object { $_.'Status' -ne 'Enabled' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $TableParams = @{
                        Name         = "Insider Risk Policies - $TenantId"
                        List         = $false
                        ColumnWidths = 25, 12, 22, 12, 14, 15
                    }
                    $null = (& {
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    })
                    $OutObj | Sort-Object -Property 'Policy Name' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Insider Risk Policy information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Insider Risk Policy Section: $($_.Exception.Message)" | Out-Null
        }

        # Insider Risk Global Settings
        try {
            $SettingsUri = "https://graph.microsoft.com/beta/security/insiderRiskSettings"
            $Settings = Invoke-MgGraphRequest -Uri $SettingsUri -Method GET -ErrorAction Stop

            if ($Settings) {
                Section -Style Heading3 'Insider Risk Global Settings' {
                    $OutObj = [System.Collections.ArrayList]::new()
                    try {
                        $inObj = [ordered] @{
                            'Analytics Enabled'                = $Settings.analyticsEnabled
                            'Privacy Mode'                     = $TextInfo.ToTitleCase($Settings.privacyMode)
                            'Alert Volume'                     = $TextInfo.ToTitleCase($Settings.alertVolume)
                            'Microsoft Defender Integration'   = $Settings.microsoftDefenderForEndpointIntegrationEnabled
                            'Office Apps Indicators'           = $Settings.officeAppsIndicatorsEnabled
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "Insider Risk Settings: $($_.Exception.Message)" | Out-Null
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.InsiderRisk) {
                        $OutObj | Where-Object { $_.'Analytics Enabled' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $TableParams = @{
                        Name         = "Insider Risk Global Settings - $TenantId"
                        List         = $true
                        ColumnWidths = 45, 55
                    }
                    $null = (& {
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    })
                    $OutObj | Table @TableParams
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Insider Risk Settings Section: $($_.Exception.Message)" | Out-Null
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Insider Risk'
    }
}
