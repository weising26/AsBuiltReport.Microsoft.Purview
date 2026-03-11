function Get-AbrPurviewInsiderRisk {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Insider Risk Management information.
    .DESCRIPTION
        Collects and reports on Insider Risk Management policies configured in
        Microsoft Purview, using the Microsoft Graph API.
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
        Write-PScriboMessage -Message "Collecting Microsoft Purview Insider Risk Management information for tenant $TenantId."
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Insider Risk'
    }

    process {
        try {
            # Insider Risk policies are available via Graph API beta endpoint
            $Uri = "https://graph.microsoft.com/beta/security/insiderRiskPolicies"
            $Response = Invoke-MgGraphRequest -Uri $Uri -Method GET -ErrorAction Stop
            $InsiderRiskPolicies = $Response.value

            if ($InsiderRiskPolicies) {
                Section -Style Heading3 'Insider Risk Management Policies' {
                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Policy in $InsiderRiskPolicies) {
                        try {
                            $inObj = [ordered] @{
                                'Policy Name'   = $Policy.displayName
                                'Status'        = $TextInfo.ToTitleCase($Policy.status)
                                'Policy Type'   = $TextInfo.ToTitleCase($Policy.policyTemplate)
                                'Created'       = if ($Policy.createdDateTime) { ([datetime]$Policy.createdDateTime).ToString('yyyy-MM-dd') } else { 'N/A' }
                                'Last Modified' = if ($Policy.lastModifiedDateTime) { ([datetime]$Policy.lastModifiedDateTime).ToString('yyyy-MM-dd') } else { 'N/A' }
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Insider Risk Policy '$($Policy.displayName)': $($_.Exception.Message)"
                        }
                    }

                    if ($HealthCheck.Purview.InsiderRisk) {
                        $OutObj | Where-Object { $_.'Status' -ne 'Enabled' } | Set-Style -Style Warning
                    }

                    $TableParams = @{
                        Name         = "Insider Risk Policies - $TenantId"
                        List         = $false
                        ColumnWidths = 28, 14, 24, 17, 17
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Policy Name' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Insider Risk Policy information found for $TenantId. Disabling section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Insider Risk Policy Section: $($_.Exception.Message)"
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
                        Write-PScriboMessage -IsWarning -Message "Insider Risk Settings: $($_.Exception.Message)"
                    }

                    if ($HealthCheck.Purview.InsiderRisk) {
                        $OutObj | Where-Object { $_.'Analytics Enabled' -eq 'No' } | Set-Style -Style Warning
                    }

                    $TableParams = @{
                        Name         = "Insider Risk Global Settings - $TenantId"
                        List         = $true
                        ColumnWidths = 45, 55
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Insider Risk Settings Section: $($_.Exception.Message)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Insider Risk'
    }
}
