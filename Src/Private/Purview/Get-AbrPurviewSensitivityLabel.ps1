function Get-AbrPurviewSensitivityLabel {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Sensitivity Label information.
    .DESCRIPTION
        Collects and reports on Sensitivity Labels and Label Policies configured in
        Microsoft Purview Information Protection.
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
        Write-PScriboMessage -Message "Collecting Microsoft Purview Sensitivity Label information for tenant $TenantId."
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Sensitivity Labels'
    }

    process {
        try {
            $Labels = Get-Label -ErrorAction Stop

            if ($Labels) {
                Section -Style Heading3 'Sensitivity Labels' {
                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Label in $Labels) {
                        try {
                            $inObj = [ordered] @{
                                'Name'              = $Label.DisplayName
                                'Priority'          = $Label.Priority
                                'Enabled'           = $Label.Disabled -eq $false
                                'Encryption'        = $Label.EncryptionEnabled
                                'Content Marking'   = $Label.ContentMarkingEnabled
                                'Auto Labeling'     = $Label.AutoLabelingEnabled
                                'Scope'             = ($Label.ContentType -join ', ')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Sensitivity Label '$($Label.DisplayName)': $($_.Exception.Message)"
                        }
                    }

                    if ($HealthCheck.Purview.InformationProtection) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Warning
                    }

                    $TableParams = @{
                        Name         = "Sensitivity Labels - $TenantId"
                        List         = $false
                        ColumnWidths = 22, 10, 10, 12, 14, 14, 18
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Priority' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Sensitivity Label information found for $TenantId. Disabling section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Sensitivity Label Section: $($_.Exception.Message)"
        }

        # Sensitivity Label Policies
        try {
            $LabelPolicies = Get-LabelPolicy -ErrorAction Stop

            if ($LabelPolicies) {
                Section -Style Heading3 'Sensitivity Label Policies' {
                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Policy in $LabelPolicies) {
                        try {
                            $inObj = [ordered] @{
                                'Name'              = $Policy.Name
                                'Enabled'           = $Policy.Enabled
                                'Labels'            = ($Policy.Labels -join ', ')
                                'Exchange Location' = ($Policy.ExchangeLocation.Name -join ', ')
                                'Users'             = ($Policy.ExchangeLocationException.Name -join ', ')
                                'Created'           = $Policy.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Label Policy '$($Policy.Name)': $($_.Exception.Message)"
                        }
                    }

                    if ($HealthCheck.Purview.InformationProtection) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical
                    }

                    $TableParams = @{
                        Name         = "Sensitivity Label Policies - $TenantId"
                        List         = $false
                        ColumnWidths = 22, 10, 20, 18, 18, 12
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Sensitivity Label Policy information found for $TenantId. Disabling section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Sensitivity Label Policy Section: $($_.Exception.Message)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Sensitivity Labels'
    }
}