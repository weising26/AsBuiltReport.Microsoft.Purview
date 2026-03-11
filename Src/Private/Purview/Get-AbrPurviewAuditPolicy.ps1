function Get-AbrPurviewAuditPolicy {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Audit Policy information.
    .DESCRIPTION
        Collects and reports on Audit Log configuration, Audit Policies, and
        Audit Retention Policies in Microsoft Purview.
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
        Write-PScriboMessage -Message "Collecting Microsoft Purview Audit Policy information for tenant $TenantId."
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Audit Policies'
    }

    process {
        # Admin Audit Log Configuration
        try {
            $AuditConfig = Get-AdminAuditLogConfig -ErrorAction Stop

            if ($AuditConfig) {
                Section -Style Heading3 'Audit Log Configuration' {
                    $OutObj = [System.Collections.ArrayList]::new()
                    try {
                        $inObj = [ordered] @{
                            'Unified Audit Log Enabled'  = $AuditConfig.UnifiedAuditLogIngestionEnabled
                            'Audit Log Age Limit'        = $AuditConfig.AuditLogAgeLimit
                            'Admin Audit Log Enabled'    = $AuditConfig.AdminAuditLogEnabled
                            'Log Cmdlets'                = if ($AuditConfig.AdminAuditLogCmdlets) { ($AuditConfig.AdminAuditLogCmdlets -join ', ') } else { 'All' }
                            'Log Parameters'             = if ($AuditConfig.AdminAuditLogParameters) { ($AuditConfig.AdminAuditLogParameters -join ', ') } else { 'All' }
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "Audit Log Config: $($_.Exception.Message)"
                    }

                    if ($HealthCheck.Purview.Audit) {
                        $OutObj | Where-Object { $_.'Unified Audit Log Enabled' -eq 'No' } | Set-Style -Style Critical
                        $OutObj | Where-Object { $_.'Admin Audit Log Enabled' -eq 'No' } | Set-Style -Style Critical
                    }

                    $TableParams = @{
                        Name         = "Audit Log Configuration - $TenantId"
                        List         = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Audit Log Configuration found for $TenantId. Disabling section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Audit Log Configuration Section: $($_.Exception.Message)"
        }

        # Audit Retention Policies
        try {
            $AuditRetentionPolicies = Get-UnifiedAuditLogRetentionPolicy -ErrorAction Stop

            if ($AuditRetentionPolicies) {
                Section -Style Heading3 'Audit Retention Policies' {
                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Policy in $AuditRetentionPolicies) {
                        try {
                            $inObj = [ordered] @{
                                'Policy Name'       = $Policy.Name
                                'Description'       = $Policy.Description
                                'Retention Duration'= $TextInfo.ToTitleCase($Policy.RetentionDuration)
                                'Record Types'      = ($Policy.RecordTypes -join ', ')
                                'Operations'        = if ($Policy.Operations) { ($Policy.Operations -join ', ') } else { 'All' }
                                'Priority'          = $Policy.Priority
                                'Users'             = if ($Policy.UserIds) { ($Policy.UserIds -join ', ') } else { 'All' }
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Audit Retention Policy '$($Policy.Name)': $($_.Exception.Message)"
                        }
                    }

                    $TableParams = @{
                        Name         = "Audit Retention Policies - $TenantId"
                        List         = $false
                        ColumnWidths = 18, 18, 15, 16, 13, 10, 10
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Priority' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Audit Retention Policy information found for $TenantId. Disabling section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Audit Retention Policy Section: $($_.Exception.Message)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Audit Policies'
    }
}