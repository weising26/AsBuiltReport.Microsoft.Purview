function Get-AbrPurviewAuditPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory)]
        [string]$TenantId
    )

    begin {
        Write-PScriboMessage -Message "Collecting Microsoft Purview Audit Policy information for tenant $TenantId." | Out-Null
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Audit Policies'
    }

    process {
        #region Audit Log Configuration (InfoLevel 1+)
        try {
            $AuditConfig    = Get-AdminAuditLogConfig -ErrorAction Stop
            $OrgConfig      = Get-OrganizationConfig -ErrorAction SilentlyContinue

            if ($AuditConfig) {
                Section -Style Heading3 'Audit Log Configuration' {
                    $OutObj = [System.Collections.ArrayList]::new()
                    try {
                        $inObj = [ordered] @{
                            'Unified Audit Log Enabled'         = $AuditConfig.UnifiedAuditLogIngestionEnabled
                            'Audit Log Age Limit'               = $AuditConfig.AuditLogAgeLimit
                            'Admin Audit Log Enabled'           = $AuditConfig.AdminAuditLogEnabled
                            'Mailbox Auditing Enabled by Default' = if ($OrgConfig) { $OrgConfig.AuditDisabled -eq $false } else { 'Unknown' }
                            'Log Cmdlets'                       = if ($AuditConfig.AdminAuditLogCmdlets) { ($AuditConfig.AdminAuditLogCmdlets -join ', ') } else { 'All' }
                            'Log Parameters'                    = if ($AuditConfig.AdminAuditLogParameters) { ($AuditConfig.AdminAuditLogParameters -join ', ') } else { 'All' }
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "Audit Log Config: $($_.Exception.Message)" | Out-Null
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.Audit) {
                        $OutObj | Where-Object { $_.'Unified Audit Log Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                        $OutObj | Where-Object { $_.'Admin Audit Log Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                        $OutObj | Where-Object { $_.'Mailbox Auditing Enabled by Default' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $TableParams = @{ Name = "Audit Log Configuration - $TenantId"; List = $true; ColumnWidths = 45, 55 }
                    $null = (& { if ($Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" } })
                    $OutObj | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Audit Log Configuration found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Audit Log Configuration Section: $($_.Exception.Message)" | Out-Null
        }
        #endregion

        #region Audit-Related Protection Alerts (InfoLevel 1+)
        try {
            $AuditAlerts = Get-ProtectionAlert -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'audit' -or $_.Category -match 'audit' }

            if ($AuditAlerts) {
                Section -Style Heading3 'Audit-Related Protection Alerts' {
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Alert in $AuditAlerts) {
                        try {
                            $inObj = [ordered] @{
                                'Alert Name'  = $Alert.Name
                                'Severity'    = $TextInfo.ToTitleCase($Alert.Severity)
                                'Category'    = $TextInfo.ToTitleCase($Alert.Category)
                                'Enabled'     = $Alert.Disabled -eq $false
                                'Notify'      = if ($Alert.NotifyUser) { ($Alert.NotifyUser -join ', ') } else { '--' }
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Audit Alert '$($Alert.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.Audit) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $TableParams = @{ Name = "Audit Protection Alerts - $TenantId"; List = $false; ColumnWidths = 35, 15, 15, 12, 23 }
                    $null = (& { if ($Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" } })
                    $OutObj | Sort-Object -Property 'Alert Name' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No audit-related protection alerts found for $TenantId." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Audit Protection Alerts Section: $($_.Exception.Message)" | Out-Null
        }
        #endregion

        #region Audit Retention Policies (InfoLevel 2+)
        if ($InfoLevel.Audit -ge 2) {
            try {
                $AuditRetentionPolicies = Get-UnifiedAuditLogRetentionPolicy -ErrorAction Stop

                if ($AuditRetentionPolicies) {
                    Section -Style Heading3 'Audit Retention Policies' {
                        $OutObj = [System.Collections.ArrayList]::new()

                        foreach ($Policy in $AuditRetentionPolicies) {
                            try {
                                $inObj = [ordered] @{
                                    'Policy Name'        = $Policy.Name
                                    'Description'        = if ($Policy.Description) { $Policy.Description } else { '--' }
                                    'Retention Duration' = $TextInfo.ToTitleCase($Policy.RetentionDuration)
                                    'Record Types'       = if ($Policy.RecordTypes) { ($Policy.RecordTypes -join ', ') } else { 'All' }
                                    'Operations'         = if ($Policy.Operations) { ($Policy.Operations -join ', ') } else { 'All' }
                                    'Priority'           = $Policy.Priority
                                    'Users'              = if ($Policy.UserIds) { ($Policy.UserIds -join ', ') } else { 'All' }
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "Audit Retention Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                            }
                        }

                        $TableParams = @{ Name = "Audit Retention Policies - $TenantId"; List = $false; ColumnWidths = 18, 16, 14, 16, 14, 10, 12 }
                        $null = (& { if ($Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" } })
                        $OutObj | Sort-Object -Property 'Priority' | Table @TableParams
                    }
                } else {
                    Write-PScriboMessage -Message "No Audit Retention Policy information found for $TenantId. Disabling section." | Out-Null
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "Audit Retention Policy Section: $($_.Exception.Message)" | Out-Null
            }
        }
        #endregion
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Audit Policies'
    }
}
