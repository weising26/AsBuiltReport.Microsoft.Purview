function Get-AbrPurviewAuditPolicy {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Audit configuration information.
    .DESCRIPTION
        Collects and reports on the Unified Audit Log configuration, audit-related
        protection alerts, and custom Audit Log Retention Policies configured in
        Microsoft Purview.
    .NOTES
        Version:        0.1.0
        Author:         Pai Wei Sing
    .EXAMPLE
        Get-AbrPurviewAuditPolicy -TenantId 'contoso.onmicrosoft.com'
    #>
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
                        $mailboxAuditVal = if ($OrgConfig) { if ($OrgConfig.AuditDisabled -eq $false) { 'Yes' } else { 'No' } } else { 'Unknown' }
                            $_pre_UnifiedAuditLogEnabl_37 = if ($AuditConfig.UnifiedAuditLogIngestionEnabled) { 'Yes' } else { 'No' }
                            $_pre_AdminAuditLogEnabled_39 = if ($AuditConfig.AdminAuditLogEnabled) { 'Yes' } else { 'No' }
                            $_pre_LogCmdlets_41 = if ($AuditConfig.AdminAuditLogCmdlets) { ($AuditConfig.AdminAuditLogCmdlets -join ', ') } else { 'All' }
                            $_pre_LogParameters_42 = if ($AuditConfig.AdminAuditLogParameters) { ($AuditConfig.AdminAuditLogParameters -join ', ') } else { 'All' }
                        $inObj = [ordered] @{
                            'Unified Audit Log Enabled' = $_pre_UnifiedAuditLogEnabl_37
                            'Audit Log Age Limit'               = $AuditConfig.AuditLogAgeLimit
                            'Admin Audit Log Enabled' = $_pre_AdminAuditLogEnabled_39
                            'Mailbox Auditing Enabled by Default' = $mailboxAuditVal
                            'Log Cmdlets' = $_pre_LogCmdlets_41
                            'Log Parameters' = $_pre_LogParameters_42
                        }
                        $OutObj.Add([pscustomobject]$inObj) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "Audit Log Config: $($_.Exception.Message)" | Out-Null
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.Audit) {
                        $OutObj | Where-Object { $_.'Unified Audit Log Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                        $OutObj | Where-Object { $_.'Admin Audit Log Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                        $OutObj | Where-Object { $_.'Mailbox Auditing Enabled by Default' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }

                    $TableParams = @{ Name = "Audit Log Configuration - $TenantId"; List = $true; ColumnWidths = 45, 55 }
                    if ($script:Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" }
                    $OutObj | Table @TableParams

                    #region ACSC Inline Check — Audit Log Configuration
                    if ($script:InfoLevel.Audit -ge 3) {
                        $AuditEnabled        = [bool]($AuditConfig.UnifiedAuditLogIngestionEnabled)
                        $MailboxAuditDefault = ($OrgConfig -and $OrgConfig.AuditDisabled -eq $false)

                        # Determine max retention days from any custom audit retention policy
                        $MaxRetDays = 90
                        $RetPolicies = @(try { Get-UnifiedAuditLogRetentionPolicy -ErrorAction SilentlyContinue } catch { @() })
                        foreach ($rp in $RetPolicies) {
                            $d = switch ($rp.RetentionDuration) {
                                'ThreeMonths'  { 90 };  'SixMonths'    { 180 }; 'NineMonths'   { 270 }
                                'TwelveMonths' { 365 }; 'TwoYears'     { 730 }; 'FiveYears'    { 1825 }
                                'SevenYears'   { 2555 }; 'TenYears'    { 3650 }; default        { 0 }
                            }
                            if ($d -gt $MaxRetDays) { $MaxRetDays = $d }
                        }

                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'Audit Log Configuration' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-0580'
                                E8          = 'N/A'
                                Description = 'Event logging policy implemented and active'
                                Check       = 'Unified Audit Log ingestion enabled'
                                Status      = if ($AuditEnabled) { 'Pass' } else { 'Fail' }
                            }
                            [pscustomobject]@{
                                ControlId   = 'ISM-0585'
                                E8          = 'N/A'
                                Description = 'Sufficient detail recorded in event logs'
                                Check       = 'Mailbox auditing enabled by default for all users'
                                Status      = if ($MailboxAuditDefault) { 'Pass' } else { 'Fail' }
                            }
                            [pscustomobject]@{
                                ControlId   = 'ISM-1998'
                                E8          = 'N/A'
                                Description = 'Event logs retained for at least 12 months'
                                Check       = "Audit retention policy >= 365 days (current max: $MaxRetDays days)"
                                Status      = if ($MaxRetDays -ge 365) { 'Pass' } else { 'Fail' }
                            }
                            [pscustomobject]@{
                                ControlId   = 'ISM-1989'
                                E8          = 'N/A'
                                Description = 'Event logs retained for at least 7 years (records systems)'
                                Check       = "Audit retention policy >= 2555 days / 7 years (current max: $MaxRetDays days)"
                                Status      = if ($MaxRetDays -ge 2555) { 'Pass' } else { 'Fail' }
                            }
                        )
                    }
                    #endregion
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
                                $_pre_Enabled_134 = if ($Alert.Disabled -eq $false) { 'Yes' } else { 'No' }
                                $_pre_Notify_135 = if ($Alert.NotifyUser) { ($Alert.NotifyUser -join ', ') } else { '--' }
                            $inObj = [ordered] @{
                                'Alert Name'  = $Alert.Name
                                'Severity'    = $script:TextInfo.ToTitleCase($Alert.Severity)
                                'Category'    = $script:TextInfo.ToTitleCase($Alert.Category)
                                'Enabled' = $_pre_Enabled_134
                                'Notify' = $_pre_Notify_135
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Audit Alert '$($Alert.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.Audit) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }

                    $TableParams = @{ Name = "Audit Protection Alerts - $TenantId"; List = $false; ColumnWidths = 35, 15, 15, 12, 23 }
                    if ($script:Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" }
                    $OutObj | Sort-Object -Property 'Alert Name' | Table @TableParams

                    #region ACSC Inline Check — Audit Alerts
                    if ($script:InfoLevel.Audit -ge 3) {
                        $ActiveAlerts = $AuditAlerts | Where-Object { $_.Disabled -eq $false }
                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'Audit Protection Alerts' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-0109'
                                E8          = 'E8 ML2, ML3'
                                Description = 'Event logs analysed in timely manner to detect cyber security events'
                                Check       = 'Active protection alerts configured for audit/eDiscovery/privilege activities'
                                Status      = if ($ActiveAlerts) { 'Pass' } elseif ($AuditAlerts) { 'Partial' } else { 'Fail' }
                            }
                        )
                    }
                    #endregion
                }
            } else {
                Write-PScriboMessage -Message "No audit-related protection alerts found for $TenantId." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Audit Protection Alerts Section: $($_.Exception.Message)" | Out-Null
        }
        #endregion

        #region Audit Retention Policies (InfoLevel 2+)
        if ($script:InfoLevel.Audit -ge 2) {
            try {
                $AuditRetentionPolicies = Get-UnifiedAuditLogRetentionPolicy -ErrorAction Stop

                if ($AuditRetentionPolicies) {
                    Section -Style Heading3 'Audit Retention Policies' {
                        $OutObj = [System.Collections.ArrayList]::new()

                        foreach ($Policy in $AuditRetentionPolicies) {
                            try {
                                    $_pre_Description_189 = if ($Policy.Description) { $Policy.Description } else { '--' }
                                    $_pre_RecordTypes_191 = if ($Policy.RecordTypes) { ($Policy.RecordTypes -join ', ') } else { 'All' }
                                    $_pre_Operations_192 = if ($Policy.Operations) { ($Policy.Operations -join ', ') } else { 'All' }
                                    $_pre_Users_194 = if ($Policy.UserIds) { ($Policy.UserIds -join ', ') } else { 'All' }
                                $inObj = [ordered] @{
                                    'Policy Name'        = $Policy.Name
                                    'Description' = $_pre_Description_189
                                    'Retention Duration' = $script:TextInfo.ToTitleCase($Policy.RetentionDuration)
                                    'Record Types' = $_pre_RecordTypes_191
                                    'Operations' = $_pre_Operations_192
                                    'Priority'           = $Policy.Priority
                                    'Users' = $_pre_Users_194
                                }
                                $OutObj.Add([pscustomobject]$inObj) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "Audit Retention Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                            }
                        }

                        $TableParams = @{ Name = "Audit Retention Policies - $TenantId"; List = $false; ColumnWidths = 18, 16, 14, 16, 14, 10, 12 }
                        if ($script:Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" }
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
