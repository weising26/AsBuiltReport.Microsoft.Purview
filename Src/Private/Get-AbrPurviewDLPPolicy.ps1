function Get-AbrPurviewDLPPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory)]
        [string]$TenantId
    )

    begin {
        Write-PScriboMessage -Message "Collecting Microsoft Purview DLP Policy information for tenant $TenantId." | Out-Null
        Show-AbrDebugExecutionTime -Start -TitleMessage 'DLP Policies'
    }

    process {
        try {
            $DLPPolicies = Get-DlpCompliancePolicy -ErrorAction Stop

            if ($DLPPolicies) {
                Section -Style Heading3 'Data Loss Prevention Policies' {

                    #region Pre-scan all rules for flags and SIT coverage
                    $AllRules             = [System.Collections.ArrayList]::new()
                    $HasEnforcedPolicies  = $false
                    $HasEndpointDlp       = $false
                    $UsesUserNotifications= $false
                    $UsesBlockingRules    = $false
                    $HasEphiPolicy        = $false
                    $HasPiiPolicy         = $false
                    $HasFinancialPolicy   = $false
                    $HasCopilotDlpPolicy  = $false

                    foreach ($Policy in $DLPPolicies) {
                        if ($Policy.Mode -eq 'Enable') { $HasEnforcedPolicies = $true }
                        if ($Policy.Workload -join ',' -match 'Endpoint') { $HasEndpointDlp = $true }
                        if ($Policy.AdaptiveScopes -or ($Policy.Workload -join ',' -match 'Copilot')) { $HasCopilotDlpPolicy = $true }

                        try {
                            $Rules = Get-DlpComplianceRule -Policy $Policy.Name -ErrorAction SilentlyContinue
                            foreach ($Rule in $Rules) {
                                $AllRules.Add($Rule) | Out-Null
                                if ($Rule.NotifyUser)  { $UsesUserNotifications = $true }
                                if ($Rule.BlockAccess) { $UsesBlockingRules = $true }

                                # Check SIT names from ContentContainsSensitiveInformation
                                foreach ($sit in $Rule.ContentContainsSensitiveInformation) {
                                    if ($sit.Name -match 'HIPAA|Health')           { $HasEphiPolicy      = $true }
                                    if ($sit.Name -match 'Credit Card')            { $HasFinancialPolicy  = $true }
                                    if ($sit.Name -match 'Social Security|SSN|Tax') { $HasPiiPolicy       = $true }
                                }
                            }
                        } catch { }
                    }
                    #endregion

                    #region Summary Table
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Policy in $DLPPolicies) {
                        try {
                            $inObj = [ordered] @{
                                'Name'          = $Policy.Name
                                'Mode'          = switch ($Policy.Mode) {
                                                    'Enable'                     { 'On (Enforced)' }
                                                    'Disable'                    { 'Off (Disabled)' }
                                                    'TestWithNotifications'      { 'Test with notifications' }
                                                    'TestWithoutNotifications'   { 'Test without notifications' }
                                                    default                      { $TextInfo.ToTitleCase($Policy.Mode) }
                                                  }
                                'Enabled'       = $Policy.Enabled
                                'Workload'      = ($Policy.Workload -join ', ')
                                'Created'       = $Policy.WhenCreated.ToString('yyyy-MM-dd')
                                'Last Modified' = $Policy.WhenChanged.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "DLP Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.DLP) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                        $OutObj | Where-Object { $_.'Mode' -notmatch 'Enforced' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $TableParams = @{ Name = "DLP Policies - $TenantId"; List = $false; ColumnWidths = 25, 18, 8, 21, 14, 14 }
                    $null = (& { if ($Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" } })
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                    #endregion

                    #region Coverage Summary (HealthCheck flags)
                    $CovObj = [System.Collections.ArrayList]::new()
                    $covInObj = [ordered] @{
                        'Has Enforced Policies (Mode: On)'     = $HasEnforcedPolicies
                        'Has Endpoint DLP Coverage'            = $HasEndpointDlp
                        'Has Copilot DLP Coverage'             = $HasCopilotDlpPolicy
                        'Uses User Notifications'              = $UsesUserNotifications
                        'Uses Blocking Rules'                  = $UsesBlockingRules
                        'Covers Health / ePHI Data (HIPAA)'   = $HasEphiPolicy
                        'Covers PII Data (SSN / Tax)'          = $HasPiiPolicy
                        'Covers Financial Data (Credit Card)'  = $HasFinancialPolicy
                    }
                    $CovObj.Add([pscustomobject](ConvertTo-HashToYN $covInObj)) | Out-Null

                    $null = (& {
                    if ($HealthCheck.Purview.DLP) {
                        $CovObj | Where-Object { $_.'Has Enforced Policies (Mode: On)' -eq 'No' }   | Set-Style -Style Critical | Out-Null
                        $CovObj | Where-Object { $_.'Has Endpoint DLP Coverage' -eq 'No' }          | Set-Style -Style Warning  | Out-Null
                        $CovObj | Where-Object { $_.'Has Copilot DLP Coverage' -eq 'No' }           | Set-Style -Style Warning  | Out-Null
                        $CovObj | Where-Object { $_.'Uses Blocking Rules' -eq 'No' }                | Set-Style -Style Warning  | Out-Null
                    }
                    })

                    $CovTableParams = @{ Name = "DLP Coverage Summary - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    $null = (& { if ($Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" } })
                    $CovObj | Table @CovTableParams
                    #endregion

                    #region Per-Policy Detail Sections (InfoLevel 2+)
                    if ($InfoLevel.DLP -ge 2) {
                        foreach ($Policy in ($DLPPolicies | Sort-Object Name)) {
                            try {
                                # Fetch rules for this policy
                                $DLPRules = Get-DlpComplianceRule -Policy $Policy.Name -ErrorAction SilentlyContinue

                                Section -Style Heading4 $Policy.Name {

                                    Paragraph "Logicalis implemented the $($Policy.Name) DLP policy with the following configuration."
                                    BlankLine

                                    #region Policy Details
                                    $DetObj = [System.Collections.ArrayList]::new()
                                    $detInObj = [ordered] @{
                                        'What info do you want to protect?' = if ($Policy.Workload) { ($Policy.Workload -join ', ') } else { '--' }
                                        'Name'                              = $Policy.Name
                                        'Description'                       = if ($Policy.Comment) { $Policy.Comment } else { '--' }
                                        'Priority'                          = $Policy.Priority
                                    }
                                    $DetObj.Add([pscustomobject](ConvertTo-HashToYN $detInObj)) | Out-Null
                                    $DetTableParams = @{ Name = "Policy Details - $($Policy.Name)"; List = $true; ColumnWidths = 40, 60 }
                                    $null = (& { if ($Report.ShowTableCaptions) { $DetTableParams['Caption'] = "- $($DetTableParams.Name)" } })
                                    $DetObj | Table @DetTableParams
                                    #endregion

                                    #region Locations
                                    $LocObj = [System.Collections.ArrayList]::new()
                                    $locInObj = [ordered] @{
                                        'Exchange email'                         = if ($Policy.ExchangeLocation)             { "Checked ($( if ($Policy.ExchangeLocation.Name -contains 'All') { 'All groups' } else { ($Policy.ExchangeLocation.Name -join ', ') } ))" }             else { 'Not checked' }
                                        'SharePoint sites'                       = if ($Policy.SharePointLocation)           { "Checked ($( if ($Policy.SharePointLocation.Name -contains 'All') { 'All sites' } else { ($Policy.SharePointLocation.Name -join ', ') } ))" }           else { 'Not checked' }
                                        'OneDrive accounts'                      = if ($Policy.OneDriveLocation)             { "Checked ($( if ($Policy.OneDriveLocation.Name -contains 'All') { 'All accounts' } else { ($Policy.OneDriveLocation.Name -join ', ') } ))" }             else { 'Not checked' }
                                        'Teams and channel messages'             = if ($Policy.TeamsLocation)                { "Checked ($( if ($Policy.TeamsLocation.Name -contains 'All') { 'All teams' } else { ($Policy.TeamsLocation.Name -join ', ') } ))" }                     else { 'Not checked' }
                                        'Devices'                                = if ($Policy.EndpointDlpLocation)          { "Checked ($( if ($Policy.EndpointDlpLocation.Name -contains 'All') { 'All devices' } else { ($Policy.EndpointDlpLocation.Name -join ', ') } ))" }       else { 'Not checked' }
                                        'On-premises repositories'               = if ($Policy.OnPremisesScannerDlpLocation) { 'Checked' } else { 'Not checked' }
                                        'Fabric and Power BI workspaces'         = if ($Policy.PowerBIDlpLocation)           { 'Checked' } else { 'N/A' }
                                        'Microsoft 365 Copilot and Copilot Chat' = if ($Policy.AdaptiveScopes)               { 'Checked' } else { 'N/A' }
                                        'Managed cloud apps'                     = if ($Policy.ThirdPartyAppDlpLocation)     { 'Checked' } else { 'N/A' }
                                    }
                                    $LocObj.Add([pscustomobject](ConvertTo-HashToYN $locInObj)) | Out-Null
                                    $LocTableParams = @{ Name = "Locations - $($Policy.Name)"; List = $true; ColumnWidths = 40, 60 }
                                    $null = (& { if ($Report.ShowTableCaptions) { $LocTableParams['Caption'] = "- $($LocTableParams.Name)" } })
                                    $LocObj | Table @LocTableParams
                                    #endregion

                                    #region Policy Settings - Rules Table
                                    try {
                                        if ($DLPRules) {
                                            $RuleObj = [System.Collections.ArrayList]::new()
                                            foreach ($Rule in ($DLPRules | Where-Object { -not $_.Disabled } | Sort-Object Name)) {
                                                try {
                                                    #-- Conditions --
                                                    $ConditionParts = [System.Collections.ArrayList]::new()

                                                    # SIT-based conditions (direct property)
                                                    foreach ($sit in $Rule.ContentContainsSensitiveInformation) {
                                                        $sitDetail = "Contains SIT: $($sit.Name)"
                                                        if ($sit.minCount)      { $sitDetail += " (min count: $($sit.minCount))" }
                                                        if ($sit.confidenceLevel) { $sitDetail += " [confidence: $($sit.confidenceLevel)]" }
                                                        $ConditionParts.Add($sitDetail) | Out-Null
                                                    }

                                                    # Sensitivity label conditions from AdvancedRule JSON
                                                    if ($Rule.AdvancedRule) {
                                                        try {
                                                            $AdvJson = $Rule.AdvancedRule | ConvertFrom-Json -ErrorAction SilentlyContinue
                                                            $nodes = [System.Collections.Queue]::new()
                                                            $nodes.Enqueue($AdvJson)
                                                            while ($nodes.Count -gt 0) {
                                                                $node = $nodes.Dequeue()
                                                                if ($node.PSObject.Properties['Operator']) {
                                                                    foreach ($sub in $node.SubConditions) { $nodes.Enqueue($sub) }
                                                                }
                                                                if ($node.ConditionName -eq 'ContentContainsSensitivityLabel') {
                                                                    foreach ($lv in $node.Value) {
                                                                        $ConditionParts.Add("Content Contains Sensitivity Label: $lv") | Out-Null
                                                                    }
                                                                }
                                                                if ($node.ConditionName -eq 'ContentContainsSensitiveInformation') {
                                                                    foreach ($sitNode in $node.Value) {
                                                                        $sitDetail = "Contains SIT: $($sitNode.name)"
                                                                        if ($sitNode.minCount)       { $sitDetail += " (min: $($sitNode.minCount))" }
                                                                        if ($sitNode.confidenceLevel) { $sitDetail += " [confidence: $($sitNode.confidenceLevel)]" }
                                                                        $ConditionParts.Add($sitDetail) | Out-Null
                                                                    }
                                                                }
                                                            }
                                                        } catch { }
                                                    }

                                                    if ($Rule.SentTo)                    { $ConditionParts.Add("Sent to: $($Rule.SentTo -join ', ')") | Out-Null }
                                                    if ($Rule.SentToMemberOf)            { $ConditionParts.Add("Sent to member of: $($Rule.SentToMemberOf -join ', ')") | Out-Null }
                                                    if ($Rule.ContentPropertyContainsWords) { $ConditionParts.Add("Property contains: $($Rule.ContentPropertyContainsWords -join ', ')") | Out-Null }

                                                    $ConditionsDisplay = if ($ConditionParts.Count -gt 0) { $ConditionParts -join "`n" } else { '--' }

                                                    #-- Actions --
                                                    $ActionParts = [System.Collections.ArrayList]::new()

                                                    if ($Rule.BlockAccess) {
                                                        $scope = if ($Rule.BlockAccessScope) { " ($($TextInfo.ToTitleCase($Rule.BlockAccessScope)))" } else { '' }
                                                        $ActionParts.Add("Block Access$scope") | Out-Null
                                                    }
                                                    if ($Rule.SetHeader) {
                                                        foreach ($h in $Rule.SetHeader) {
                                                            $ActionParts.Add("Set header: $($h.Name):$($h.Value)") | Out-Null
                                                        }
                                                    }
                                                    if ($Rule.ModifySubject) {
                                                        foreach ($ms in $Rule.ModifySubject) {
                                                            $ActionParts.Add("Modify subject, remove text that matches: $($ms.SearchString)`nInsert replacement text: $($ms.ReplaceString)`nPosition: $($ms.Position)") | Out-Null
                                                        }
                                                    }
                                                    if ($Rule.NotifyUser) {
                                                        $ActionParts.Add("Notify user: $($Rule.NotifyUser -join ', ')") | Out-Null
                                                    }
                                                    if ($Rule.GenerateIncidentReport) {
                                                        $ActionParts.Add("Generate incident report to: $($Rule.IncidentReportContent -join ', ')") | Out-Null
                                                    }
                                                    if ($Rule.ExceptIfHeaderMatchesPatterns) {
                                                        foreach ($ex in $Rule.ExceptIfHeaderMatchesPatterns) {
                                                            $ActionParts.Add("Except if header matches: $($ex.Name):$($ex.Value -join '|')") | Out-Null
                                                        }
                                                    }

                                                    $ActionsDisplay = if ($ActionParts.Count -gt 0) { $ActionParts -join "`n" } else { 'Audit Only' }

                                                    $ruleInObj = [ordered] @{
                                                        'Rule'       = $Rule.Name
                                                        'Conditions' = $ConditionsDisplay
                                                        'Actions'    = $ActionsDisplay
                                                    }
                                                    $RuleObj.Add([pscustomobject]($ruleInObj)) | Out-Null
                                                } catch {
                                                    Write-PScriboMessage -IsWarning -Message "DLP Rule '$($Rule.Name)': $($_.Exception.Message)" | Out-Null
                                                }
                                            }

                                            if ($RuleObj.Count -gt 0) {
                                                $RuleTableParams = @{ Name = "Policy Settings - $($Policy.Name)"; List = $false; ColumnWidths = 28, 36, 36 }
                                                $null = (& { if ($Report.ShowTableCaptions) { $RuleTableParams['Caption'] = "- $($RuleTableParams.Name)" } })
                                                $RuleObj | Table @RuleTableParams
                                            }
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "DLP Rules for '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                                    }
                                    #endregion

                                    #region User Notifications
                                    $NotifObj = [System.Collections.ArrayList]::new()
                                    $notifInObj = [ordered] @{
                                        'Use notifications to inform your users and help educate them on the proper use of sensitive info.' = if ($DLPRules | Where-Object { $_.NotifyUser }) { 'On' } else { 'Off' }
                                    }
                                    $NotifObj.Add([pscustomobject](ConvertTo-HashToYN $notifInObj)) | Out-Null
                                    $NotifTableParams = @{ Name = "User Notifications - $($Policy.Name)"; List = $true; ColumnWidths = 70, 30 }
                                    $null = (& { if ($Report.ShowTableCaptions) { $NotifTableParams['Caption'] = "- $($NotifTableParams.Name)" } })
                                    $NotifObj | Table @NotifTableParams
                                    #endregion

                                    #region Incident Reports
                                    $IncObj = [System.Collections.ArrayList]::new()
                                    $FirstRule = $DLPRules | Where-Object { $_.ReportSeverityLevel } | Select-Object -First 1
                                    $incInObj = [ordered] @{
                                        'Use this severity level in admin alerts and reports:' = if ($FirstRule) { $TextInfo.ToTitleCase($FirstRule.ReportSeverityLevel) } else { 'Low' }
                                        'Send an alert to admins when a rule match occurs.'    = if ($DLPRules | Where-Object { $_.AlertProperties }) { 'On' } else { 'Off' }
                                        'Use email incident reports to notify you when a policy match occurs.' = if ($DLPRules | Where-Object { $_.GenerateIncidentReport }) { 'On' } else { 'Off' }
                                    }
                                    $IncObj.Add([pscustomobject](ConvertTo-HashToYN $incInObj)) | Out-Null
                                    $IncTableParams = @{ Name = "Incident Reports - $($Policy.Name)"; List = $true; ColumnWidths = 70, 30 }
                                    $null = (& { if ($Report.ShowTableCaptions) { $IncTableParams['Caption'] = "- $($IncTableParams.Name)" } })
                                    $IncObj | Table @IncTableParams
                                    #endregion

                                    #region Additional Options
                                    $AddObj = [System.Collections.ArrayList]::new()
                                    $StopProcessing = $DLPRules | Where-Object { $_.StopPolicyProcessing } | Select-Object -First 1
                                    $addInObj = [ordered] @{
                                        "If there's a match for this rule, stop processing additional DLP policies and rules." = if ($StopProcessing) { 'Checked' } else { 'Not checked' }
                                    }
                                    $AddObj.Add([pscustomobject](ConvertTo-HashToYN $addInObj)) | Out-Null
                                    $AddTableParams = @{ Name = "Additional Options - $($Policy.Name)"; List = $true; ColumnWidths = 70, 30 }
                                    $null = (& { if ($Report.ShowTableCaptions) { $AddTableParams['Caption'] = "- $($AddTableParams.Name)" } })
                                    $AddObj | Table @AddTableParams
                                    #endregion

                                    #region Policy Mode
                                    $ModeObj = [System.Collections.ArrayList]::new()
                                    $modeInObj = [ordered] @{
                                        'Policy mode' = switch ($Policy.Mode) {
                                            'Enable'                     { 'On (Enabled)' }
                                            'Disable'                    { 'Off (Disabled)' }
                                            'TestWithNotifications'      { 'Test mode with notifications' }
                                            'TestWithoutNotifications'   { 'Test mode without notifications' }
                                            default                      { $TextInfo.ToTitleCase($Policy.Mode) }
                                        }
                                    }
                                    $ModeObj.Add([pscustomobject](ConvertTo-HashToYN $modeInObj)) | Out-Null
                                    $ModeTableParams = @{ Name = "Policy Mode - $($Policy.Name)"; List = $true; ColumnWidths = 40, 60 }
                                    $null = (& { if ($Report.ShowTableCaptions) { $ModeTableParams['Caption'] = "- $($ModeTableParams.Name)" } })
                                    $ModeObj | Table @ModeTableParams
                                    #endregion

                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "DLP Policy Detail '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                            }
                        }
                    }
                    #endregion
                }
            } else {
                Write-PScriboMessage -Message "No DLP Policy information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "DLP Policy Section: $($_.Exception.Message)" | Out-Null
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'DLP Policies'
    }
}
