function Get-AbrPurviewDLPPolicy {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Data Loss Prevention policy information.
    .DESCRIPTION
        Collects and reports on DLP Compliance Policies and their associated rules
        configured in Microsoft Purview, including coverage summary, locations,
        conditions, actions, notifications, and incident reports.
    .NOTES
        Version:        0.1.0
        Author:         Pai Wei Sing
    .EXAMPLE
        Get-AbrPurviewDLPPolicy -TenantId 'contoso.onmicrosoft.com'
    #>
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
                                $_pre_Enabled_79 = if ($Policy.Enabled) { 'Yes' } else { 'No' }
                            $inObj = [ordered] @{
                                'Name'          = $Policy.Name
                                'Mode'          = switch ($Policy.Mode) {
                                                    'Enable'                     { 'On (Enforced)' }
                                                    'Disable'                    { 'Off (Disabled)' }
                                                    'TestWithNotifications'      { 'Test with notifications' }
                                                    'TestWithoutNotifications'   { 'Test without notifications' }
                                                    default                      { $script:TextInfo.ToTitleCase($Policy.Mode) }
                                                  }
                                'Enabled' = $_pre_Enabled_79
                                'Workload'      = ($Policy.Workload -join ', ')
                                'Created'       = $Policy.WhenCreated.ToString('yyyy-MM-dd')
                                'Last Modified' = $Policy.WhenChanged.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "DLP Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.DLP) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                        $OutObj | Where-Object { $_.'Mode' -notmatch 'Enforced' } | Set-Style -Style Warning | Out-Null
                    }

                    $TableParams = @{ Name = "DLP Policies - $TenantId"; List = $false; ColumnWidths = 25, 18, 8, 21, 14, 14 }
                    if ($script:Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                    #endregion

                    #region Coverage Summary (HealthCheck flags)
                    $CovObj = [System.Collections.ArrayList]::new()
                        $_pre_HasEnforcedPoliciesM_104 = if ($HasEnforcedPolicies) { 'Yes' } else { 'No' }
                        $_pre_HasEndpointDLPCovera_106 = if ($HasEndpointDlp) { 'Yes' } else { 'No' }
                        $_pre_HasCopilotDLPCoverag_108 = if ($HasCopilotDlpPolicy) { 'Yes' } else { 'No' }
                        $_pre_UsesUserNotification_110 = if ($UsesUserNotifications) { 'Yes' } else { 'No' }
                        $_pre_UsesBlockingRules_112 = if ($UsesBlockingRules) { 'Yes' } else { 'No' }
                        $_pre_CoversHealthePHIData_114 = if ($HasEphiPolicy) { 'Yes' } else { 'No' }
                        $_pre_CoversPIIDataSSNTax_116 = if ($HasPiiPolicy) { 'Yes' } else { 'No' }
                        $_pre_CoversFinancialDataC_118 = if ($HasFinancialPolicy) { 'Yes' } else { 'No' }
                    $covInObj = [ordered] @{
                        'Has Enforced Policies (Mode: On)' = $_pre_HasEnforcedPoliciesM_104

                        'Has Endpoint DLP Coverage' = $_pre_HasEndpointDLPCovera_106

                        'Has Copilot DLP Coverage' = $_pre_HasCopilotDLPCoverag_108

                        'Uses User Notifications' = $_pre_UsesUserNotification_110

                        'Uses Blocking Rules' = $_pre_UsesBlockingRules_112

                        'Covers Health / ePHI Data (HIPAA)' = $_pre_CoversHealthePHIData_114

                        'Covers PII Data (SSN / Tax)' = $_pre_CoversPIIDataSSNTax_116

                        'Covers Financial Data (Credit Card)' = $_pre_CoversFinancialDataC_118

                    }
                    $CovObj.Add([pscustomobject]$covInObj) | Out-Null

                    if ($Healthcheck -and $script:HealthCheck.Purview.DLP) {
                        $CovObj | Where-Object { $_.'Has Enforced Policies (Mode: On)' -eq 'No' }   | Set-Style -Style Critical | Out-Null
                        $CovObj | Where-Object { $_.'Has Endpoint DLP Coverage' -eq 'No' }          | Set-Style -Style Warning  | Out-Null
                        $CovObj | Where-Object { $_.'Has Copilot DLP Coverage' -eq 'No' }           | Set-Style -Style Warning  | Out-Null
                        $CovObj | Where-Object { $_.'Uses Blocking Rules' -eq 'No' }                | Set-Style -Style Warning  | Out-Null
                    }

                    $CovTableParams = @{ Name = "DLP Coverage Summary - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    if ($script:Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" }
                    $CovObj | Table @CovTableParams
                    #endregion

                    #region ACSC Inline Check — DLP Policies
                    if ($script:InfoLevel.DLP -ge 3) {
                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'DLP Policies' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-1550'
                                E8          = 'N/A'
                                Description = 'DLP controls preventing unauthorised disclosure of sensitive data'
                                Check       = 'At least one DLP policy in enforced (Enable) mode'
                                Status      = if ($HasEnforcedPolicies) { 'Pass' } elseif ($DLPPolicies.Count -gt 0) { 'Partial' } else { 'Fail' }
                            }
                            [pscustomobject]@{
                                ControlId   = 'ISM-1550'
                                E8          = 'N/A'
                                Description = 'DLP rules actively block access to sensitive content'
                                Check       = 'At least one DLP rule with BlockAccess action configured'
                                Status      = if ($UsesBlockingRules) { 'Pass' } else { 'Fail' }
                            }
                        )
                    }
                    #endregion

                    #region Per-Policy Detail Sections (InfoLevel 2+)
                    if ($script:InfoLevel.DLP -ge 2) {
                        foreach ($Policy in ($DLPPolicies | Sort-Object Name)) {
                            try {
                                # Fetch rules for this policy
                                $DLPRules = Get-DlpComplianceRule -Policy $Policy.Name -ErrorAction SilentlyContinue

                                Section -Style Heading4 $Policy.Name {

                                    Paragraph "The $($Policy.Name) DLP policy is configured as follows."
                                    BlankLine

                                    #region Policy Details
                                    $DetObj = [System.Collections.ArrayList]::new()
                                        $_pre_Whatinfodoyouwanttop_179 = if ($Policy.Workload) { ($Policy.Workload -join ', ') } else { '--' }
                                        $_pre_Description_181 = if ($Policy.Comment) { $Policy.Comment } else { '--' }
                                    $detInObj = [ordered] @{
                                        'What info do you want to protect?' = $_pre_Whatinfodoyouwanttop_179
                                        'Name'                              = $Policy.Name
                                        'Description' = $_pre_Description_181
                                        'Priority'                          = $Policy.Priority
                                    }
                                    $DetObj.Add([pscustomobject]$detInObj) | Out-Null
                                    $DetTableParams = @{ Name = "Policy Details - $($Policy.Name)"; List = $true; ColumnWidths = 40, 60 }
                                    if ($script:Report.ShowTableCaptions) { $DetTableParams['Caption'] = "- $($DetTableParams.Name)" }
                                    $DetObj | Table @DetTableParams
                                    #endregion

                                    #region Locations
                                    $locExchange   = if ($Policy.ExchangeLocation)             { "Checked ($(if ($Policy.ExchangeLocation.Name -contains 'All') { 'All groups' } else { ($Policy.ExchangeLocation.Name -join ', ') }))" }             else { 'Not checked' }
                                    $locSharePoint = if ($Policy.SharePointLocation)           { "Checked ($(if ($Policy.SharePointLocation.Name -contains 'All') { 'All sites' } else { ($Policy.SharePointLocation.Name -join ', ') }))" }           else { 'Not checked' }
                                    $locOneDrive   = if ($Policy.OneDriveLocation)             { "Checked ($(if ($Policy.OneDriveLocation.Name -contains 'All') { 'All accounts' } else { ($Policy.OneDriveLocation.Name -join ', ') }))" }             else { 'Not checked' }
                                    $locTeams      = if ($Policy.TeamsLocation)                { "Checked ($(if ($Policy.TeamsLocation.Name -contains 'All') { 'All teams' } else { ($Policy.TeamsLocation.Name -join ', ') }))" }                     else { 'Not checked' }
                                    $locDevices    = if ($Policy.EndpointDlpLocation)          { "Checked ($(if ($Policy.EndpointDlpLocation.Name -contains 'All') { 'All devices' } else { ($Policy.EndpointDlpLocation.Name -join ', ') }))" }       else { 'Not checked' }
                                    $LocObj = [System.Collections.ArrayList]::new()
                                        $_pre_Onpremisesrepositori_205 = if ($Policy.OnPremisesScannerDlpLocation) { 'Checked' } else { 'Not checked' }
                                        $_pre_FabricandPowerBIwork_206 = if ($Policy.PowerBIDlpLocation) { 'Checked' } else { 'N/A' }
                                        $_pre_Microsoft365Copilota_207 = if ($Policy.AdaptiveScopes) { 'Checked' } else { 'N/A' }
                                        $_pre_Managedcloudapps_208 = if ($Policy.ThirdPartyAppDlpLocation) { 'Checked' } else { 'N/A' }
                                    $locInObj = [ordered] @{
                                        'Exchange email'                         = $locExchange
                                        'SharePoint sites'                       = $locSharePoint
                                        'OneDrive accounts'                      = $locOneDrive
                                        'Teams and channel messages'             = $locTeams
                                        'Devices'                                = $locDevices
                                        'On-premises repositories' = $_pre_Onpremisesrepositori_205
                                        'Fabric and Power BI workspaces' = $_pre_FabricandPowerBIwork_206
                                        'Microsoft 365 Copilot and Copilot Chat' = $_pre_Microsoft365Copilota_207
                                        'Managed cloud apps' = $_pre_Managedcloudapps_208
                                    }
                                    $LocObj.Add([pscustomobject]$locInObj) | Out-Null
                                    $LocTableParams = @{ Name = "Locations - $($Policy.Name)"; List = $true; ColumnWidths = 40, 60 }
                                    if ($script:Report.ShowTableCaptions) { $LocTableParams['Caption'] = "- $($LocTableParams.Name)" }
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
                                                        $scope = if ($Rule.BlockAccessScope) { " ($($script:TextInfo.ToTitleCase($Rule.BlockAccessScope)))" } else { '' }
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
                                                    $RuleObj.Add([pscustomobject]$ruleInObj) | Out-Null
                                                } catch {
                                                    Write-PScriboMessage -IsWarning -Message "DLP Rule '$($Rule.Name)': $($_.Exception.Message)" | Out-Null
                                                }
                                            }

                                            if ($RuleObj.Count -gt 0) {
                                                $RuleTableParams = @{ Name = "Policy Settings - $($Policy.Name)"; List = $false; ColumnWidths = 28, 36, 36 }
                                                if ($script:Report.ShowTableCaptions) { $RuleTableParams['Caption'] = "- $($RuleTableParams.Name)" }
                                                $RuleObj | Table @RuleTableParams
                                            }
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "DLP Rules for '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                                    }
                                    #endregion

                                    #region User Notifications
                                    $NotifObj = [System.Collections.ArrayList]::new()
                                        $_pre_Usenotificationstoin_327 = if ($DLPRules | Where-Object { $_.NotifyUser }) { 'On' } else { 'Off' }
                                    $notifInObj = [ordered] @{
                                        'Use notifications to inform your users and help educate them on the proper use of sensitive info.' = $_pre_Usenotificationstoin_327
                                    }
                                    $NotifObj.Add([pscustomobject]$notifInObj) | Out-Null
                                    $NotifTableParams = @{ Name = "User Notifications - $($Policy.Name)"; List = $true; ColumnWidths = 70, 30 }
                                    if ($script:Report.ShowTableCaptions) { $NotifTableParams['Caption'] = "- $($NotifTableParams.Name)" }
                                    $NotifObj | Table @NotifTableParams
                                    #endregion

                                    #region Incident Reports
                                    $IncObj = [System.Collections.ArrayList]::new()
                                    $FirstRule = $DLPRules | Where-Object { $_.ReportSeverityLevel } | Select-Object -First 1
                                    $firstRuleSev = if ($FirstRule) { $script:TextInfo.ToTitleCase($FirstRule.ReportSeverityLevel) } else { 'Low' }
                                        $_pre_Sendanalerttoadminsw_342 = if ($DLPRules | Where-Object { $_.AlertProperties }) { 'On' } else { 'Off' }
                                        $_pre_Useemailincidentrepo_343 = if ($DLPRules | Where-Object { $_.GenerateIncidentReport }) { 'On' } else { 'Off' }
                                    $incInObj = [ordered] @{
                                        'Use this severity level in admin alerts and reports:' = $firstRuleSev
                                        'Send an alert to admins when a rule match occurs.' = $_pre_Sendanalerttoadminsw_342
                                        'Use email incident reports to notify you when a policy match occurs.' = $_pre_Useemailincidentrepo_343
                                    }
                                    $IncObj.Add([pscustomobject]$incInObj) | Out-Null
                                    $IncTableParams = @{ Name = "Incident Reports - $($Policy.Name)"; List = $true; ColumnWidths = 70, 30 }
                                    if ($script:Report.ShowTableCaptions) { $IncTableParams['Caption'] = "- $($IncTableParams.Name)" }
                                    $IncObj | Table @IncTableParams
                                    #endregion

                                    #region Additional Options
                                    $AddObj = [System.Collections.ArrayList]::new()
                                    $StopProcessing = $DLPRules | Where-Object { $_.StopPolicyProcessing } | Select-Object -First 1
                                    $_preStopProc = if ($StopProcessing) { 'Checked' } else { 'Not checked' }
                                    $addInObj = [ordered] @{
                                        "If there's a match for this rule, stop processing additional DLP policies and rules." = $_preStopProc
                                    }
                                    $AddObj.Add([pscustomobject]$addInObj) | Out-Null
                                    $AddTableParams = @{ Name = "Additional Options - $($Policy.Name)"; List = $true; ColumnWidths = 70, 30 }
                                    if ($script:Report.ShowTableCaptions) { $AddTableParams['Caption'] = "- $($AddTableParams.Name)" }
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
                                            default                      { $script:TextInfo.ToTitleCase($Policy.Mode) }
                                        }
                                    }
                                    $ModeObj.Add([pscustomobject]$modeInObj) | Out-Null
                                    $ModeTableParams = @{ Name = "Policy Mode - $($Policy.Name)"; List = $true; ColumnWidths = 40, 60 }
                                    if ($script:Report.ShowTableCaptions) { $ModeTableParams['Caption'] = "- $($ModeTableParams.Name)" }
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
