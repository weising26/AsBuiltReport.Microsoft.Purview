function Get-AbrPurviewEDiscovery {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview eDiscovery information.
    .DESCRIPTION
        Collects and reports on eDiscovery Cases, Holds, and Searches configured
        in Microsoft Purview compliance portal.
    .NOTES
        Version:        0.1.0
        Author:         Pai Wei Sing
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory)]
        [string]$TenantId
    )

    begin {
        Write-PScriboMessage -Message "Collecting Microsoft Purview eDiscovery information for tenant $TenantId." | Out-Null
        Show-AbrDebugExecutionTime -Start -TitleMessage 'eDiscovery'
    }

    process {
        # Collect Core and Advanced cases separately
        try {
            # CaseType enum changed in REST API: Core -> eDiscovery, Advanced -> AdvancedEdiscovery
            $CoreCases     = @(try { Get-ComplianceCase -CaseType eDiscovery       -ErrorAction Stop } catch { @() })
            $AdvancedCases = @(try { Get-ComplianceCase -CaseType AdvancedEdiscovery -ErrorAction Stop } catch { @() })
            $AllCases      = @($CoreCases) + @($AdvancedCases)

            # Collect holds per-case to avoid permission errors from the parameterless call.
            # The parameterless Get-CaseHoldPolicy requires elevated roles that may not be present.
            $AllHolds = [System.Collections.ArrayList]::new()
            foreach ($c in $AllCases) {
                try {
                    $holds = Get-CaseHoldPolicy -Case $c.Name -ErrorAction SilentlyContinue
                    foreach ($h in $holds) { $AllHolds.Add($h) | Out-Null }
                } catch { }
            }

            if ($AllCases.Count -gt 0) {
                Section -Style Heading3 'eDiscovery Cases' {

                    #region Coverage Summary
                    $CovObj = [System.Collections.ArrayList]::new()
                        $_pre_CoreeDiscoveryCases_49 = if ($CoreCases.Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_AdvancedeDiscoveryCa_50 = if ($AdvancedCases.Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_ActiveCaseHolds_51 = if ($AllHolds.Count -gt 0) { 'Yes' } else { 'No' }
                    $covInObj = [ordered] @{
                        'Core eDiscovery Cases' = $_pre_CoreeDiscoveryCases_49
                        'Advanced eDiscovery Cases' = $_pre_AdvancedeDiscoveryCa_50
                        'Active Case Holds' = $_pre_ActiveCaseHolds_51
                    }
                    $CovObj.Add([pscustomobject]$covInObj) | Out-Null

                    if ($Healthcheck -and $script:HealthCheck.Purview.EDiscovery) {
                        $CovObj | Where-Object { $_.'Active Case Holds' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }

                    $CovTableParams = @{ Name = "eDiscovery Coverage Summary - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    if ($script:Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" }
                    $CovObj | Table @CovTableParams
                    #endregion

                    #region Cases Summary Table
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Case in $AllCases) {
                        try {
                            $caseClosedTime = if ($Case.ClosedDateTime) { $Case.ClosedDateTime.ToString('yyyy-MM-dd') } else { 'N/A' }
                            $caseCreated    = if ($Case.WhenCreated) { $Case.WhenCreated.ToString('yyyy-MM-dd') } else { 'N/A' }
                            $caseTypeDisplay = switch ($Case.CaseType) {
                                'eDiscovery'         { 'Core eDiscovery' }
                                'AdvancedEdiscovery' { 'Advanced eDiscovery' }
                                default              { $Case.CaseType }
                            }
                                $_pre_Members_77 = if ($Case.Members) { ($Case.Members -join ', ') } else { 'N/A' }
                                $_pre_ClosedBy_78 = if ($Case.ClosedBy) { $Case.ClosedBy } else { 'N/A' }
                            $inObj = [ordered] @{
                                'Case Name'   = $Case.Name
                                'Status'      = $script:TextInfo.ToTitleCase($Case.Status)
                                'Case Type'   = $caseTypeDisplay
                                'Members' = $_pre_Members_77
                                'Closed By' = $_pre_ClosedBy_78
                                'Closed Time' = $caseClosedTime
                                'Created'     = $caseCreated
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "eDiscovery Case '$($Case.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.EDiscovery) {
                        $OutObj | Where-Object { $_.'Status' -eq 'Closed' } | Set-Style -Style Warning | Out-Null
                    }

                    $TableParams = @{ Name = "eDiscovery Cases - $TenantId"; List = $false; ColumnWidths = 20, 10, 12, 20, 14, 12, 12 }
                    if ($script:Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" }
                    if ($OutObj.Count -gt 0) {
                        $OutObj | Sort-Object -Property 'Case Name' | Table @TableParams
                    }
                    #endregion

                    #region ACSC Inline Check — eDiscovery Cases
                    if ($script:InfoLevel.EDiscovery -ge 3) {
                        $HasActiveHolds = [bool]($AllHolds | Where-Object { $_.Enabled })
                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'eDiscovery Cases' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-0854'
                                E8          = 'N/A'
                                Description = 'Legal hold capability exists to preserve evidence for investigations'
                                Check       = 'At least one active eDiscovery case hold configured'
                                Status      = if ($HasActiveHolds) { 'Pass' } elseif ($AllCases.Count -gt 0) { 'Partial' } else { 'Manual' }
                            }
                        )
                    }
                    #endregion

                    #region Case Holds per case (InfoLevel 2+)
                    if ($script:InfoLevel.EDiscovery -ge 2) {
                        foreach ($Case in ($AllCases | Where-Object { $_.Status -ne 'Closed' })) {
                            try {
                                $Holds = Get-CaseHoldPolicy -Case $Case.Name -ErrorAction SilentlyContinue
                                if ($Holds) {
                                    Section -ExcludeFromTOC -Style NOTOCHeading4 "Holds: $($Case.Name)" {
                                        $HoldObj = [System.Collections.ArrayList]::new()
                                        foreach ($Hold in $Holds) {
                                            try {
                                                    $_pre_Enabled_128 = if ($Hold.Enabled) { 'Yes' } else { 'No' }
                                                    $_pre_ExchangeLocation_130 = if ($Hold.ExchangeLocation.Name) { ($Hold.ExchangeLocation.Name -join ', ') } else { 'N/A' }
                                                    $_pre_SharePointLocation_131 = if ($Hold.SharePointLocation.Name) { ($Hold.SharePointLocation.Name -join ', ') } else { 'N/A' }
                                                $holdInObj = [ordered] @{
                                                    'Hold Name'          = $Hold.Name
                                                    'Enabled' = $_pre_Enabled_128
                                                    'Status'             = $script:TextInfo.ToTitleCase($Hold.Status)
                                                    'Exchange Location' = $_pre_ExchangeLocation_130
                                                    'SharePoint Location' = $_pre_SharePointLocation_131
                                                }
                                                $HoldObj.Add([pscustomobject]$holdInObj) | Out-Null
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "Case Hold '$($Hold.Name)': $($_.Exception.Message)" | Out-Null
                                            }
                                        }
                                        if ($Healthcheck -and $script:HealthCheck.Purview.EDiscovery) {
                                            $HoldObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                                        }
                                        $HoldTableParams = @{ Name = "Case Holds - $($Case.Name)"; List = $false; ColumnWidths = 22, 10, 12, 28, 28 }
                                        if ($script:Report.ShowTableCaptions) { $HoldTableParams['Caption'] = "- $($HoldTableParams.Name)" }
                                        $HoldObj | Sort-Object -Property 'Hold Name' | Table @HoldTableParams
                                    }
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "Case Holds for '$($Case.Name)': $($_.Exception.Message)" | Out-Null
                            }
                        }
                    }
                    #endregion
                }
            } else {
                Write-PScriboMessage -Message "No eDiscovery Case information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "eDiscovery Section: $($_.Exception.Message)" | Out-Null
        }

        # Content Searches (InfoLevel 2+)
        if ($script:InfoLevel.EDiscovery -ge 2) {
            try {
                $Searches = Get-ComplianceSearch -ErrorAction Stop

                if ($Searches) {
                    Section -Style Heading3 'Content Searches' {
                        $OutObj = [System.Collections.ArrayList]::new()

                        foreach ($Search in $Searches) {
                            try {
                                    $_pre_ContentMatchQuery_179 = if ($Search.ContentMatchQuery) { $Search.ContentMatchQuery } else { '--' }
                                $inObj = [ordered] @{
                                    'Search Name'        = $Search.Name
                                    'Status'             = $script:TextInfo.ToTitleCase($Search.Status)
                                    'Items Found'        = $Search.Items
                                    'Size (MB)'          = [math]::Round($Search.Size / 1MB, 2)
                                    'Content Match Query' = $_pre_ContentMatchQuery_179
                                    'Created'            = $Search.WhenCreated.ToString('yyyy-MM-dd')
                                }
                                $OutObj.Add([pscustomobject]$inObj) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "Content Search '$($Search.Name)': $($_.Exception.Message)" | Out-Null
                            }
                        }

                        $TableParams = @{ Name = "Content Searches - $TenantId"; List = $false; ColumnWidths = 22, 12, 10, 10, 34, 12 }
                        if ($script:Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" }
                        $OutObj | Sort-Object -Property 'Search Name' | Table @TableParams
                    }
                } else {
                    Write-PScriboMessage -Message "No Content Search information found for $TenantId. Disabling section." | Out-Null
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "Content Search Section: $($_.Exception.Message)" | Out-Null
            }
        }

        #region Advanced eDiscovery Settings (MCCA check-eDiscovery102)
        try {
            $AdvancedCases = Get-ComplianceCase -CaseType AdvancedEdiscovery -ErrorAction SilentlyContinue

            if ($AdvancedCases) {
                Section -Style Heading3 'Advanced eDiscovery Case Details' {
                    Paragraph "Advanced eDiscovery provides custodian management, legal hold notifications, and built-in analytics. The following shows member assignments and hold status per case."
                    BlankLine

                    foreach ($Case in $AdvancedCases) {
                        try {
                            Section -Style Heading4 $Case.Name {
                                # Members
                                $Members = Get-ComplianceCaseMember -Case $Case.Name -ErrorAction SilentlyContinue
                                $Holds   = Get-CaseHoldPolicy -Case $Case.Name -ErrorAction SilentlyContinue

                                $_pre_Status       = $script:TextInfo.ToTitleCase($Case.Status)
                                $_pre_MemberCount  = if ($Members) { @($Members).Count } else { 0 }
                                $_pre_HoldCount    = if ($Holds)   { @($Holds).Count }   else { 0 }
                                $_pre_ActiveHolds  = if ($Holds)   { @($Holds | Where-Object { $_.Enabled }).Count } else { 0 }
                                $_pre_Created      = if ($Case.CreatedDateTime) { ([datetime]$Case.CreatedDateTime).ToString('yyyy-MM-dd') } else { 'N/A' }

                                $caseInObj = [ordered] @{
                                    'Case Name'           = $Case.Name
                                    'Status'              = $_pre_Status
                                    'Members Assigned'    = $_pre_MemberCount
                                    'Total Holds'         = $_pre_HoldCount
                                    'Active Holds'        = $_pre_ActiveHolds
                                    'Created'             = $_pre_Created
                                }
                                $CaseDetailObj = [System.Collections.ArrayList]::new()
                                $CaseDetailObj.Add([pscustomobject]$caseInObj) | Out-Null

                                if ($Healthcheck -and $script:HealthCheck.Purview.EDiscovery) {
                                    $CaseDetailObj | Where-Object { $_.'Members Assigned' -eq 0 } | Set-Style -Style Warning  | Out-Null
                                    $CaseDetailObj | Where-Object { $_.'Active Holds' -eq 0 }     | Set-Style -Style Warning  | Out-Null
                                }

                                $CaseDetailTableParams = @{ Name = "Advanced eDiscovery - $($Case.Name)"; List = $true; ColumnWidths = 40, 60 }
                                if ($script:Report.ShowTableCaptions) { $CaseDetailTableParams['Caption'] = "- $($CaseDetailTableParams.Name)" }
                                $CaseDetailObj | Table @CaseDetailTableParams

                                # Members table
                                if ($Members) {
                                    $MemObj = [System.Collections.ArrayList]::new()
                                    foreach ($Member in $Members) {
                                        $memInObj = [ordered] @{
                                            'Display Name' = $Member.DisplayName
                                            'Role'         = if ($Member.Role) { $Member.Role } else { 'Member' }
                                            'Windows Live ID' = if ($Member.WindowsLiveID) { $Member.WindowsLiveID } else { '--' }
                                        }
                                        $MemObj.Add([pscustomobject]$memInObj) | Out-Null
                                    }
                                    $MemTableParams = @{ Name = "Case Members - $($Case.Name)"; List = $false; ColumnWidths = 35, 25, 40 }
                                    if ($script:Report.ShowTableCaptions) { $MemTableParams['Caption'] = "- $($MemTableParams.Name)" }
                                    $MemObj | Table @MemTableParams
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Advanced eDiscovery Case '$($Case.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Advanced eDiscovery cases found for $TenantId." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Advanced eDiscovery Settings Section: $($_.Exception.Message)" | Out-Null
        }
        #endregion
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'eDiscovery'
    }
}
