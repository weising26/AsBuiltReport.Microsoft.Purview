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
            $CoreCases     = @(Get-ComplianceCase -CaseType Core     -ErrorAction SilentlyContinue)
            $AdvancedCases = @(Get-ComplianceCase -CaseType Advanced  -ErrorAction SilentlyContinue)
            $AllCases      = @($CoreCases) + @($AdvancedCases)
            $AllHolds      = @(Get-CaseHoldPolicy -ErrorAction SilentlyContinue)

            if ($AllCases.Count -gt 0) {
                Section -Style Heading3 'eDiscovery Cases' {

                    #region Coverage Summary
                    $CovObj = [System.Collections.ArrayList]::new()
                    $covInObj = [ordered] @{
                        'Core eDiscovery Cases'     = ($CoreCases.Count -gt 0)
                        'Advanced eDiscovery Cases' = ($AdvancedCases.Count -gt 0)
                        'Active Case Holds'         = ($AllHolds.Count -gt 0)
                    }
                    $CovObj.Add([pscustomobject](ConvertTo-HashToYN $covInObj)) | Out-Null

                    $null = (& {
                    if ($HealthCheck.Purview.EDiscovery) {
                        $CovObj | Where-Object { $_.'Active Case Holds' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $CovTableParams = @{ Name = "eDiscovery Coverage Summary - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    $null = (& { if ($Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" } })
                    $CovObj | Table @CovTableParams
                    #endregion

                    #region Cases Summary Table
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Case in $AllCases) {
                        try {
                            $inObj = [ordered] @{
                                'Case Name'   = $Case.Name
                                'Status'      = $TextInfo.ToTitleCase($Case.Status)
                                'Case Type'   = $TextInfo.ToTitleCase($Case.CaseType)
                                'Members'     = if ($Case.Members) { ($Case.Members -join ', ') } else { 'N/A' }
                                'Closed By'   = if ($Case.ClosedBy) { $Case.ClosedBy } else { 'N/A' }
                                'Closed Time' = if ($Case.ClosedDateTime) { $Case.ClosedDateTime.ToString('yyyy-MM-dd') } else { 'N/A' }
                                'Created'     = $Case.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "eDiscovery Case '$($Case.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.EDiscovery) {
                        $OutObj | Where-Object { $_.'Status' -eq 'Closed' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $TableParams = @{ Name = "eDiscovery Cases - $TenantId"; List = $false; ColumnWidths = 20, 10, 12, 20, 14, 12, 12 }
                    $null = (& { if ($Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" } })
                    $OutObj | Sort-Object -Property 'Case Name' | Table @TableParams
                    #endregion

                    #region Case Holds per case (InfoLevel 2+)
                    if ($InfoLevel.EDiscovery -ge 2) {
                        foreach ($Case in ($AllCases | Where-Object { $_.Status -ne 'Closed' })) {
                            try {
                                $Holds = Get-CaseHoldPolicy -Case $Case.Name -ErrorAction SilentlyContinue
                                if ($Holds) {
                                    Section -ExcludeFromTOC -Style NOTOCHeading4 "Holds: $($Case.Name)" {
                                        $HoldObj = [System.Collections.ArrayList]::new()
                                        foreach ($Hold in $Holds) {
                                            try {
                                                $holdInObj = [ordered] @{
                                                    'Hold Name'          = $Hold.Name
                                                    'Enabled'            = $Hold.Enabled
                                                    'Status'             = $TextInfo.ToTitleCase($Hold.Status)
                                                    'Exchange Location'  = if ($Hold.ExchangeLocation.Name) { ($Hold.ExchangeLocation.Name -join ', ') } else { 'N/A' }
                                                    'SharePoint Location'= if ($Hold.SharePointLocation.Name) { ($Hold.SharePointLocation.Name -join ', ') } else { 'N/A' }
                                                }
                                                $HoldObj.Add([pscustomobject](ConvertTo-HashToYN $holdInObj)) | Out-Null
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "Case Hold '$($Hold.Name)': $($_.Exception.Message)" | Out-Null
                                            }
                                        }
                                        $null = (& {
                                        if ($HealthCheck.Purview.EDiscovery) {
                                            $HoldObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                                        }
                                        })
                                        $HoldTableParams = @{ Name = "Case Holds - $($Case.Name)"; List = $false; ColumnWidths = 22, 10, 12, 28, 28 }
                                        $null = (& { if ($Report.ShowTableCaptions) { $HoldTableParams['Caption'] = "- $($HoldTableParams.Name)" } })
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
        if ($InfoLevel.EDiscovery -ge 2) {
            try {
                $Searches = Get-ComplianceSearch -ErrorAction Stop

                if ($Searches) {
                    Section -Style Heading3 'Content Searches' {
                        $OutObj = [System.Collections.ArrayList]::new()

                        foreach ($Search in $Searches) {
                            try {
                                $inObj = [ordered] @{
                                    'Search Name'        = $Search.Name
                                    'Status'             = $TextInfo.ToTitleCase($Search.Status)
                                    'Items Found'        = $Search.Items
                                    'Size (MB)'          = [math]::Round($Search.Size / 1MB, 2)
                                    'Content Match Query'= if ($Search.ContentMatchQuery) { $Search.ContentMatchQuery } else { '--' }
                                    'Created'            = $Search.WhenCreated.ToString('yyyy-MM-dd')
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "Content Search '$($Search.Name)': $($_.Exception.Message)" | Out-Null
                            }
                        }

                        $TableParams = @{ Name = "Content Searches - $TenantId"; List = $false; ColumnWidths = 22, 12, 10, 10, 34, 12 }
                        $null = (& { if ($Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" } })
                        $OutObj | Sort-Object -Property 'Search Name' | Table @TableParams
                    }
                } else {
                    Write-PScriboMessage -Message "No Content Search information found for $TenantId. Disabling section." | Out-Null
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "Content Search Section: $($_.Exception.Message)" | Out-Null
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'eDiscovery'
    }
}
