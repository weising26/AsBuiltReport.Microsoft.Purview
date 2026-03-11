function Get-AbrPurviewEDiscovery {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview eDiscovery information.
    .DESCRIPTION
        Collects and reports on eDiscovery Cases, Holds, and Searches configured
        in Microsoft Purview compliance portal.
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
        Write-PScriboMessage -Message "Collecting Microsoft Purview eDiscovery information for tenant $TenantId."
        Show-AbrDebugExecutionTime -Start -TitleMessage 'eDiscovery'
    }

    process {
        # Standard eDiscovery Cases
        try {
            $Cases = Get-ComplianceCase -ErrorAction Stop

            if ($Cases) {
                Section -Style Heading3 'eDiscovery Cases' {
                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Case in $Cases) {
                        try {
                            $inObj = [ordered] @{
                                'Case Name'     = $Case.Name
                                'Status'        = $TextInfo.ToTitleCase($Case.Status)
                                'Case Type'     = $TextInfo.ToTitleCase($Case.CaseType)
                                'Closed By'     = $Case.ClosedBy
                                'Closed Time'   = if ($Case.ClosedDateTime) { $Case.ClosedDateTime.ToString('yyyy-MM-dd') } else { 'N/A' }
                                'Created'       = $Case.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "eDiscovery Case '$($Case.Name)': $($_.Exception.Message)"
                        }
                    }

                    if ($HealthCheck.Purview.EDiscovery) {
                        $OutObj | Where-Object { $_.'Status' -eq 'Closed' } | Set-Style -Style Warning
                    }

                    $TableParams = @{
                        Name         = "eDiscovery Cases - $TenantId"
                        List         = $false
                        ColumnWidths = 25, 12, 13, 20, 15, 15
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Case Name' | Table @TableParams

                    # Case Holds per case
                    foreach ($Case in ($Cases | Where-Object { $_.Status -ne 'Closed' })) {
                        try {
                            $Holds = Get-CaseHoldPolicy -Case $Case.Name -ErrorAction SilentlyContinue
                            if ($Holds) {
                                Section -ExcludeFromTOC -Style NOTOCHeading4 "Holds: $($Case.Name)" {
                                    $HoldObj = [System.Collections.ArrayList]::new()
                                    foreach ($Hold in $Holds) {
                                        try {
                                            $holdInObj = [ordered] @{
                                                'Hold Name'         = $Hold.Name
                                                'Enabled'           = $Hold.Enabled
                                                'Status'            = $TextInfo.ToTitleCase($Hold.Status)
                                                'Exchange Location' = ($Hold.ExchangeLocation.Name -join ', ')
                                                'SharePoint Location'= ($Hold.SharePointLocation.Name -join ', ')
                                            }
                                            $HoldObj.Add([pscustomobject](ConvertTo-HashToYN $holdInObj)) | Out-Null
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "Case Hold '$($Hold.Name)': $($_.Exception.Message)"
                                        }
                                    }
                                    if ($HealthCheck.Purview.EDiscovery) {
                                        $HoldObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical
                                    }
                                    $HoldTableParams = @{
                                        Name         = "Case Holds - $($Case.Name)"
                                        List         = $false
                                        ColumnWidths = 25, 10, 13, 26, 26
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $HoldTableParams['Caption'] = "- $($HoldTableParams.Name)"
                                    }
                                    $HoldObj | Sort-Object -Property 'Hold Name' | Table @HoldTableParams
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Case Holds for '$($Case.Name)': $($_.Exception.Message)"
                        }
                    }
                }
            } else {
                Write-PScriboMessage -Message "No eDiscovery Case information found for $TenantId. Disabling section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "eDiscovery Section: $($_.Exception.Message)"
        }

        # Content Searches
        try {
            $Searches = Get-ComplianceSearch -ErrorAction Stop

            if ($Searches) {
                Section -Style Heading3 'Content Searches' {
                    $OutObj = [System.Collections.ArrayList]::new()

                    foreach ($Search in $Searches) {
                        try {
                            $inObj = [ordered] @{
                                'Search Name'       = $Search.Name
                                'Status'            = $TextInfo.ToTitleCase($Search.Status)
                                'Items Found'       = $Search.Items
                                'Size (MB)'         = [math]::Round($Search.Size / 1MB, 2)
                                'Content Match Query'= $Search.ContentMatchQuery
                                'Created'           = $Search.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Content Search '$($Search.Name)': $($_.Exception.Message)"
                        }
                    }

                    $TableParams = @{
                        Name         = "Content Searches - $TenantId"
                        List         = $false
                        ColumnWidths = 22, 12, 12, 10, 32, 12
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Search Name' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Content Search information found for $TenantId. Disabling section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Content Search Section: $($_.Exception.Message)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'eDiscovery'
    }
}