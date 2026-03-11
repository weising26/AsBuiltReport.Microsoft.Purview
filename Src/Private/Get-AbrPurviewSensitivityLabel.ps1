function Get-AbrPurviewSensitivityLabel {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory)]
        [string]$TenantId
    )

    begin {
        Write-PScriboMessage -Message "Collecting Microsoft Purview Sensitivity Label information for tenant $TenantId." | Out-Null
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Sensitivity Labels'
    }

    process {
        #region Sensitivity Labels
        try {
            $Labels = Get-Label -ErrorAction Stop

            if ($Labels) {
                Section -Style Heading3 'Sensitivity Labels' {

                    # Summary Table
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Label in $Labels) {
                        try {
                            $inObj = [ordered] @{
                                'Name'            = $Label.DisplayName
                                'Priority'        = $Label.Priority
                                'Enabled'         = $Label.Disabled -eq $false
                                'Scope'           = ($Label.ContentType -join ', ')
                                'Encryption'      = $Label.EncryptionEnabled
                                'Content Marking' = $Label.ContentMarkingEnabled
                                'Auto Labeling'   = $Label.AutoLabelingEnabled
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Sensitivity Label '$($Label.DisplayName)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.InformationProtection) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }
                    })

                    $TableParams = @{ Name = "Sensitivity Labels - $TenantId"; List = $false; ColumnWidths = 24, 10, 10, 18, 13, 13, 12 }
                    $null = (& { if ($Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" } })
                    $OutObj | Sort-Object -Property 'Priority' | Table @TableParams

                    #region Coverage Summary
                    $HasEncryption     = $Labels | Where-Object { $_.EncryptionEnabled }
                    $HasAutoLabeling   = $Labels | Where-Object { $_.AutoLabelingEnabled }
                    $HasContentMarking = $Labels | Where-Object { $_.ContentMarkingEnabled }
                    $AutoLabelPolicies = try { Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue } catch { $null }

                    $CovObj = [System.Collections.ArrayList]::new()
                    $covInObj = [ordered] @{
                        'Labels Configured'                    = if ($Labels.Count -gt 0) { 'Yes' } else { 'No' }
                        'Labels with Encryption'               = if ($null -ne $HasEncryption) { 'Yes' } else { 'No' }
                        'Labels with Content Marking'          = if ($null -ne $HasContentMarking) { 'Yes' } else { 'No' }
                        'Labels with Auto-Labeling (per-label)'= if ($null -ne $HasAutoLabeling) { 'Yes' } else { 'No' }
                        'Auto-Labeling Policies Configured'    = if ($null -ne $AutoLabelPolicies -and @($AutoLabelPolicies).Count -gt 0) { 'Yes' } else { 'No' }
                    }
                    $CovObj.Add([pscustomobject](ConvertTo-HashToYN $covInObj)) | Out-Null

                    $null = (& {
                    if ($HealthCheck.Purview.InformationProtection) {
                        $CovObj | Where-Object { $_.'Labels Configured' -eq 'No' }                     | Set-Style -Style Critical | Out-Null
                        $CovObj | Where-Object { $_.'Labels with Encryption' -eq 'No' }                | Set-Style -Style Warning  | Out-Null
                        $CovObj | Where-Object { $_.'Auto-Labeling Policies Configured' -eq 'No' }     | Set-Style -Style Warning  | Out-Null
                    }
                    })

                    $CovTableParams = @{ Name = "Information Protection Coverage - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    $null = (& { if ($Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" } })
                    $CovObj | Table @CovTableParams
                    #endregion

                    # Per-Label Detail Sections
                    if ($InfoLevel.InformationProtection -ge 2) {
                        foreach ($Label in ($Labels | Sort-Object Priority)) {
                                                try {
                                                    Section -Style Heading4 $Label.DisplayName {

                                                        Paragraph "Logicalis implemented the $($Label.DisplayName) sensitivity label with the following configuration."
                                                        BlankLine

                                                        #region Label Details
                                                        $GenObj = [System.Collections.ArrayList]::new()
                                                        $genInObj = [ordered] @{
                                                            'Parent Label'              = if ($Label.ParentId) { $Label.ParentId } else { 'N/A' }
                                                            'Name'                      = $Label.Name
                                                            'Display Name'              = $Label.DisplayName
                                                            'Label Priority'            = $Label.Priority
                                                            'Description for Users'     = if ($Label.Tooltip) { $Label.Tooltip } else { '--' }
                                                            'Description for Admins'    = if ($Label.Comment) { $Label.Comment } else { '--' }
                                                            'Label Colour'              = if ($Label.LabelColor) { $Label.LabelColor } else { 'None' }
                                                        }
                                                        $GenObj.Add([pscustomobject](ConvertTo-HashToYN $genInObj)) | Out-Null
                                                        $GenTableParams = @{ Name = "Label Details - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                                        $null = (& { if ($Report.ShowTableCaptions) { $GenTableParams['Caption'] = "- $($GenTableParams.Name)" } })
                                                        $GenObj | Table @GenTableParams
                                                        #endregion

                                                        #region Scope
                                                        $ScopeObj = [System.Collections.ArrayList]::new()
                                                        $ContentTypes = $Label.ContentType
                                                        $scopeInObj = [ordered] @{
                                                            'Files & other data assets' = if ($ContentTypes -contains 'File') { 'Checked' } else { 'Not checked' }
                                                            'Emails'                    = if ($ContentTypes -contains 'Email') { 'Checked' } else { 'Not checked' }
                                                            'Meetings'                  = if ($ContentTypes -contains 'Meeting') { 'Checked' } else { 'Not checked' }
                                                            'Groups & sites'            = if ($ContentTypes -contains 'Site') { 'Checked' } else { 'Not checked' }
                                                            'Schematized data assets'   = if ($ContentTypes -contains 'SchematizedData') { 'Checked' } else { 'Not checked' }
                                                        }
                                                        $ScopeObj.Add([pscustomobject](ConvertTo-HashToYN $scopeInObj)) | Out-Null
                                                        $ScopeTableParams = @{ Name = "Scope - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                                        $null = (& { if ($Report.ShowTableCaptions) { $ScopeTableParams['Caption'] = "- $($ScopeTableParams.Name)" } })
                                                        $ScopeObj | Table @ScopeTableParams
                                                        #endregion

                                                        #region Protection Settings
                                                        $ProtObj = [System.Collections.ArrayList]::new()
                                                        $protInObj = [ordered] @{
                                                            'Control access (Encryption)'            = if ($Label.EncryptionEnabled) { 'Checked' } else { 'Not checked' }
                                                            'Apply content marking'                  = if ($Label.ContentMarkingEnabled) { 'Checked' } else { 'Not checked' }
                                                            'Protect Teams meetings and chats'       = 'N/A (Teams Premium licensing required)'
                                                        }
                                                        $ProtObj.Add([pscustomobject](ConvertTo-HashToYN $protInObj)) | Out-Null
                                                        $ProtTableParams = @{ Name = "Protection Settings - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                                        $null = (& { if ($Report.ShowTableCaptions) { $ProtTableParams['Caption'] = "- $($ProtTableParams.Name)" } })
                                                        $ProtObj | Table @ProtTableParams
                                                        #endregion

                                                        #region Encryption Details
                                                        if ($Label.EncryptionEnabled) {
                                                            $EncObj = [System.Collections.ArrayList]::new()

                                                            # Parse rights definitions into readable format
                                                            $RightsDisplay = if ($Label.EncryptionRightsDefinitions) {
                                                                ($Label.EncryptionRightsDefinitions | ForEach-Object { "$($_.Identity): $($_.Rights -join ', ')" }) -join '; '
                                                            } else { 'N/A' }

                                                            $encInObj = [ordered] @{
                                                                'Encryption'                         = 'Enabled'
                                                                'Assign permissions now or let users decide' = if ($Label.EncryptionAdhocPermissions) { 'Let users assign permissions' } else { 'Assign permissions now' }
                                                                'Rights Definitions'                 = $RightsDisplay
                                                                'Do Not Forward'                     = if ($Label.EncryptionDoNotForward) { 'Checked' } else { 'Not checked' }
                                                                'Encrypt Only'                       = if ($Label.EncryptionEncryptOnly) { 'Checked' } else { 'Not checked' }
                                                                'Content Expiry'                     = if ($Label.EncryptionContentExpiredOnDateInDaysOrNever -and $Label.EncryptionContentExpiredOnDateInDaysOrNever -ne 'Never') { "$($Label.EncryptionContentExpiredOnDateInDaysOrNever) days" } else { 'Never' }
                                                                'Offline Access Duration'            = if ($Label.EncryptionOfflineAccessDays -ge 0) { "$($Label.EncryptionOfflineAccessDays) days" } else { 'Always' }
                                                                'Double Key Encryption URL'          = if ($Label.EncryptionDoubleKeyEncryptionUrl) { $Label.EncryptionDoubleKeyEncryptionUrl } else { 'N/A' }
                                                            }
                                                            $EncObj.Add([pscustomobject](ConvertTo-HashToYN $encInObj)) | Out-Null
                                                            $EncTableParams = @{ Name = "Encryption - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                                            $null = (& { if ($Report.ShowTableCaptions) { $EncTableParams['Caption'] = "- $($EncTableParams.Name)" } })
                                                            $EncObj | Table @EncTableParams
                                                        }
                                                        #endregion

                                                        #region Content Marking
                                                        $CmObj = [System.Collections.ArrayList]::new()
                                                        $cmInObj = [ordered] @{
                                                            'Content marking'      = if ($Label.ContentMarkingEnabled) { 'Enabled' } else { 'Disabled' }
                                                            'Add a watermark'      = if ($Label.ContentMarkingWaterMarkEnabled) { 'Checked' } else { 'Not checked' }
                                                            'Add a header'         = if ($Label.ContentMarkingHeaderEnabled) { 'Checked' } else { 'Not checked' }
                                                            '- Header text'        = if ($Label.ContentMarkingHeaderText) { $Label.ContentMarkingHeaderText } else { 'N/A' }
                                                            '- Font size'          = if ($Label.ContentMarkingHeaderFontSize) { $Label.ContentMarkingHeaderFontSize } else { 'N/A' }
                                                            '- Font colour'        = if ($Label.ContentMarkingHeaderFontColor) { $Label.ContentMarkingHeaderFontColor } else { 'N/A' }
                                                            '- Align text'         = if ($Label.ContentMarkingHeaderAlignment) { $TextInfo.ToTitleCase($Label.ContentMarkingHeaderAlignment) } else { 'N/A' }
                                                            'Add a footer'         = if ($Label.ContentMarkingFooterEnabled) { 'Checked' } else { 'Not checked' }
                                                            '- Footer text'        = if ($Label.ContentMarkingFooterText) { $Label.ContentMarkingFooterText } else { 'N/A' }
                                                            '- Font size '         = if ($Label.ContentMarkingFooterFontSize) { $Label.ContentMarkingFooterFontSize } else { 'N/A' }
                                                            '- Font colour '       = if ($Label.ContentMarkingFooterFontColor) { $Label.ContentMarkingFooterFontColor } else { 'N/A' }
                                                            '- Align text '        = if ($Label.ContentMarkingFooterAlignment) { $TextInfo.ToTitleCase($Label.ContentMarkingFooterAlignment) } else { 'N/A' }
                                                        }
                                                        if ($Label.ContentMarkingWaterMarkEnabled) {
                                                            $cmInObj['- Watermark text']        = if ($Label.ContentMarkingWaterMarkText) { $Label.ContentMarkingWaterMarkText } else { 'N/A' }
                                                            $cmInObj['- Watermark font size']   = if ($Label.ContentMarkingWaterMarkFontSize) { $Label.ContentMarkingWaterMarkFontSize } else { 'N/A' }
                                                            $cmInObj['- Watermark layout']      = if ($Label.ContentMarkingWaterMarkLayout) { $TextInfo.ToTitleCase($Label.ContentMarkingWaterMarkLayout) } else { 'N/A' }
                                                        }
                                                        $CmObj.Add([pscustomobject](ConvertTo-HashToYN $cmInObj)) | Out-Null
                                                        $CmTableParams = @{ Name = "Content Marking - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                                        $null = (& { if ($Report.ShowTableCaptions) { $CmTableParams['Caption'] = "- $($CmTableParams.Name)" } })
                                                        $CmObj | Table @CmTableParams
                                                        #endregion

                                                        #region Auto-labeling for files and emails
                                                        $AlObj = [System.Collections.ArrayList]::new()
                                                        $alInObj = [ordered] @{
                                                            'Auto-labelling for files and emails'                = if ($Label.AutoLabelingEnabled) { 'Enabled' } else { 'Disabled' }
                                                            'Condition'                                          = if ($Label.Conditions) { 'Configured' } else { 'N/A' }
                                                            'When content matches these conditions'              = if ($Label.AutoLabelingMessage) { $Label.AutoLabelingMessage } else { 'N/A' }
                                                            'Display this message to users when label is applied'= if ($Label.AutoLabelingPolicyTip) { $Label.AutoLabelingPolicyTip } else { 'N/A' }
                                                        }
                                                        $AlObj.Add([pscustomobject](ConvertTo-HashToYN $alInObj)) | Out-Null
                                                        $AlTableParams = @{ Name = "Auto-labelling for Files and Emails - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                                        $null = (& { if ($Report.ShowTableCaptions) { $AlTableParams['Caption'] = "- $($AlTableParams.Name)" } })
                                                        $AlObj | Table @AlTableParams
                                                        #endregion

                                                        #region Groups & Sites
                                                        $GsObj = [System.Collections.ArrayList]::new()
                                                        $gsInObj = [ordered] @{
                                                            'Privacy and external user access'                           = if ($Label.SiteAndGroupProtectionEnabled -and $Label.SiteAndGroupPrivacy) { 'Checked' } else { 'Not checked' }
                                                            'External sharing and Conditional Access'                    = if ($Label.SiteAndGroupProtectionEnabled -and $Label.SiteAndGroupExternalSharingControlType) { 'Checked' } else { 'Not checked' }
                                                            'Private teams discoverability and shared channel settings'  = if ($Label.SiteAndGroupProtectionEnabled -and $Label.SiteAndGroupTeamsAllowPrivateChannels) { 'Checked' } else { 'Not checked' }
                                                            'Apply a label to channel meetings'                         = 'Not checked'
                                                        }
                                                        $GsObj.Add([pscustomobject](ConvertTo-HashToYN $gsInObj)) | Out-Null
                                                        $GsTableParams = @{ Name = "Groups & Sites - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                                        $null = (& { if ($Report.ShowTableCaptions) { $GsTableParams['Caption'] = "- $($GsTableParams.Name)" } })
                                                        $GsObj | Table @GsTableParams

                                                        # Privacy & External User Access detail
                                                        $PrivObj = [System.Collections.ArrayList]::new()
                                                        $privInObj = [ordered] @{
                                                            'Privacy'                                                              = if ($Label.SiteAndGroupPrivacy) { $TextInfo.ToTitleCase($Label.SiteAndGroupPrivacy) } else { 'None' }
                                                            'Let Microsoft 365 Group owners add people outside your organisation as guests' = if ($Label.SiteAndGroupAllowGuestsToBeGroupOwner) { 'Checked' } else { 'N/A' }
                                                        }
                                                        $PrivObj.Add([pscustomobject](ConvertTo-HashToYN $privInObj)) | Out-Null
                                                        $PrivTableParams = @{ Name = "Privacy and External User Access - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                                        $null = (& { if ($Report.ShowTableCaptions) { $PrivTableParams['Caption'] = "- $($PrivTableParams.Name)" } })
                                                        $PrivObj | Table @PrivTableParams

                                                        # External Sharing & Conditional Access detail
                                                        $ExtObj = [System.Collections.ArrayList]::new()
                                                        $extInObj = [ordered] @{
                                                            'Control external sharing from labelled SharePoint sites'   = if ($Label.SiteAndGroupExternalSharingControlType) { 'Checked' } else { 'N/A' }
                                                            '- Content can be shared with'                             = if ($Label.SiteAndGroupExternalSharingControlType) { $TextInfo.ToTitleCase($Label.SiteAndGroupExternalSharingControlType) } else { 'N/A' }
                                                            'Use Microsoft Entra Conditional Access to protect labelled SharePoint site' = if ($Label.SiteAndGroupAccessToSitesFromUnmanagedDevices) { 'Checked' } else { 'N/A' }
                                                            '- Choose an existing authentication context'              = if ($Label.SiteAndGroupAccessToSitesFromUnmanagedDevices) { $TextInfo.ToTitleCase($Label.SiteAndGroupAccessToSitesFromUnmanagedDevices) } else { 'N/A' }
                                                        }
                                                        $ExtObj.Add([pscustomobject](ConvertTo-HashToYN $extInObj)) | Out-Null
                                                        $ExtTableParams = @{ Name = "External Sharing and Conditional Access - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                                        $null = (& { if ($Report.ShowTableCaptions) { $ExtTableParams['Caption'] = "- $($ExtTableParams.Name)" } })
                                                        $ExtObj | Table @ExtTableParams
                                                        #endregion

                                                    }
                                                } catch {
                                                    Write-PScriboMessage -IsWarning -Message "Label Detail '$($Label.DisplayName)': $($_.Exception.Message)" | Out-Null
                                                }
                                            }
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Sensitivity Label information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Sensitivity Label Section: $($_.Exception.Message)" | Out-Null
        }
        #endregion

        #region Sensitivity Label Policies
        try {
            $LabelPolicies = Get-LabelPolicy -ErrorAction Stop

            if ($LabelPolicies) {
                Section -Style Heading3 'Sensitivity Label Policies' {

                    # Summary Table
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Policy in $LabelPolicies) {
                        try {
                            $inObj = [ordered] @{
                                'Name'              = $Policy.Name
                                'Enabled'           = $Policy.Enabled
                                'Labels'            = ($Policy.Labels -join ', ')
                                'Exchange Location' = if ($Policy.ExchangeLocation.Name) { ($Policy.ExchangeLocation.Name -join ', ') } else { 'All' }
                                'Excluded Users'    = if ($Policy.ExchangeLocationException.Name) { ($Policy.ExchangeLocationException.Name -join ', ') } else { '--' }
                                'Created'           = $Policy.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Label Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.InformationProtection) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                    }
                    })

                    $TableParams = @{ Name = "Sensitivity Label Policies - $TenantId"; List = $false; ColumnWidths = 22, 10, 22, 18, 16, 12 }
                    $null = (& { if ($Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" } })
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams

                    # Per-Policy Detail Sections
                    if ($InfoLevel.InformationProtection -ge 2) {
                        foreach ($Policy in ($LabelPolicies | Sort-Object Name)) {
                                                try {
                                                    Section -Style Heading4 $Policy.Name {
                                                        Paragraph "Logicalis implemented the $($Policy.Name) label policy with the following configuration."
                                                        BlankLine

                                                        $PolObj = [System.Collections.ArrayList]::new()
                                                        $polInObj = [ordered] @{
                                                            'Policy Name'                      = $Policy.Name
                                                            'Enabled'                          = $Policy.Enabled
                                                            'Labels Included'                  = if ($Policy.Labels) { ($Policy.Labels -join ', ') } else { '--' }
                                                            'Published to (Exchange)'          = if ($Policy.ExchangeLocation.Name) { ($Policy.ExchangeLocation.Name -join ', ') } else { 'All Users' }
                                                            'Excluded from Exchange'           = if ($Policy.ExchangeLocationException.Name) { ($Policy.ExchangeLocationException.Name -join ', ') } else { 'N/A' }
                                                            'Modern Group Location'            = if ($Policy.ModernGroupLocation.Name) { ($Policy.ModernGroupLocation.Name -join ', ') } else { 'N/A' }
                                                            'Mandatory Labeling'               = if ($Policy.RequireSensitivityLabelOnSave) { 'Enabled' } else { 'Disabled' }
                                                            'Require Justification to Downgrade' = if ($Policy.RequireDowngradeJustification) { 'Enabled' } else { 'Disabled' }
                                                            'Apply to Unlabeled Documents'     = if ($Policy.ApplyAutoLabelPolicy) { 'Enabled' } else { 'Disabled' }
                                                            'More Info URL'                    = if ($Policy.MoreInfoUrl) { $Policy.MoreInfoUrl } else { 'N/A' }
                                                            'Created'                          = $Policy.WhenCreated.ToString('yyyy-MM-dd HH:mm')
                                                            'Last Modified'                    = $Policy.WhenChangedUTC.ToString('yyyy-MM-dd HH:mm')
                                                            'Created By'                       = if ($Policy.CreatedBy) { $Policy.CreatedBy } else { 'N/A' }
                                                            'Modified By'                      = if ($Policy.LastModifiedBy) { $Policy.LastModifiedBy } else { 'N/A' }
                                                        }
                                                        $PolObj.Add([pscustomobject](ConvertTo-HashToYN $polInObj)) | Out-Null
                                                        $PolTableParams = @{ Name = "Policy Detail - $($Policy.Name)"; List = $true; ColumnWidths = 40, 60 }
                                                        $null = (& { if ($Report.ShowTableCaptions) { $PolTableParams['Caption'] = "- $($PolTableParams.Name)" } })
                                                        $PolObj | Table @PolTableParams
                                                    }
                                                } catch {
                                                    Write-PScriboMessage -IsWarning -Message "Label Policy Detail '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                                                }
                                            }
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Sensitivity Label Policy information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Sensitivity Label Policy Section: $($_.Exception.Message)" | Out-Null
        }
        #endregion

        #region Auto-Labeling Policies
        try {
            $AutoLabelPolicies = Get-AutoSensitivityLabelPolicy -ErrorAction Stop

            if ($AutoLabelPolicies) {
                Section -Style Heading3 'Auto-Labeling Policies' {
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Policy in $AutoLabelPolicies) {
                        try {
                            $inObj = [ordered] @{
                                'Name'          = $Policy.Name
                                'Enabled'       = $Policy.Enabled
                                'Mode'          = switch ($Policy.Mode) {
                                                      'Enable'                   { 'On (Enforced)' }
                                                      'TestWithNotifications'    { 'Simulation (notify)' }
                                                      'TestWithoutNotifications' { 'Simulation (silent)' }
                                                      default                    { $TextInfo.ToTitleCase($Policy.Mode) }
                                                  }
                                'Labels'        = if ($Policy.Labels) { ($Policy.Labels -join ', ') } else { '--' }
                                'Exchange'      = if ($Policy.ExchangeLocation) { 'Checked' } else { 'Not checked' }
                                'SharePoint'    = if ($Policy.SharePointLocation) { 'Checked' } else { 'Not checked' }
                                'OneDrive'      = if ($Policy.OneDriveLocation) { 'Checked' } else { 'Not checked' }
                                'Last Modified' = $Policy.WhenChangedUTC.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Auto-Label Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    $null = (& {
                    if ($HealthCheck.Purview.InformationProtection) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' }          | Set-Style -Style Critical | Out-Null
                        $OutObj | Where-Object { $_.'Mode' -notmatch 'Enforced' } | Set-Style -Style Warning  | Out-Null
                    }
                    })

                    $TableParams = @{ Name = "Auto-Labeling Policies - $TenantId"; List = $false; ColumnWidths = 20, 8, 18, 16, 10, 10, 10, 8 }
                    $null = (& { if ($Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" } })
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No Auto-Labeling Policy information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Auto-Labeling Policy Section: $($_.Exception.Message)" | Out-Null
        }
        #endregion
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Sensitivity Labels'
    }
}
