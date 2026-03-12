function Get-AbrPurviewSensitivityLabel {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Purview Sensitivity Label information.
    .DESCRIPTION
        Collects and reports on Sensitivity Labels, Sensitivity Label Policies, and
        Auto-Labeling Policies configured in Microsoft Purview, including encryption
        settings, content marking, scopes, and auto-labeling rules.
    .NOTES
        Version:        0.1.0
        Author:         Pai Wei Sing
    .EXAMPLE
        Get-AbrPurviewSensitivityLabel -TenantId 'contoso.onmicrosoft.com'
    #>
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
        # Fetch Auto-Labeling Policies once here; reused in both the Coverage Summary
        # and the dedicated Auto-Labeling Policies section below.
        $AutoLabelPolicies = try { Get-AutoSensitivityLabelPolicy -ErrorAction Stop } catch { @() }

        # GAP 4 (MCCA check-IP103): AIP unified labeling migration status
        $AIPUnifiedLabelingEnabled = $null
        try {
            $AIPConfig = Get-AIPServiceConfiguration -ErrorAction SilentlyContinue
            if ($AIPConfig) { $AIPUnifiedLabelingEnabled = $AIPConfig.UnifiedLabelingEnabled }
        } catch { }  # cmdlet only available when AIPService module present; non-fatal

        #region Sensitivity Labels
        try {
            $Labels = Get-Label -ErrorAction Stop

            if ($Labels) {
                Section -Style Heading3 'Sensitivity Labels' {

                    # Summary Table
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Label in $Labels) {
                        try {
                             $_pre_Enabled_44 = if ($Label.Disabled -eq $false) { 'Yes' } else { 'No' }
                             $_pre_Encryption_46 = if ($Label.EncryptionEnabled) { 'Yes' } else { 'No' }
                             $_pre_ContentMarking_47 = if ($Label.ContentMarkingEnabled) { 'Yes' } else { 'No' }
                             $_pre_AutoLabeling_48 = if ($Label.AutoLabelingEnabled) { 'Yes' } else { 'No' }
                            $inObj = [ordered] @{
                             'Name'            = $Label.DisplayName
                             'Priority'        = $Label.Priority
                             'Enabled' = $_pre_Enabled_44
                             'Scope'           = ($Label.ContentType -join ', ')
                             'Encryption' = $_pre_Encryption_46
                             'Content Marking' = $_pre_ContentMarking_47
                             'Auto Labeling' = $_pre_AutoLabeling_48
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Sensitivity Label '$($Label.DisplayName)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.InformationProtection) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Warning | Out-Null
                    }

                    $TableParams = @{ Name = "Sensitivity Labels - $TenantId"; List = $false; ColumnWidths = 24, 10, 10, 18, 13, 13, 12 }
                    if ($script:Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" }
                    $OutObj | Sort-Object -Property 'Priority' | Table @TableParams

                    #region Coverage Summary
                    $HasEncryption     = $Labels | Where-Object { $_.EncryptionEnabled }
                    $HasAutoLabeling   = $Labels | Where-Object { $_.AutoLabelingEnabled }
                    $HasContentMarking = $Labels | Where-Object { $_.ContentMarkingEnabled }
                    # $AutoLabelPolicies already fetched at top of process block

                    $CovObj = [System.Collections.ArrayList]::new()
                        $_pre_LabelsConfigured_76 = if ($Labels.Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_LabelswithEncryption_77 = if ($null -ne $HasEncryption) { 'Yes' } else { 'No' }
                        $_pre_LabelswithContentMar_78 = if ($null -ne $HasContentMarking) { 'Yes' } else { 'No' }
                        $_pre_LabelswithAutoLabeli_79 = if ($null -ne $HasAutoLabeling) { 'Yes' } else { 'No' }
                        $_pre_AutoLabelingPolicies_80 = if ($null -ne $AutoLabelPolicies -and @($AutoLabelPolicies).Count -gt 0) { 'Yes' } else { 'No' }
                        $_pre_AIPUnifiedLabeling_81   = if ($null -eq $AIPUnifiedLabelingEnabled) { 'Unknown' } elseif ($AIPUnifiedLabelingEnabled) { 'Yes' } else { 'No — migration required' }
                    $covInObj = [ordered] @{
                        'Labels Configured' = $_pre_LabelsConfigured_76
                        'Labels with Encryption' = $_pre_LabelswithEncryption_77
                        'Labels with Content Marking' = $_pre_LabelswithContentMar_78
                        'Labels with Auto-Labeling (per-label)' = $_pre_LabelswithAutoLabeli_79
                        'Auto-Labeling Policies Configured' = $_pre_AutoLabelingPolicies_80
                        'AIP Unified Labeling Enabled'      = $_pre_AIPUnifiedLabeling_81
                    }
                    $CovObj.Add([pscustomobject]$covInObj) | Out-Null

                    if ($Healthcheck -and $script:HealthCheck.Purview.InformationProtection) {
                        $CovObj | Where-Object { $_.'Labels Configured' -eq 'No' }                     | Set-Style -Style Critical | Out-Null
                        $CovObj | Where-Object { $_.'Labels with Encryption' -eq 'No' }                | Set-Style -Style Warning  | Out-Null
                        $CovObj | Where-Object { $_.'Auto-Labeling Policies Configured' -eq 'No' }     | Set-Style -Style Warning  | Out-Null
                        $CovObj | Where-Object { $_.'AIP Unified Labeling Enabled' -match 'migration' } | Set-Style -Style Warning  | Out-Null
                    }

                    $CovTableParams = @{ Name = "Information Protection Coverage - $TenantId"; List = $true; ColumnWidths = 55, 45 }
                    if ($script:Report.ShowTableCaptions) { $CovTableParams['Caption'] = "- $($CovTableParams.Name)" }
                    $CovObj | Table @CovTableParams

                    #region ACSC Inline Check — Sensitivity Labels
                    if ($script:InfoLevel.InformationProtection -ge 3) {
                        $HasEncryptionLabel  = [bool]($Labels | Where-Object { $_.EncryptionEnabled })
                        $HasLabelsConfigured = ($Labels.Count -gt 0)
                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'Sensitivity Labels' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-0271'
                                E8          = 'N/A'
                                Description = 'Information is classified before being stored or transmitted'
                                Check       = 'Sensitivity labels are configured and published to users'
                                Status      = if ($HasLabelsConfigured) { 'Pass' } else { 'Fail' }
                            }
                            [pscustomobject]@{
                                ControlId   = 'ISM-0884'
                                E8          = 'N/A'
                                Description = 'Encryption applied to sensitive/protected information'
                                Check       = 'At least one sensitivity label has encryption enabled'
                                Status      = if ($HasEncryptionLabel) { 'Pass' } else { 'Fail' }
                            }
                        )
                    }
                    #endregion

                    # Per-Label Detail Sections
                    if ($script:InfoLevel.InformationProtection -ge 2) {
                        foreach ($Label in ($Labels | Sort-Object Priority)) {
                                 try {
                                  Section -Style Heading4 $Label.DisplayName {

                                   Paragraph "The $($Label.DisplayName) sensitivity label is configured as follows."
                                   BlankLine

                                   #region Label Details
                                   $GenObj = [System.Collections.ArrayList]::new()
                                    $_pre_ParentLabel_134 = if ($Label.ParentId) { $Label.ParentId } else { 'N/A' }
                                    $_pre_DescriptionforUsers_138 = if ($Label.Tooltip) { $Label.Tooltip } else { '--' }
                                    $_pre_DescriptionforAdmins_139 = if ($Label.Comment) { $Label.Comment } else { '--' }
                                    $_pre_LabelColour_140 = if ($Label.LabelColor) { $Label.LabelColor } else { 'None' }
                                   $genInObj = [ordered] @{
                                    'Parent Label' = $_pre_ParentLabel_134
                                    'Name'                      = $Label.Name
                                    'Display Name'              = $Label.DisplayName
                                    'Label Priority'            = $Label.Priority
                                    'Description for Users' = $_pre_DescriptionforUsers_138
                                    'Description for Admins' = $_pre_DescriptionforAdmins_139
                                    'Label Colour' = $_pre_LabelColour_140
                                   }
                                   $GenObj.Add([pscustomobject]$genInObj) | Out-Null
                                   $GenTableParams = @{ Name = "Label Details - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                   if ($script:Report.ShowTableCaptions) { $GenTableParams['Caption'] = "- $($GenTableParams.Name)" }
                                   $GenObj | Table @GenTableParams
                                   #endregion

                                   #region Scope
                                   $ScopeObj = [System.Collections.ArrayList]::new()
                                   $ContentTypes = $Label.ContentType
                                    $_pre_Filesotherdataassets_156 = if ($ContentTypes -contains 'File') { 'Checked' } else { 'Not checked' }
                                    $_pre_Emails_157 = if ($ContentTypes -contains 'Email') { 'Checked' } else { 'Not checked' }
                                    $_pre_Meetings_158 = if ($ContentTypes -contains 'Meeting') { 'Checked' } else { 'Not checked' }
                                    $_pre_Groupssites_159 = if ($ContentTypes -contains 'Site') { 'Checked' } else { 'Not checked' }
                                    $_pre_Schematizeddataasset_160 = if ($ContentTypes -contains 'SchematizedData') { 'Checked' } else { 'Not checked' }
                                   $scopeInObj = [ordered] @{
                                    'Files & other data assets' = $_pre_Filesotherdataassets_156
                                    'Emails' = $_pre_Emails_157
                                    'Meetings' = $_pre_Meetings_158
                                    'Groups & sites' = $_pre_Groupssites_159
                                    'Schematized data assets' = $_pre_Schematizeddataasset_160
                                   }
                                   $ScopeObj.Add([pscustomobject]$scopeInObj) | Out-Null
                                   $ScopeTableParams = @{ Name = "Scope - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                   if ($script:Report.ShowTableCaptions) { $ScopeTableParams['Caption'] = "- $($ScopeTableParams.Name)" }
                                   $ScopeObj | Table @ScopeTableParams
                                   #endregion

                                   #region Protection Settings
                                   $ProtObj = [System.Collections.ArrayList]::new()
                                    $_pre_ControlaccessEncrypt_176 = if ($Label.EncryptionEnabled) { 'Checked' } else { 'Not checked' }
                                    $_pre_Applycontentmarking_177 = if ($Label.ContentMarkingEnabled) { 'Checked' } else { 'Not checked' }
                                   $protInObj = [ordered] @{
                                    'Control access (Encryption)' = $_pre_ControlaccessEncrypt_176
                                    'Apply content marking' = $_pre_Applycontentmarking_177
                                    'Protect Teams meetings and chats'       = 'N/A (Teams Premium licensing required)'
                                   }
                                   $ProtObj.Add([pscustomobject]$protInObj) | Out-Null
                                   $ProtTableParams = @{ Name = "Protection Settings - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                   if ($script:Report.ShowTableCaptions) { $ProtTableParams['Caption'] = "- $($ProtTableParams.Name)" }
                                   $ProtObj | Table @ProtTableParams
                                   #endregion

                                   #region Encryption Details
                                   if ($Label.EncryptionEnabled) {
                                    $EncObj = [System.Collections.ArrayList]::new()

                                    # Parse rights definitions into readable format
                                    $RightsDisplay = if ($Label.EncryptionRightsDefinitions) {
                                     ($Label.EncryptionRightsDefinitions | ForEach-Object { "$($_.Identity): $($_.Rights -join ', ')" }) -join '; '
                                    } else { 'N/A' }

                                     $_pre_Assignpermissionsnow_199 = if ($Label.EncryptionAdhocPermissions) { 'Let users assign permissions' } else { 'Assign permissions now' }
                                     $_pre_DoNotForward_201 = if ($Label.EncryptionDoNotForward) { 'Checked' } else { 'Not checked' }
                                     $_pre_EncryptOnly_202 = if ($Label.EncryptionEncryptOnly) { 'Checked' } else { 'Not checked' }
                                     $_pre_ContentExpiry_203 = if ($Label.EncryptionContentExpiredOnDateInDaysOrNever -and $Label.EncryptionContentExpiredOnDateInDaysOrNever -ne 'Never') { "$($Label.EncryptionContentExpiredOnDateInDaysOrNever) days" } else { 'Never' }
                                     $_pre_OfflineAccessDuratio_204 = if ($Label.EncryptionOfflineAccessDays -ge 0) { "$($Label.EncryptionOfflineAccessDays) days" } else { 'Always' }
                                     $_pre_DoubleKeyEncryptionU_205 = if ($Label.EncryptionDoubleKeyEncryptionUrl) { $Label.EncryptionDoubleKeyEncryptionUrl } else { 'N/A' }
                                    $encInObj = [ordered] @{
                                     'Encryption'                         = 'Enabled'
                                     'Assign permissions now or let users decide' = $_pre_Assignpermissionsnow_199
                                     'Rights Definitions'                 = $RightsDisplay
                                     'Do Not Forward' = $_pre_DoNotForward_201
                                     'Encrypt Only' = $_pre_EncryptOnly_202
                                     'Content Expiry' = $_pre_ContentExpiry_203
                                     'Offline Access Duration' = $_pre_OfflineAccessDuratio_204
                                     'Double Key Encryption URL' = $_pre_DoubleKeyEncryptionU_205
                                    }
                                    $EncObj.Add([pscustomobject]$encInObj) | Out-Null
                                    $EncTableParams = @{ Name = "Encryption - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                    if ($script:Report.ShowTableCaptions) { $EncTableParams['Caption'] = "- $($EncTableParams.Name)" }
                                    $EncObj | Table @EncTableParams
                                   }
                                   #endregion

                                   #region Content Marking
                                   $cmHeaderAlign = if ($Label.ContentMarkingHeaderAlignment) { $script:TextInfo.ToTitleCase($Label.ContentMarkingHeaderAlignment) } else { 'N/A' }
                                   $cmFooterAlign = if ($Label.ContentMarkingFooterAlignment) { $script:TextInfo.ToTitleCase($Label.ContentMarkingFooterAlignment) } else { 'N/A' }
                                   $cmWaterLayout = if ($Label.ContentMarkingWaterMarkLayout) { $script:TextInfo.ToTitleCase($Label.ContentMarkingWaterMarkLayout) } else { 'N/A' }
                                   $CmObj = [System.Collections.ArrayList]::new()
                                    $_pre_Contentmarking_226 = if ($Label.ContentMarkingEnabled) { 'Enabled' } else { 'Disabled' }
                                    $_pre_Addawatermark_227 = if ($Label.ContentMarkingWaterMarkEnabled) { 'Checked' } else { 'Not checked' }
                                    $_pre_Addaheader_228 = if ($Label.ContentMarkingHeaderEnabled) { 'Checked' } else { 'Not checked' }
                                    $_pre_Headertext_229 = if ($Label.ContentMarkingHeaderText) { $Label.ContentMarkingHeaderText } else { 'N/A' }
                                    $_pre_Fontsize_230 = if ($Label.ContentMarkingHeaderFontSize) { $Label.ContentMarkingHeaderFontSize } else { 'N/A' }
                                    $_pre_Fontcolour_231 = if ($Label.ContentMarkingHeaderFontColor) { $Label.ContentMarkingHeaderFontColor } else { 'N/A' }
                                    $_pre_Addafooter_233 = if ($Label.ContentMarkingFooterEnabled) { 'Checked' } else { 'Not checked' }
                                    $_pre_Footertext_234 = if ($Label.ContentMarkingFooterText) { $Label.ContentMarkingFooterText } else { 'N/A' }
                                    $_pre_Fontsize_235 = if ($Label.ContentMarkingFooterFontSize) { $Label.ContentMarkingFooterFontSize } else { 'N/A' }
                                    $_pre_Fontcolour_236 = if ($Label.ContentMarkingFooterFontColor) { $Label.ContentMarkingFooterFontColor } else { 'N/A' }
                                   $cmInObj = [ordered] @{
                                    'Content marking' = $_pre_Contentmarking_226
                                    'Add a watermark' = $_pre_Addawatermark_227
                                    'Add a header' = $_pre_Addaheader_228
                                    '- Header text' = $_pre_Headertext_229
                                    '- Font size' = $_pre_Fontsize_230
                                    '- Font colour' = $_pre_Fontcolour_231
                                    '- Align text'         = $cmHeaderAlign
                                    'Add a footer' = $_pre_Addafooter_233
                                    '- Footer text' = $_pre_Footertext_234
                                    '- Font size ' = $_pre_Fontsize_235
                                    '- Font colour ' = $_pre_Fontcolour_236
                                    '- Align text '        = $cmFooterAlign
                                   }
                                   if ($Label.ContentMarkingWaterMarkEnabled) {
                                    $cmInObj['- Watermark text']        = if ($Label.ContentMarkingWaterMarkText) { $Label.ContentMarkingWaterMarkText } else { 'N/A' }
                                    $cmInObj['- Watermark font size']   = if ($Label.ContentMarkingWaterMarkFontSize) { $Label.ContentMarkingWaterMarkFontSize } else { 'N/A' }
                                    $cmInObj['- Watermark layout']      = $cmWaterLayout
                                   }
                                   $CmObj.Add([pscustomobject]$cmInObj) | Out-Null
                                   $CmTableParams = @{ Name = "Content Marking - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                   if ($script:Report.ShowTableCaptions) { $CmTableParams['Caption'] = "- $($CmTableParams.Name)" }
                                   $CmObj | Table @CmTableParams
                                   #endregion

                                   #region Auto-labeling for files and emails
                                   $AlObj = [System.Collections.ArrayList]::new()
                                    $_pre_Autolabellingforfile_263 = if ($Label.AutoLabelingEnabled) { 'Enabled' } else { 'Disabled' }
                                    $_pre_Condition_264 = if ($Label.Conditions) { 'Configured' } else { 'N/A' }
                                    $_pre_Whencontentmatchesth_265 = if ($Label.AutoLabelingMessage) { $Label.AutoLabelingMessage } else { 'N/A' }
                                    $_pre_Displaythismessageto_266 = if ($Label.AutoLabelingPolicyTip) { $Label.AutoLabelingPolicyTip } else { 'N/A' }
                                   $alInObj = [ordered] @{
                                    'Auto-labelling for files and emails' = $_pre_Autolabellingforfile_263
                                    'Condition' = $_pre_Condition_264
                                    'When content matches these conditions' = $_pre_Whencontentmatchesth_265
                                    'Display this message to users when label is applied' = $_pre_Displaythismessageto_266
                                   }
                                   $AlObj.Add([pscustomobject]$alInObj) | Out-Null
                                   $AlTableParams = @{ Name = "Auto-labelling for Files and Emails - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                   if ($script:Report.ShowTableCaptions) { $AlTableParams['Caption'] = "- $($AlTableParams.Name)" }
                                   $AlObj | Table @AlTableParams
                                   #endregion

                                   #region Groups & Sites
                                   $GsObj = [System.Collections.ArrayList]::new()
                                    $_pre_Privacyandexternalus_281 = if ($Label.SiteAndGroupProtectionEnabled -and $Label.SiteAndGroupPrivacy) { 'Checked' } else { 'Not checked' }
                                    $_pre_ExternalsharingandCo_282 = if ($Label.SiteAndGroupProtectionEnabled -and $Label.SiteAndGroupExternalSharingControlType) { 'Checked' } else { 'Not checked' }
                                    $_pre_Privateteamsdiscover_283 = if ($Label.SiteAndGroupProtectionEnabled -and $Label.SiteAndGroupTeamsAllowPrivateChannels) { 'Checked' } else { 'Not checked' }
                                   $gsInObj = [ordered] @{
                                    'Privacy and external user access' = $_pre_Privacyandexternalus_281
                                    'External sharing and Conditional Access' = $_pre_ExternalsharingandCo_282
                                    'Private teams discoverability and shared channel settings' = $_pre_Privateteamsdiscover_283
                                    'Apply a label to channel meetings'                         = 'Not checked'
                                   }
                                   $GsObj.Add([pscustomobject]$gsInObj) | Out-Null
                                   $GsTableParams = @{ Name = "Groups & Sites - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                   if ($script:Report.ShowTableCaptions) { $GsTableParams['Caption'] = "- $($GsTableParams.Name)" }
                                   $GsObj | Table @GsTableParams

                                   # Privacy & External User Access detail
                                   $sgPrivacy    = if ($Label.SiteAndGroupPrivacy) { $script:TextInfo.ToTitleCase($Label.SiteAndGroupPrivacy) } else { 'None' }
                                   $sgSharing    = if ($Label.SiteAndGroupExternalSharingControlType) { $script:TextInfo.ToTitleCase($Label.SiteAndGroupExternalSharingControlType) } else { 'N/A' }
                                   $sgCondAccess = if ($Label.SiteAndGroupAccessToSitesFromUnmanagedDevices) { $script:TextInfo.ToTitleCase($Label.SiteAndGroupAccessToSitesFromUnmanagedDevices) } else { 'N/A' }
                                   $PrivObj = [System.Collections.ArrayList]::new()
                                    $_pre_LetMicrosoft365Group_301 = if ($Label.SiteAndGroupAllowGuestsToBeGroupOwner) { 'Checked' } else { 'N/A' }
                                   $privInObj = [ordered] @{
                                    'Privacy'              = $sgPrivacy
                                    'Let Microsoft 365 Group owners add people outside your organisation as guests' = $_pre_LetMicrosoft365Group_301
                                   }
                                   $PrivObj.Add([pscustomobject]$privInObj) | Out-Null
                                   $PrivTableParams = @{ Name = "Privacy and External User Access - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                   if ($script:Report.ShowTableCaptions) { $PrivTableParams['Caption'] = "- $($PrivTableParams.Name)" }
                                   $PrivObj | Table @PrivTableParams

                                   # External Sharing & Conditional Access detail
                                   $ExtObj = [System.Collections.ArrayList]::new()
                                    $_pre_Controlexternalshari_312 = if ($Label.SiteAndGroupExternalSharingControlType) { 'Checked' } else { 'N/A' }
                                    $_pre_UseMicrosoftEntraCon_314 = if ($Label.SiteAndGroupAccessToSitesFromUnmanagedDevices) { 'Checked' } else { 'N/A' }
                                   $extInObj = [ordered] @{
                                    'Control external sharing from labelled SharePoint sites' = $_pre_Controlexternalshari_312
                                    '- Content can be shared with'     = $sgSharing
                                    'Use Microsoft Entra Conditional Access to protect labelled SharePoint site' = $_pre_UseMicrosoftEntraCon_314
                                    '- Choose an existing authentication context' = $sgCondAccess
                                   }
                                   $ExtObj.Add([pscustomobject]$extInObj) | Out-Null
                                   $ExtTableParams = @{ Name = "External Sharing and Conditional Access - $($Label.DisplayName)"; List = $true; ColumnWidths = 40, 60 }
                                   if ($script:Report.ShowTableCaptions) { $ExtTableParams['Caption'] = "- $($ExtTableParams.Name)" }
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
                             $_pre_Enabled_353 = if ($Policy.Enabled) { 'Yes' } else { 'No' }
                             $_pre_ExchangeLocation_355 = if ($Policy.ExchangeLocation.Name) { ($Policy.ExchangeLocation.Name -join ', ') } else { 'All' }
                             $_pre_ExcludedUsers_356 = if ($Policy.ExchangeLocationException.Name) { ($Policy.ExchangeLocationException.Name -join ', ') } else { '--' }
                            $inObj = [ordered] @{
                             'Name'              = $Policy.Name
                             'Enabled' = $_pre_Enabled_353
                             'Labels'            = ($Policy.Labels -join ', ')
                             'Exchange Location' = $_pre_ExchangeLocation_355
                             'Excluded Users' = $_pre_ExcludedUsers_356
                             'Created'           = $Policy.WhenCreated.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Label Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.InformationProtection) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Critical | Out-Null
                    }

                    $TableParams = @{ Name = "Sensitivity Label Policies - $TenantId"; List = $false; ColumnWidths = 22, 10, 22, 18, 16, 12 }
                    if ($script:Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams

                    #region ACSC Inline Check — Sensitivity Label Policies
                    if ($script:InfoLevel.InformationProtection -ge 3) {
                        $HasMandatory  = [bool]($LabelPolicies | Where-Object { $_.RequireSensitivityLabelOnSave })
                        $HasDowngrade  = [bool]($LabelPolicies | Where-Object { $_.RequireDowngradeJustification })
                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'Sensitivity Label Policies' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-0272'
                                E8          = 'PSPF Req 59'
                                Description = 'Labels applied to all information (mandatory labelling)'
                                Check       = 'RequireSensitivityLabelOnSave enabled in at least one label policy'
                                Status      = if ($HasMandatory) { 'Pass' } else { 'Fail' }
                            }
                            [pscustomobject]@{
                                ControlId   = 'PSPF-060'
                                E8          = 'PSPF Req 60'
                                Description = 'Label downgrade justification required'
                                Check       = 'RequireDowngradeJustification enabled in at least one label policy'
                                Status      = if ($HasDowngrade) { 'Pass' } else { 'Fail' }
                            }
                        )
                    }
                    #endregion

                    # Per-Policy Detail Sections
                    if ($script:InfoLevel.InformationProtection -ge 2) {
                        foreach ($Policy in ($LabelPolicies | Sort-Object Name)) {
                                 try {
                                  Section -Style Heading4 $Policy.Name {
                                   Paragraph "The $($Policy.Name) label policy is configured as follows."
                                   BlankLine

                                   $PolObj = [System.Collections.ArrayList]::new()
                                    $_pre_Enabled_410 = if ($Policy.Enabled) { 'Yes' } else { 'No' }
                                    $_pre_LabelsIncluded_411 = if ($Policy.Labels) { ($Policy.Labels -join ', ') } else { '--' }
                                    $_pre_PublishedtoExchange_412 = if ($Policy.ExchangeLocation.Name) { ($Policy.ExchangeLocation.Name -join ', ') } else { 'All Users' }
                                    $_pre_ExcludedfromExchange_413 = if ($Policy.ExchangeLocationException.Name) { ($Policy.ExchangeLocationException.Name -join ', ') } else { 'N/A' }
                                    $_pre_ModernGroupLocation_414 = if ($Policy.ModernGroupLocation.Name) { ($Policy.ModernGroupLocation.Name -join ', ') } else { 'N/A' }
                                    $_pre_MandatoryLabeling_415 = if ($Policy.RequireSensitivityLabelOnSave) { 'Enabled' } else { 'Disabled' }
                                    $_pre_RequireJustification_416 = if ($Policy.RequireDowngradeJustification) { 'Enabled' } else { 'Disabled' }
                                    $_pre_ApplytoUnlabeledDocu_417 = if ($Policy.ApplyAutoLabelPolicy) { 'Enabled' } else { 'Disabled' }
                                    $_pre_MoreInfoURL_418 = if ($Policy.MoreInfoUrl) { $Policy.MoreInfoUrl } else { 'N/A' }
                                    $_pre_CreatedBy_421 = if ($Policy.CreatedBy) { $Policy.CreatedBy } else { 'N/A' }
                                    $_pre_ModifiedBy_422 = if ($Policy.LastModifiedBy) { $Policy.LastModifiedBy } else { 'N/A' }
                                   $polInObj = [ordered] @{
                                    'Policy Name'                      = $Policy.Name
                                    'Enabled' = $_pre_Enabled_410
                                    'Labels Included' = $_pre_LabelsIncluded_411
                                    'Published to (Exchange)' = $_pre_PublishedtoExchange_412
                                    'Excluded from Exchange' = $_pre_ExcludedfromExchange_413
                                    'Modern Group Location' = $_pre_ModernGroupLocation_414
                                    'Mandatory Labeling' = $_pre_MandatoryLabeling_415
                                    'Require Justification to Downgrade' = $_pre_RequireJustification_416
                                    'Apply to Unlabeled Documents' = $_pre_ApplytoUnlabeledDocu_417
                                    'More Info URL' = $_pre_MoreInfoURL_418
                                    'Created'                          = $Policy.WhenCreated.ToString('yyyy-MM-dd HH:mm')
                                    'Last Modified'                    = $Policy.WhenChangedUTC.ToString('yyyy-MM-dd HH:mm')
                                    'Created By' = $_pre_CreatedBy_421
                                    'Modified By' = $_pre_ModifiedBy_422
                                   }
                                   $PolObj.Add([pscustomobject]$polInObj) | Out-Null
                                   $PolTableParams = @{ Name = "Policy Detail - $($Policy.Name)"; List = $true; ColumnWidths = 40, 60 }
                                   if ($script:Report.ShowTableCaptions) { $PolTableParams['Caption'] = "- $($PolTableParams.Name)" }
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
            # $AutoLabelPolicies already fetched at top of process block — reuse here

            if ($AutoLabelPolicies) {
                Section -Style Heading3 'Auto-Labeling Policies' {
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Policy in $AutoLabelPolicies) {
                        try {
                             $_pre_Enabled_465 = if ($Policy.Enabled) { 'Yes' } else { 'No' }
                             $_pre_Labels_472 = if ($Policy.Labels) { ($Policy.Labels -join ', ') } else { '--' }
                             $_pre_Exchange_473 = if ($Policy.ExchangeLocation) { 'Checked' } else { 'Not checked' }
                             $_pre_SharePoint_474 = if ($Policy.SharePointLocation) { 'Checked' } else { 'Not checked' }
                             $_pre_OneDrive_475 = if ($Policy.OneDriveLocation) { 'Checked' } else { 'Not checked' }
                            $inObj = [ordered] @{
                             'Name'          = $Policy.Name
                             'Enabled' = $_pre_Enabled_465
                             'Mode'          = switch ($Policy.Mode) {
                                    'Enable'                   { 'On (Enforced)' }
                                    'TestWithNotifications'    { 'Simulation (notify)' }
                                    'TestWithoutNotifications' { 'Simulation (silent)' }
                                    default                    { $script:TextInfo.ToTitleCase($Policy.Mode) }
                                   }
                             'Labels' = $_pre_Labels_472
                             'Exchange' = $_pre_Exchange_473
                             'SharePoint' = $_pre_SharePoint_474
                             'OneDrive' = $_pre_OneDrive_475
                             'Last Modified' = $Policy.WhenChangedUTC.ToString('yyyy-MM-dd')
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Auto-Label Policy '$($Policy.Name)': $($_.Exception.Message)" | Out-Null
                        }
                    }

                    if ($Healthcheck -and $script:HealthCheck.Purview.InformationProtection) {
                        $OutObj | Where-Object { $_.'Enabled' -eq 'No' }          | Set-Style -Style Critical | Out-Null
                        $OutObj | Where-Object { $_.'Mode' -notmatch 'Enforced' } | Set-Style -Style Warning  | Out-Null
                    }

                    $TableParams = @{ Name = "Auto-Labeling Policies - $TenantId"; List = $false; ColumnWidths = 20, 8, 18, 16, 10, 10, 10, 8 }
                    if ($script:Report.ShowTableCaptions) { $TableParams['Caption'] = "- $($TableParams.Name)" }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams

                    #region ACSC Inline Check — Auto-Labeling Policies
                    if ($script:InfoLevel.InformationProtection -ge 3) {
                        $HasEnforcedALP = [bool]($AutoLabelPolicies | Where-Object { $_.Mode -eq 'Enable' })
                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'Auto-Labeling Policies' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-0271'
                                E8          = 'N/A'
                                Description = 'Classification applied automatically to unlabelled content'
                                Check       = 'At least one auto-labeling policy is in Enforce (Enable) mode'
                                Status      = if ($HasEnforcedALP) { 'Pass' } elseif ($AutoLabelPolicies.Count -gt 0) { 'Partial' } else { 'Fail' }
                            }
                        )
                    }
                    #endregion
                }
            } else {
                Write-PScriboMessage -Message "No Auto-Labeling Policy information found for $TenantId. Disabling section." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Auto-Labeling Policy Section: $($_.Exception.Message)" | Out-Null
        }
        #endregion

        #region IRM for Exchange Online (MCCA check-IP102)
        try {
            $IRMConfig = Get-IRMConfiguration -ErrorAction SilentlyContinue

            if ($IRMConfig) {
                Section -Style Heading3 'IRM Configuration (Exchange Online)' {
                    Paragraph "Information Rights Management (IRM) integrates sensitivity label encryption with Exchange Online. The following settings control how IRM protection is applied to email."
                    BlankLine

                    $_pre_InternalLicensing = if ($IRMConfig.InternalLicensingEnabled) { 'Yes' } else { 'No' }
                    $_pre_ExternalLicensing = if ($IRMConfig.ExternalLicensingEnabled) { 'Yes' } else { 'No' }
                    $_pre_AzureRMS          = if ($IRMConfig.AzureRMSLicensingEnabled) { 'Yes' } else { 'No' }
                    $_pre_OWAEnabled        = if ($IRMConfig.OWAEnabled)               { 'Yes' } else { 'No' }
                    $_pre_SimplifiedClient  = if ($IRMConfig.SimplifiedClientAccessEnabled) { 'Yes' } else { 'No' }
                    $_pre_SearchEnabled     = if ($IRMConfig.SearchEnabled)            { 'Yes' } else { 'No' }
                    $_pre_DecryptAttach     = if ($IRMConfig.DecryptAttachmentForEncryptOnly) { 'Yes' } else { 'No' }
                    $_pre_EDiscovery        = if ($IRMConfig.EDiscoverySuperUserEnabled) { 'Yes' } else { 'No' }
                    $_pre_JournalReport     = if ($IRMConfig.JournalReportDecryptionEnabled) { 'Yes' } else { 'No' }

                    $irmInObj = [ordered] @{
                        'Internal Licensing Enabled'        = $_pre_InternalLicensing
                        'External Licensing Enabled'        = $_pre_ExternalLicensing
                        'Azure RMS Licensing Enabled'       = $_pre_AzureRMS
                        'OWA IRM Enabled'                   = $_pre_OWAEnabled
                        'Simplified Client Access Enabled'  = $_pre_SimplifiedClient
                        'Search of Encrypted Email Enabled' = $_pre_SearchEnabled
                        'Decrypt Attachments (Encrypt-Only)' = $_pre_DecryptAttach
                        'eDiscovery Super User Enabled'     = $_pre_EDiscovery
                        'Journal Report Decryption Enabled' = $_pre_JournalReport
                    }
                    $IRMObj = [System.Collections.ArrayList]::new()
                    $IRMObj.Add([pscustomobject]$irmInObj) | Out-Null

                    if ($Healthcheck -and $script:HealthCheck.Purview.InformationProtection) {
                        $IRMObj | Where-Object { $_.'Internal Licensing Enabled' -eq 'No' }   | Set-Style -Style Critical | Out-Null
                        $IRMObj | Where-Object { $_.'Azure RMS Licensing Enabled' -eq 'No' }  | Set-Style -Style Warning  | Out-Null
                        $IRMObj | Where-Object { $_.'OWA IRM Enabled' -eq 'No' }              | Set-Style -Style Warning  | Out-Null
                    }

                    $IRMTableParams = @{ Name = "IRM Configuration - $TenantId"; List = $true; ColumnWidths = 45, 55 }
                    if ($script:Report.ShowTableCaptions) { $IRMTableParams['Caption'] = "- $($IRMTableParams.Name)" }
                    $IRMObj | Table @IRMTableParams

                    if ($script:InfoLevel.InformationProtection -ge 3) {
                        $_irmInternalEnabled = [bool]$IRMConfig.InternalLicensingEnabled
                        $_irmAzureEnabled    = [bool]$IRMConfig.AzureRMSLicensingEnabled
                        Write-AbrPurviewACSCCheck -TenantId $TenantId -SectionName 'IRM Configuration' -Checks @(
                            [pscustomobject]@{
                                ControlId   = 'ISM-0884'
                                E8          = 'N/A'
                                Description = 'Encryption applied to sensitive information in email'
                                Check       = 'IRM internal licensing and Azure RMS enabled for Exchange Online'
                                Status      = if ($_irmInternalEnabled -and $_irmAzureEnabled) { 'Pass' } elseif ($_irmInternalEnabled) { 'Partial' } else { 'Fail' }
                            }
                        )
                    }
                }
            } else {
                Write-PScriboMessage -Message "No IRM Configuration found for $TenantId." | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "IRM Configuration Section: $($_.Exception.Message)" | Out-Null
        }
        #endregion
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Sensitivity Labels'
    }
}
