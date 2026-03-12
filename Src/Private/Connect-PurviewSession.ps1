function Connect-PurviewSession {
    <#
    .SYNOPSIS
    Establishes authenticated connections to all Microsoft Purview dependent services.
    .DESCRIPTION
        Connects to Exchange Online (compliance cmdlets), Security & Compliance
        PowerShell (IPPSSession), and Microsoft Graph API.

        Features:
          - UPN format validation before attempting any connection
          - Retry logic with exponential back-off via Invoke-WithRetry
          - Reuses existing live sessions to avoid redundant auth prompts
          - Verifies each connection after establishment
          - Structured transcript logging throughout

        Required Roles (any one of):
          - Compliance Administrator
          - Global Administrator
          - Or granular roles: eDiscovery Manager, Retention Management,
            DLP Compliance Management, Sensitivity Label Administrator
    .NOTES
        Version:        0.1.0
        Author:         Pai Wei Sing
    .EXAMPLE
        Connect-PurviewSession -UserPrincipalName 'admin@contoso.onmicrosoft.com'
    .EXAMPLE
        Connect-PurviewSession -UserPrincipalName 'admin@contoso.onmicrosoft.com' -SkipGraph
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        # Skip Microsoft Graph connection (e.g. if Insider Risk / Compliance Manager not needed)
        [switch]$SkipGraph
    )

    #region Validate UPN
    if (-not (Test-UserPrincipalName -UserPrincipalName $UserPrincipalName)) {
        $errorMsg = "Invalid User Principal Name format: '$UserPrincipalName'. Expected format: user@domain.com"
        Write-TranscriptLog $errorMsg 'ERROR' 'AUTH' | Out-Null
        throw $errorMsg
    }
    #endregion

    Write-TranscriptLog "Starting connection to Microsoft Purview services for: $UserPrincipalName" 'INFO' 'AUTH' | Out-Null

    #region Exchange Online
    $ExistingEXO = $null
    try {
        $ExistingEXO = Get-ConnectionInformation -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Connected' } |
            Select-Object -First 1
    } catch { }

    if ($ExistingEXO) {
        Write-TranscriptLog "Reusing existing Exchange Online session (Org: $($ExistingEXO.TenantDisplayName))" 'SUCCESS' 'AUTH' | Out-Null
    } else {
        Write-Host "  - Disconnecting any stale Exchange Online sessions..."
        Write-TranscriptLog "Disconnecting stale Exchange Online sessions" 'DEBUG' 'AUTH' | Out-Null

        Invoke-WithRetry -ScriptBlock {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        } -OperationName 'Disconnect Exchange Online' -MaxAttempts 2 -DelaySeconds 3

        Write-Host "  - Connecting to Exchange Online..."
        Write-TranscriptLog "Connecting to Exchange Online with UPN: $UserPrincipalName" 'INFO' 'AUTH' | Out-Null

        Invoke-WithRetry -ScriptBlock {
            Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ShowProgress $true -ErrorAction Stop
        } -OperationName 'Connect to Exchange Online'

        Write-TranscriptLog "Exchange Online connection established" 'SUCCESS' 'AUTH' | Out-Null
    }
    #endregion

    #region Security & Compliance (IPPSSession)
    # IPPSSession provides compliance cmdlets: Get-DlpCompliancePolicy, Get-Label,
    # Get-RetentionCompliancePolicy, Get-ComplianceCase, Get-SupervisoryReviewPolicyV2 etc.
    $ExistingIPPS = $null
    try {
        # Detect an active IPPS session by checking for a connected implicit remoting session
        # that targets the Security & Compliance endpoint, rather than probing a cmdlet that
        # requires specific permissions (which would silently skip reconnection on failure).
        $ExistingIPPS = Get-PSSession -ErrorAction SilentlyContinue |
            Where-Object {
                $_.State -eq 'Opened' -and
                ($_.ConfigurationName -match 'Microsoft.Exchange' -or $_.ComputerName -match 'compliance|protection\.outlook')
            } |
            Select-Object -First 1
    } catch { }

    if ($ExistingIPPS) {
        Write-TranscriptLog "Reusing existing Security & Compliance (IPPS) session" 'SUCCESS' 'AUTH' | Out-Null
    } else {
        Write-Host "  - Connecting to Security & Compliance PowerShell..."
        Write-TranscriptLog "Connecting to Security & Compliance PowerShell (IPPSSession)" 'INFO' 'AUTH' | Out-Null

        Invoke-WithRetry -ScriptBlock {
            Connect-IPPSSession -UserPrincipalName $UserPrincipalName -ErrorAction Stop
        } -OperationName 'Connect to Security & Compliance PowerShell'

        # Verify the connection actually works
        Write-Host "  - Verifying Security & Compliance connection..."
        Write-TranscriptLog "Verifying Security & Compliance connection" 'DEBUG' 'AUTH' | Out-Null

        Invoke-WithRetry -ScriptBlock {
            $null = Get-ComplianceCase -ErrorAction Stop
        } -OperationName 'Verify Security & Compliance connection' -MaxAttempts 2 -DelaySeconds 3

        Write-TranscriptLog "Security & Compliance connection verified" 'SUCCESS' 'AUTH' | Out-Null
    }
    #endregion

    #region Microsoft Graph
    if (-not $SkipGraph) {
        $ExistingGraph = $null
        try {
            $ExistingGraph = Get-MgContext -ErrorAction SilentlyContinue
        } catch { }

        if ($ExistingGraph) {
            Write-TranscriptLog "Reusing existing Microsoft Graph session (TenantId: $($ExistingGraph.TenantId))" 'SUCCESS' 'AUTH' | Out-Null
        } else {
            Write-Host "  - Importing Microsoft Graph sub-modules..."
            Write-TranscriptLog "Importing required Microsoft Graph sub-modules" 'INFO' 'AUTH' | Out-Null
            $RequiredGraphModules = @(
                'Microsoft.Graph.Authentication'
                'Microsoft.Graph.Identity.DirectoryManagement'
            )
            foreach ($GraphModule in $RequiredGraphModules) {
                try {
                    # Skip if already loaded in session to avoid assembly conflict
                    if (-not (Get-Module -Name $GraphModule -ErrorAction SilentlyContinue)) {
                        Import-Module $GraphModule -ErrorAction Stop
                        Write-TranscriptLog "Imported $GraphModule" 'DEBUG' 'AUTH' | Out-Null
                    } else {
                        Write-TranscriptLog "$GraphModule already loaded, skipping import" 'DEBUG' 'AUTH' | Out-Null
                    }
                } catch {
                    Write-TranscriptLog "Could not import ${GraphModule}: $($_.Exception.Message)" 'WARNING' 'AUTH' | Out-Null
                }
            }

            Write-Host "  - Connecting to Microsoft Graph..."
            Write-TranscriptLog "Connecting to Microsoft Graph" 'INFO' 'AUTH' | Out-Null

            # Minimal scopes guaranteed to exist on the Graph resource.
            # Compliance data (DLP, Retention, eDiscovery etc.) comes from
            # IPPSSession cmdlets — Graph is only needed here for tenant info.
            $GraphScopes = @(
                'Organization.Read.All'
                'Directory.Read.All'
                'AuditLog.Read.All'
                'SecurityEvents.Read.All'                          # Insider Risk policies
            )

            Invoke-WithRetry -ScriptBlock {
                Connect-MgGraph -Scopes $GraphScopes -ErrorAction Stop
            } -OperationName 'Connect to Microsoft Graph'

            # Verify connection using Get-MgContext only — avoids assembly conflicts
            # caused by re-importing sub-modules that are already loaded in memory
            $MgCtx = Get-MgContext -ErrorAction SilentlyContinue
            if ($MgCtx -and $MgCtx.TenantId) {
                Write-TranscriptLog "Microsoft Graph connection verified (TenantId: $($MgCtx.TenantId))" 'SUCCESS' 'AUTH' | Out-Null
            } else {
                throw "Connect-MgGraph succeeded but Get-MgContext returned no context."
            }
        }
    } else {
        Write-TranscriptLog "Skipping Microsoft Graph connection (-SkipGraph specified)" 'INFO' 'AUTH' | Out-Null
    }
    #endregion

    Write-Host "  - All required services connected successfully." -ForegroundColor Green
    Write-TranscriptLog "All Microsoft Purview service connections established for: $UserPrincipalName" 'SUCCESS' 'AUTH' | Out-Null
}


function Disconnect-PurviewSession {
    <#
    .SYNOPSIS
    Cleanly disconnects all Microsoft Purview service sessions.
    .DESCRIPTION
        Disconnects Exchange Online, Security & Compliance (IPPS), and
        Microsoft Graph sessions. Errors during disconnect are logged as
        warnings rather than thrown, so report completion is not affected.
    .NOTES
        Version:        0.1.0
        Author:         Pai Wei Sing
    .EXAMPLE
        Disconnect-PurviewSession
    #>
    [CmdletBinding()]
    param()

    Write-TranscriptLog "Disconnecting Microsoft Purview service sessions" 'INFO' 'AUTH' | Out-Null

    # Exchange Online + IPPS (both disconnected by Disconnect-ExchangeOnline)
    try {
        Write-Host "  - Disconnecting Exchange Online / Security & Compliance..."
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-TranscriptLog "Exchange Online / IPPS session disconnected" 'SUCCESS' 'AUTH' | Out-Null
    } catch {
        Write-TranscriptLog "Exchange Online disconnect warning: $($_.Exception.Message)" 'WARNING' 'AUTH' | Out-Null
    }

    # Microsoft Graph
    try {
        $GraphCtx = Get-MgContext -ErrorAction SilentlyContinue
        if ($GraphCtx) {
            Write-Host "  - Disconnecting Microsoft Graph..."
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-TranscriptLog "Microsoft Graph session disconnected" 'SUCCESS' 'AUTH' | Out-Null
        }
    } catch {
        Write-TranscriptLog "Microsoft Graph disconnect warning: $($_.Exception.Message)" 'WARNING' 'AUTH' | Out-Null
    }

    Write-Host "  - All sessions disconnected." -ForegroundColor Green
    Write-TranscriptLog "All Microsoft Purview sessions disconnected" 'SUCCESS' 'AUTH' | Out-Null
}
