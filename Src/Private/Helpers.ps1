
function Write-AbrDebugTableObject {
    <#
    .SYNOPSIS
    Debug helper: logs any System.Boolean values found in a hashtable or pscustomobject
    before it reaches PScribo. Only active when TranscriptLogPath is set.
    Call immediately before $Obj.Add([pscustomobject]$inObj) to catch boolean sources.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        $InputObject,

        [Parameter(Mandatory, Position = 1)]
        [string]$Context
    )

    if (-not $script:TranscriptLogPath) { return }

    $boolKeys = @()
    if ($InputObject -is [System.Collections.Specialized.OrderedDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ($InputObject[$key] -is [System.Boolean]) {
                $boolKeys += "$key = $($InputObject[$key])"
            }
        }
    } elseif ($InputObject -is [pscustomobject]) {
        foreach ($prop in $InputObject.PSObject.Properties) {
            if ($prop.Value -is [System.Boolean]) {
                $boolKeys += "$($prop.Name) = $($prop.Value)"
            }
        }
    }

    if ($boolKeys.Count -gt 0) {
        $msg = "BOOLEAN DETECTED in [$Context]: $($boolKeys -join ' | ')"
        Write-TranscriptLog $msg 'WARNING' 'BOOL_DEBUG' | Out-Null
        Write-Host "  [BOOL_DEBUG] $msg" -ForegroundColor Magenta
    }
}

function Invoke-Ternary {
    <#
    .SYNOPSIS
    PS5.1-safe ternary operator. Returns TrueValue if Condition is truthy, else FalseValue.
    Solves "The term 'if' is not recognized" errors that occur when if-expressions are used
    as hashtable values inside nested PScribo Section{} scriptblocks on Windows PowerShell 5.1.
    Usage: Invoke-Ternary ($x -gt 0) 'Yes' 'No'
    #>
    param (
        [Parameter(Mandatory, Position = 0)] [AllowNull()] $Condition,
        [Parameter(Mandatory, Position = 1)] [AllowNull()] $TrueValue,
        [Parameter(Mandatory, Position = 2)] [AllowNull()] $FalseValue
    )
    if ($Condition) { $TrueValue } else { $FalseValue }
}

function Test-UserPrincipalName {
    <#
    .SYNOPSIS
    Validates that a string is a properly formatted User Principal Name.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )
    # RFC-compliant UPN: localpart@domain.tld
    return ($UserPrincipalName -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')
}

function Write-TranscriptLog {
    <#
    .SYNOPSIS
    Writes a structured log entry to the host and optionally to a transcript file.
    .DESCRIPTION
    Provides consistent log output across the module.
    Level values: DEBUG | INFO | SUCCESS | WARNING | ERROR
    Category is a short tag e.g. AUTH, DLP, RETENTION etc.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet('DEBUG', 'INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO',

        [Parameter(Position = 2)]
        [string]$Category = 'GENERAL'
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Entry     = "[$Timestamp] [$Level] [$Category] $Message"

    $null = switch ($Level) {
        'DEBUG'   { Write-PScriboMessage -Message $Entry | Out-Null }
        'INFO'    { Write-Host "  $Entry" }
        'SUCCESS' { Write-Host "  $Entry" -ForegroundColor Green }
        'WARNING' { Write-PScriboMessage -IsWarning -Message $Entry | Out-Null }
        'ERROR'   { Write-Host "  $Entry" -ForegroundColor Red }
    }

    # Append to transcript log file if path is set in script scope
    if ($script:TranscriptLogPath) {
        try {
            Add-Content -Path $script:TranscriptLogPath -Value $Entry -ErrorAction SilentlyContinue | Out-Null
        } catch { }
    }
}

function Invoke-WithRetry {
    <#
    .SYNOPSIS
    Executes a ScriptBlock with configurable retry logic and exponential back-off.
    .DESCRIPTION
    Retries the given ScriptBlock up to MaxAttempts times. Waits DelaySeconds
    between attempts, doubling the delay on each retry (exponential back-off).
    Throws on final failure.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory)]
        [string]$OperationName,

        [int]$MaxAttempts = 3,

        [int]$DelaySeconds = 5
    )

    $Attempt = 0
    $CurrentDelay = $DelaySeconds

    while ($Attempt -lt $MaxAttempts) {
        $Attempt++
        try {
            Write-TranscriptLog "Attempt ${Attempt}/${MaxAttempts}: $OperationName" 'DEBUG' 'RETRY'
            & $ScriptBlock
            Write-TranscriptLog "Attempt ${Attempt}/${MaxAttempts} succeeded: $OperationName" 'DEBUG' 'RETRY'
            return
        } catch {
            if ($Attempt -lt $MaxAttempts) {
                Write-TranscriptLog "Attempt ${Attempt}/${MaxAttempts} failed for '$OperationName'. Retrying in ${CurrentDelay}s... Error: $($_.Exception.Message)" 'WARNING' 'RETRY'
                Start-Sleep -Seconds $CurrentDelay
                $CurrentDelay = $CurrentDelay * 2   # exponential back-off
            } else {
                Write-TranscriptLog "All ${MaxAttempts} attempts failed for '$OperationName'. Error: $($_.Exception.Message)" 'ERROR' 'RETRY'
                throw
            }
        }
    }
}

function Show-AbrDebugExecutionTime {
    <#
    .SYNOPSIS
    Tracks and displays execution time for report sections.
    Compatible shim for AsBuiltReport.Core's Show-AbrDebugExecutionTime.
    #>
    [CmdletBinding()]
    param (
        [switch]$Start,
        [switch]$End,
        [string]$TitleMessage
    )

    if ($Start) {
        $script:SectionTimers[$TitleMessage] = [System.Diagnostics.Stopwatch]::StartNew()
        Write-TranscriptLog "Starting section: $TitleMessage" 'DEBUG' 'TIMER'
    }

    if ($End) {
        if ($script:SectionTimers -and $script:SectionTimers.ContainsKey($TitleMessage)) {
            $script:SectionTimers[$TitleMessage].Stop()
            $Elapsed = $script:SectionTimers[$TitleMessage].Elapsed.TotalSeconds
            Write-TranscriptLog "Completed section: $TitleMessage (${Elapsed}s)" 'DEBUG' 'TIMER'
            $null = $script:SectionTimers.Remove($TitleMessage)
        }
    }
}


function ConvertTo-TextYN {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter(Position = 0, Mandatory)]
        [AllowNull()]
        $TEXT
    )
    # Explicitly handle System.Boolean objects (Exchange Online cmdlets return
    # [System.Boolean] rather than PowerShell native bool literals, which causes
    # PScribo to throw "Unexpected System.Boolean" warnings if not caught here).
    if ($TEXT -is [System.Boolean]) {
        if ($TEXT) { return 'Yes' } else { return 'No' }
    }
    switch ($TEXT) {
        $true  { return 'Yes' }
        $false { return 'No' }
        $null  { return '--' }
        ''     { return '--' }
        default { return [string]$TEXT }
    }
}

function ConvertTo-HashToYN {
        <#
    .SYNOPSIS
    Converts boolean values in a hashtable to Yes/No strings.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Position = 0, Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [System.Collections.Specialized.OrderedDictionary] $TEXT
    )
    $result = [ordered] @{}
    foreach ($i in $TEXT.GetEnumerator()) {
        try {
            $result.add($i.Key, (ConvertTo-TextYN $i.Value))
        } catch {
            $result.add($i.Key, ($i.Value))
        }
    }
    if ($result) {
        $result
    } else { $TEXT }
}
function Write-AbrPurviewACSCCheck {
    <#
    .SYNOPSIS
    Renders an inline ACSC ISM / Essential Eight compliance check box
    directly beneath a report table (InfoLevel 3 only).
    .DESCRIPTION
        Outputs a compact two-column PScribo table showing each relevant ISM
        control ID, a plain-English description of what is being checked,
        and a Pass / Fail / Partial / Manual status. Colour-coded rows are
        applied when -EnableHealthCheck is active.

        Call this immediately after the Table command for each sub-section.
        Pass in an array of [ordered] hashtables, each with keys:
          ControlId   - e.g. 'ISM-0271'
          E8          - e.g. 'E8 Backup ML1'  or 'N/A'
          Description - Short description of the requirement
          Check       - What was checked in Purview
          Status      - 'Pass' | 'Fail' | 'Partial' | 'Manual'
    .PARAMETER Checks
        Array of [pscustomobject] check results.
    .PARAMETER TenantId
        Tenant identifier used in the table caption.
    .PARAMETER SectionName
        Label used in the table name, e.g. 'Sensitivity Labels'.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object[]]$Checks,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$SectionName
    )

    # Only render at InfoLevel 3+
    $MaxLevel = ($script:InfoLevel.PSObject.Properties.Value | Measure-Object -Maximum).Maximum
    if ($MaxLevel -lt 3) { return }

    $ACSCObj = [System.Collections.ArrayList]::new()
    foreach ($c in $Checks) {
        $ACSCObj.Add([pscustomobject][ordered]@{
            'Control'     = "$($c.ControlId)$(if ($c.E8 -and $c.E8 -ne 'N/A') { " / $($c.E8)" })"
            'Requirement' = $c.Description
            'Check'       = $c.Check
            'Status'      = $c.Status
        }) | Out-Null
    }

    if ($Healthcheck -and $script:HealthCheck.Purview.ACSC) {
        $ACSCObj | Where-Object { $_.Status -eq 'Fail' }    | Set-Style -Style Critical | Out-Null
        $ACSCObj | Where-Object { $_.Status -eq 'Partial' } | Set-Style -Style Warning  | Out-Null
        $ACSCObj | Where-Object { $_.Status -eq 'Manual' }  | Set-Style -Style Info     | Out-Null
    }

    BlankLine
    $ACSCTableParams = @{
        Name         = "ACSC ISM - $SectionName - $TenantId"
        List         = $false
        ColumnWidths = 20, 35, 30, 15
    }
    if ($script:Report.ShowTableCaptions) { $ACSCTableParams['Caption'] = "- $($ACSCTableParams.Name)" }
    $ACSCObj | Table @ACSCTableParams
}
