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
            $script:SectionTimers.Remove($TitleMessage)
        }
    }
}


function ConvertTo-TextYN {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter(Position = 0, Mandatory)]
        $TEXT
    )
    switch ($TEXT) {
        $true  { return 'Yes' }
        $false { return 'No' }
        $null  { return '--' }
        ''     { return '--' }
        default { return $TEXT }
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