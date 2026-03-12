<#
.SYNOPSIS
    Installs AsBuiltReport.Microsoft.Purview into a PowerShell module path.
.DESCRIPTION
    Copies the module folder to the correct location so that
    New-AsBuiltReport -Report Microsoft.Purview works correctly.

    DESTINATION SELECTION (first match wins):
      1. -Destination parameter (explicit override)
      2. First path in $env:PSModulePath that already contains an
         'AsBuiltReport.Microsoft.Purview' folder (upgrade in-place)
      3. First path in $env:PSModulePath that is under $USERPROFILE
         (standard CurrentUser install)
      4. First path in $env:PSModulePath (fallback)

    This means dev layouts like:
        $env:PSModulePath += ';C:\...\AsBuilt'
    are automatically detected and the module is placed correctly.

.PARAMETER Destination
    Explicit destination FOLDER (parent of the module folder).
    Omit to let the script auto-detect from $env:PSModulePath.

.PARAMETER Force
    Suppress the confirmation prompt when overwriting an existing install.

.NOTES
    Run as the same user account you will use to generate reports.
    No administrator rights required for CurrentUser installs.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [string]$Destination,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ModuleName = 'AsBuiltReport.Microsoft.Purview'
$ScriptRoot = $PSScriptRoot   # folder where Install.ps1 lives = the module root

#region ── Resolve destination ──────────────────────────────────────────────────
if (-not $Destination) {
    $PathList = $env:PSModulePath -split ';' | Where-Object { $_ -ne '' }

    # 1. Prefer a path that already has this module (upgrade in-place)
    $Destination = $PathList |
        Where-Object { Test-Path (Join-Path $_ $ModuleName) } |
        Select-Object -First 1

    # 2. Fall back to first path under USERPROFILE
    if (-not $Destination) {
        $Destination = $PathList |
            Where-Object { $_ -like "*$env:USERPROFILE*" } |
            Select-Object -First 1
    }

    # 3. Last resort: first path in the list
    if (-not $Destination) {
        $Destination = $PathList | Select-Object -First 1
    }
}

if (-not $Destination) {
    throw 'Could not determine a destination folder. Pass -Destination explicitly.'
}

$TargetFolder = Join-Path $Destination $ModuleName
#endregion

#region ── Pre-flight summary ────────────────────────────────────────────────────
Write-Host "`nInstalling $ModuleName..." -ForegroundColor Cyan
Write-Host "  Source      : $ScriptRoot"
Write-Host "  Destination : $Destination"
Write-Host "  Module path : $TargetFolder"
#endregion

#region ── Remove existing install ───────────────────────────────────────────────
if (Test-Path $TargetFolder) {
    if (-not $Force) {
        $answer = Read-Host "  '$TargetFolder' already exists. Overwrite? [Y/N]"
        if ($answer -notmatch '^[Yy]') {
            Write-Host '  Installation cancelled.' -ForegroundColor Yellow
            return
        }
    }
    Write-Host "  Removing existing installation..." -ForegroundColor Yellow
    Remove-Item -Path $TargetFolder -Recurse -Force
}
#endregion

#region ── Copy module files ─────────────────────────────────────────────────────
# Ensure the destination parent exists (e.g. a dev folder that isn't created yet)
if (-not (Test-Path $Destination)) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Write-Host "  Created destination folder: $Destination" -ForegroundColor Yellow
}

Copy-Item -Path $ScriptRoot -Destination $TargetFolder -Recurse -Force
Write-Host "  Module files copied." -ForegroundColor Green
#endregion

#region ── Validate manifest ─────────────────────────────────────────────────────
try {
    $null = Test-ModuleManifest -Path (Join-Path $TargetFolder "$ModuleName.psd1") -ErrorAction Stop
    Write-Host "  Module manifest validated." -ForegroundColor Green
} catch {
    Write-Warning "Manifest validation warning: $_"
}
#endregion

#region ── Check cover page logo ─────────────────────────────────────────────────
$LogoPath = Join-Path $TargetFolder 'Src\Public\AsBuiltReport.Microsoft.Purview.png'
if (Test-Path $LogoPath) {
    Write-Host "  Cover page logo found." -ForegroundColor Green
} else {
    Write-Warning "Cover page logo not found at '$LogoPath'. The report cover may be missing the Purview logo."
}
#endregion

#region ── Verify PSModulePath visibility ────────────────────────────────────────
$IsVisible = ($env:PSModulePath -split ';') -contains $Destination
if (-not $IsVisible) {
    Write-Host ''
    Write-Warning @"
The destination folder is NOT currently in `$env:PSModulePath:
    $Destination

PowerShell will not find the module until this path is added.
Add it for this session:
    `$env:PSModulePath += ';$Destination'

To persist across sessions, add it to your PowerShell profile:
    Add-Content `$PROFILE "`n`$env:PSModulePath += ';$Destination'"
"@
} else {
    Write-Host "  Destination is in `$env:PSModulePath — module will be auto-discovered." -ForegroundColor Green
}
#endregion

Write-Host "`n$ModuleName installed successfully!`n" -ForegroundColor Green
Write-Host 'Next steps:' -ForegroundColor Cyan
Write-Host '  1. Ensure prerequisite modules are installed:'
Write-Host '       Install-Module AsBuiltReport.Core -Force'
Write-Host '       Install-Module ExchangeOnlineManagement -Force'
Write-Host '       Install-Module Microsoft.Graph -Force'
Write-Host ''
Write-Host '  2. Set your tenant UPN in AsBuiltReport.Microsoft.Purview.json:'
Write-Host '       "UserPrincipalName": "admin@yourtenant.onmicrosoft.com"'
Write-Host ''
Write-Host '  3. Generate the report:'
Write-Host "       New-AsBuiltReport -Report Microsoft.Purview ``"
Write-Host "           -Target 'yourtenant.onmicrosoft.com' ``"
Write-Host "           -OutputFolderPath 'C:\Reports' ``"
Write-Host "           -ReportConfigFilePath '.\AsBuiltReport.Microsoft.Purview.json' ``"
Write-Host "           -OutputFormat Word, HTML ``"
Write-Host "           -EnableHealthCheck"
Write-Host ''
