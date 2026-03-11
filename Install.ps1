<#
.SYNOPSIS
    Installs AsBuiltReport.Microsoft.Purview into your PowerShell module path.
.DESCRIPTION
    Copies the module folder to the correct location so that
    New-AsBuiltReport -Report Microsoft.Purview works correctly.
    Run this script ONCE after extracting the zip.
.NOTES
    Run as the same user account you will use to generate reports.
    No administrator rights required (installs to CurrentUser scope).
#>

[CmdletBinding()]
param (
    # Override destination if needed. Defaults to CurrentUser module path.
    [string]$Destination = ($env:PSModulePath -split ';' | Where-Object { $_ -like "*$env:USERPROFILE*" } | Select-Object -First 1)
)

$ModuleName    = 'AsBuiltReport.Microsoft.Purview'
$ScriptRoot    = $PSScriptRoot   # folder where this Install.ps1 lives (= the extracted zip root)
$TargetFolder  = Join-Path $Destination $ModuleName

Write-Host "`nInstalling $ModuleName..." -ForegroundColor Cyan
Write-Host "  Source : $ScriptRoot"
Write-Host "  Target : $TargetFolder"

# Remove old version if present
if (Test-Path $TargetFolder) {
    Write-Host "  Removing existing installation at $TargetFolder..." -ForegroundColor Yellow
    Remove-Item -Path $TargetFolder -Recurse -Force
}

# Copy module files
Copy-Item -Path $ScriptRoot -Destination $TargetFolder -Recurse -Force
Write-Host "  Copied module files." -ForegroundColor Green

# Verify the manifest is importable
try {
    $null = Test-ModuleManifest -Path (Join-Path $TargetFolder "$ModuleName.psd1") -ErrorAction Stop
    Write-Host "  Module manifest validated successfully." -ForegroundColor Green
} catch {
    Write-Warning "Manifest validation warning: $_"
}

# Verify the cover page logo is present
$LogoPath = Join-Path $TargetFolder "$ModuleName.png"
if (Test-Path $LogoPath) {
    Write-Host "  Cover page logo found: $LogoPath" -ForegroundColor Green
} else {
    Write-Warning "Cover page logo not found at $LogoPath. The report will use the default AsBuiltReport logo."
}

Write-Host "`n$ModuleName installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Ensure prerequisite modules are installed:"
Write-Host "       Install-Module AsBuiltReport.Core -Force"
Write-Host "       Install-Module ExchangeOnlineManagement -Force"
Write-Host "       Install-Module Microsoft.Graph -Force"
Write-Host ""
Write-Host "  2. Generate your report:"
Write-Host "       New-AsBuiltReport -Report Microsoft.Purview ``"
Write-Host "           -Target 'yourtenantname.onmicrosoft.com' ``"
Write-Host "           -OutputFolderPath 'C:\Reports' ``"
Write-Host "           -ReportConfigFilePath '.\AsBuiltReport.Microsoft.Purview.json' ``"
Write-Host "           -OutputFormat HTML ``"
Write-Host "           -EnableHealthCheck"
Write-Host ""
