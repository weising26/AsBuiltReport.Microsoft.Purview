# AsBuiltReport.Microsoft.Purview.psm1
# Root module file - dot-sources all public and private function files

$Public  = @(Get-ChildItem -Path "$PSScriptRoot\Src\Public\*.ps1"  -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path "$PSScriptRoot\Src\Private\*.ps1" -ErrorAction SilentlyContinue)

foreach ($Import in @($Public + $Private)) {
    try {
        . $Import.FullName
    } catch {
        Write-Error "Failed to import function $($Import.FullName): $_"
    }
}

# Export public functions only
Export-ModuleMember -Function $Public.BaseName
