<#
    .SYNOPSIS
        Diagnoses Microsoft.Graph SDK installation issues for CAMP.

    .DESCRIPTION
        Run this directly when CAMP says "Microsoft.Graph SDK is not installed" even
        though you've already run Install-Module Microsoft.Graph. It prints exactly
        which PowerShell is searching where, and what (if anything) it found.

        Common root causes the output will help spot:
          1. Installed in Windows PowerShell 5.1, running from PowerShell 7 (or vice versa).
             Each edition has its own module directory.
          2. Partial install — umbrella module present but Microsoft.Graph.Authentication
             sub-module missing.
          3. PSModulePath narrowed by a parent profile script or environment override.
#>
$ErrorActionPreference = 'Continue'

Write-Host "" 
Write-Host "================ PowerShell host ================" -ForegroundColor Cyan
Write-Host "PSEdition  : $($PSVersionTable.PSEdition)"
Write-Host "PSVersion  : $($PSVersionTable.PSVersion)"
Write-Host "Platform   : $($PSVersionTable.Platform)"
Write-Host "OS         : $($PSVersionTable.OS)"

Write-Host ""
Write-Host "================ PSModulePath (where modules are searched) ================" -ForegroundColor Cyan
$paths = $env:PSModulePath -split [System.IO.Path]::PathSeparator
$i = 1
foreach ($p in $paths) {
    $exists = if (Test-Path $p) { '[exists]' } else { '[MISSING]' }
    Write-Host ("  {0}. {1} {2}" -f $i, $p, $exists)
    $i++
}

Write-Host ""
Write-Host "================ Microsoft.Graph.* modules visible to this session ================" -ForegroundColor Cyan
$mods = Get-Module -ListAvailable -Name "Microsoft.Graph*" -ErrorAction SilentlyContinue
if (-not $mods) {
    Write-Host "  (none found — that's the problem)" -ForegroundColor Yellow
} else {
    $mods |
        Group-Object Name |
        ForEach-Object {
            $latest = $_.Group | Sort-Object Version -Descending | Select-Object -First 1
            Write-Host ("  {0}  v{1}  ({2})" -f $latest.Name, $latest.Version, $latest.ModuleBase)
        }
}

Write-Host ""
Write-Host "================ Critical sub-module presence ================" -ForegroundColor Cyan
$critical = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Sites",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Applications"
)
foreach ($name in $critical) {
    $m = Get-Module -ListAvailable -Name $name -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if ($m) {
        Write-Host ("  [OK]      {0}  v{1}" -f $name, $m.Version) -ForegroundColor Green
    } else {
        Write-Host ("  [MISSING] {0}" -f $name) -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "================ Next steps ================" -ForegroundColor Cyan
$auth = Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication" -ErrorAction SilentlyContinue | Select-Object -First 1
$anyGraph = Get-Module -ListAvailable -Name "Microsoft.Graph*" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($auth) {
    Write-Host "  Microsoft.Graph.Authentication is visible to this PowerShell -- CAMP should detect it." -ForegroundColor Green
    Write-Host "  If CAMP still says it's missing, you may have a separate pwsh / Windows PowerShell mismatch when running RunCAMPReport.ps1." -ForegroundColor Green
}
elseif ($anyGraph) {
    Write-Host "  Some Microsoft.Graph.* modules are present, but Authentication is missing. Run:" -ForegroundColor Yellow
    Write-Host "      Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force" -ForegroundColor Yellow
}
else {
    Write-Host "  No Microsoft.Graph.* modules found in this PowerShell. Run, in THIS shell:" -ForegroundColor Yellow
    Write-Host "      Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor Yellow
    Write-Host "  If you previously installed it in Windows PowerShell 5.1, that won't satisfy PowerShell 7 (separate module paths)." -ForegroundColor Yellow
}
Write-Host ""
