<#
    .SYNOPSIS
        Local-repo launcher for CAMP (Configuration Analyzer for Microsoft Purview).

    .DESCRIPTION
        Use this script to run THIS local copy of the CAMP module against a tenant —
        instead of the version published on PowerShell Gallery.

        It does five things you'd otherwise do by hand:
          1. Unloads any previously-loaded copies of the module
          2. Unblocks the .ps1 files (Windows MOTW — harmless no-op on macOS/Linux)
          3. Imports the local CAMP.psm1
          4. Calls Get-CAMPReport with -NoVersionCheck so your local edits don't
             trigger the "you're behind PSGallery" warning
          5. Forwards every common parameter (Geo, Solution, Blueprint, OutputFormat,
             ExchangeEnvironmentName, TurnOffDataCollection) to Get-CAMPReport.

    .PARAMETER Geo
        Optional geo numbers (1..14). See README for the full list.
        Default: omit to use your tenant's region.

    .PARAMETER Solution
        Optional solution numbers (1..8). Same list as the original CAMP.
        Default: omit to include every legacy solution.

    .PARAMETER Blueprint
        Optional Microsoft Purview Deployment Model numbers (1..6).
        1=Secure by Default, 2=Lightweight DLP, 3=Shadow AI, 4=Copilot agents,
        5=DSPM, 6=Reduce false positives.
        Default: omit to include every blueprint (foundational checks always run).

    .PARAMETER OutputFormat
        One or more of: HTML, JSON, CSV, Markdown.
        Default: HTML (matches the legacy behaviour).

    .PARAMETER ExchangeEnvironmentName
        One of: O365Default, O365USGovGCCHigh, O365USGovDoD.
        Default: O365Default (commercial cloud).

    .PARAMETER TurnOffDataCollection
        Pass-through to Get-CAMPReport.

    .EXAMPLE
        .\RunCAMPReport.ps1
        # Default — every check, HTML only, commercial cloud.

    .EXAMPLE
        .\RunCAMPReport.ps1 -Blueprint 1,2 -OutputFormat HTML,JSON,CSV,Markdown
        # Secure by Default + Lightweight DLP only, every output format.

    .EXAMPLE
        .\RunCAMPReport.ps1 -Blueprint 3 -OutputFormat Markdown
        # Just the Shadow AI scorecard, written as a Markdown summary.

    .EXAMPLE
        .\RunCAMPReport.ps1 -ExchangeEnvironmentName O365USGovGCCHigh
        # Run against GCC High.

    .NOTES
        Prerequisites:
          * ExchangeOnlineManagement 3.0.0+ (Install-Module ExchangeOnlineManagement)
          * Optional: Microsoft.Graph SDK (Install-Module Microsoft.Graph) — needed
            for Shadow AI / Copilot Agents / DSPM checks that read SharePoint sites,
            Entra apps, directory roles, and Conditional Access policies. The tool
            degrades gracefully when the SDK is missing.

        Output files land in:
          * Windows: %LOCALAPPDATA%\Microsoft\CAMP\
          * macOS / Linux: ~/CAMP/
#>
[CmdletBinding()]
param(
    [System.Collections.ArrayList] $Geo = @(),
    [System.Collections.ArrayList] $Solution = @(),
    [System.Collections.ArrayList] $Blueprint = @(),
    [ValidateSet('HTML','JSON','CSV','Markdown')]
    [string[]] $OutputFormat = @('HTML'),
    [ValidateSet('O365Default','O365USGovDoD','O365USGovGCCHigh')]
    [string] $ExchangeEnvironmentName = 'O365Default',
    [switch] $TurnOffDataCollection
)

$ErrorActionPreference = 'Stop'

# --- 1. Unload anything previously imported (so we definitely run this copy) ---
foreach ($m in @('CAMP','MCCAPreview','ExchangeOnlineManagement')) {
    if (Get-Module -Name $m -ErrorAction SilentlyContinue) {
        Write-Host "Unloading already-loaded module: $m" -ForegroundColor DarkGray
        Remove-Module $m -Force -ErrorAction SilentlyContinue
    }
}

# --- 2. Unblock files (Windows MOTW). On macOS/Linux this is a quiet no-op. ---
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = (Get-Location).Path }
try {
    Get-ChildItem -Path $ScriptRoot -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
    Get-ChildItem -Path $ScriptRoot -Recurse -Filter '*.psm1' -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
} catch { }

# --- 3. Import this local module ---
$ModulePath = Join-Path $ScriptRoot 'CAMP.psm1'
if (-not (Test-Path $ModulePath)) {
    throw "Could not find CAMP.psm1 at $ModulePath. Run this script from the repo root."
}
Write-Host "Importing local module: $ModulePath" -ForegroundColor Cyan
Import-Module $ModulePath -Force

# --- 4. Friendly summary of what we're about to do ---
Write-Host ""
Write-Host "Running Get-CAMPReport against tenant:" -ForegroundColor Cyan
Write-Host "  ExchangeEnvironmentName : $ExchangeEnvironmentName"
if ($Geo.Count -gt 0)         { Write-Host "  Geo                     : $($Geo -join ', ')" }       else { Write-Host "  Geo                     : (auto-detect)" }
if ($Solution.Count -gt 0)    { Write-Host "  Solution                : $($Solution -join ', ')" }  else { Write-Host "  Solution                : (all legacy solutions)" }
if ($Blueprint.Count -gt 0)   { Write-Host "  Blueprint               : $($Blueprint -join ', ')" } else { Write-Host "  Blueprint               : (all blueprints)" }
Write-Host "  OutputFormat            : $($OutputFormat -join ', ')"
Write-Host "  NoVersionCheck          : True (running local repo build)"
Write-Host ""

# --- 5. Forward all parameters to Get-CAMPReport ---
$splat = @{
    NoVersionCheck         = $true
    ExchangeEnvironmentName = $ExchangeEnvironmentName
    OutputFormat           = $OutputFormat
}
if ($Geo.Count       -gt 0) { $splat['Geo']        = $Geo }
if ($Solution.Count  -gt 0) { $splat['Solution']   = $Solution }
if ($Blueprint.Count -gt 0) { $splat['Blueprint']  = $Blueprint }
if ($TurnOffDataCollection) { $splat['TurnOffDataCollection'] = $true }

Get-CAMPReport @splat
