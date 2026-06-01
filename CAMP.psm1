#Requires -Version 5.1

<#
	.SYNOPSIS
		CAMP - Configuration Analyzer for Microsoft Purview (CAMP)

	.DESCRIPTION

	.NOTES
		Neha Pandey
		Senior Software Engineer - Microsoft
              
        Kritika Mishra
        Software Engineer - Microsoft
             


        Output report uses open source components for HTML formatting
        - bootstrap - MIT License - https://getbootstrap.com/docs/4.0/about/license/
        - fontawesome - CC BY 4.0 License - https://fontawesome.com/license/free
        
        ############################################################################

        This sample script is not supported under any Microsoft standard support program or service. 
        This sample script is provided AS IS without warranty of any kind. 
        Microsoft further disclaims all implied warranties including, without limitation, any implied 
        warranties of merchantability or of fitness for a particular purpose. The entire risk arising 
        out of the use or performance of the sample script and documentation remains with you. In no
        event shall Microsoft, its authors, or anyone else involved in the creation, production, or 
        delivery of the scripts be liable for any damages whatsoever (including, without limitation, 
        damages for loss of business profits, business interruption, loss of business information, 
        or other pecuniary loss) arising out of the use of or inability to use the sample script or
        documentation, even if Microsoft has been advised of the possibility of such damages.

        ############################################################################    

	.LINK
        about_functions_advanced

#>
[bool] $global:ErrorOccurred = $false

# TelemetryEnabled 
[bool] $global:TelemetryEnabled = $false

# Connection Established 
[bool] $global:ConnectionEstablished = $false

[string] $global:EnvironmentName = ""
[string] $global:UserName = ""
function Get-CAMPDirectory {
    <#

        Gets or creates the CAMP directory in AppData

        Note: PowerShell 7 exposes $IsMacOS (not $IsMac). On PS 5.1 (Windows-only)
        none of the $Is* automatic variables exist, so we fall through to the
        Windows default — which is correct on PS 5.1.

    #>
    if ($IsWindows) {
        $Directory = Join-Path $env:LOCALAPPDATA "Microsoft/CAMP"
    }
    elseif ($IsLinux -or $IsMacOS) {
        $Directory = Join-Path $env:HOME "CAMP"
    }
    else {
        # PS 5.1 path — $IsWindows isn't defined but we're on Windows
        $Directory = Join-Path $env:LOCALAPPDATA "Microsoft/CAMP"
    }
	
    If (Test-Path $Directory) {
        Return $Directory
    } 
    else {
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
        Return $Directory
    }
}

Function Invoke-CAMPConnections {
    Param
    (
        [String]$ExchangeEnvironmentName,
        [String]$LogFile
    )


    try {
        $MinRequiredVersion = [Version]"3.0.0"
        try {
            $ExchangeVersionString = (Get-InstalledModule -name "ExchangeOnlineManagement" -ErrorAction:SilentlyContinue | Sort-Object Version -Desc)[0].Version
            $ExchangeVersion = [Version]$ExchangeVersionString
        }
        catch {
            $ExchangeVersion = $null
            Write-Host "$(Get-Date) Exchange Online Management module is not installed. Installing.."
            Write-Verbose "Installing ExchangeOnlineManagement"
            Install-Module -Name "ExchangeOnlineManagement" -Force -AllowClobber
        }


        if ($null -eq $ExchangeVersion) {
            $ExchangeVersionString = (Get-InstalledModule -name "ExchangeOnlineManagement" -ErrorAction:SilentlyContinue | Sort-Object Version -Desc)[0].Version
            $ExchangeVersion = [Version]$ExchangeVersionString
        }

        if ($ExchangeVersion -lt $MinRequiredVersion) {
            Write-Host "$(Get-Date) Your Exchange Online Management module version ($ExchangeVersion) is outdated. Minimum required: $MinRequiredVersion. Updating.."
            Update-Module -Name "ExchangeOnlineManagement" -Force
        }

        $global:ConnectionEstablished = $true

        $userName = Read-Host -Prompt 'Input the user name' -ErrorAction:SilentlyContinue
        $global:UserName = $userName
        $InfoMessage = "Connecting to Exchange Online (Modern Module).."
        Write-Host "$(Get-Date) $InfoMessage"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        Connect-ExchangeOnline -Prefix EXOP -UserPrincipalName $userName -ExchangeEnvironmentName $ExchangeEnvironmentName -ShowBanner:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
    }
    catch {
        Write-Host "Error:$(Get-Date) There was an issue in connecting to Exchange Online. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
    }

    try {
        switch ($ExchangeEnvironmentName) {
            #O365China {  }
            #O365GermanyCloud { $ConnectionUri = 'https://ps.compliance.protection.outlook.de/' }
            O365USGovDoD { $ConnectionUri = 'https://l5.ps.compliance.protection.office365.us/powershell-liveid/' }
            O365USGovGCCHigh { $ConnectionUri = 'https://ps.compliance.protection.office365.us/powershell-liveid/' }
            Default { $ConnectionUri = '' }
        }

        $InfoMessage = "Connecting to Security & Compliance PowerShell (Microsoft Purview)"
        Write-Host "$(Get-Date) $InfoMessage"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        if ($ConnectionUri -eq '') {
            Connect-IPPSSession -UserPrincipalName $userName -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
        }
        else {
            Connect-IPPSSession -UserPrincipalName $userName -ConnectionUri $ConnectionUri -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
        }
        try { $statusCode = Invoke-WebRequest -Uri "https://aka.ms/mcca-execution" -Method Head -UseBasicParsing | ForEach-Object { $_.StatusCode } } catch {}
    }
    catch {
        Write-Host "Error:$(Get-Date) There was an issue in connecting to Security & Compliance PowerShell. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
        throw 'There was an issue in connecting to Security & Compliance PowerShell. Please try running the tool again after some time.'
    }
}

# Optional Microsoft Graph SDK connection used by the newer Purview deployment-model checks
# (Shadow AI, Secure Copilot Agents, DSPM). Falls back to a "graph-unavailable" state when
# the Microsoft.Graph SDK module is not installed or the user declines consent.
[bool] $global:GraphConnectionEstablished = $false

Function Invoke-CAMPGraphConnections {
    Param
    (
        [String]$LogFile
    )

    $global:GraphConnectionEstablished = $false

    try {
        # Diagnostic: which PowerShell are we running, and where does it look for modules?
        $PsEdition = $PSVersionTable.PSEdition
        $PsVersion = $PSVersionTable.PSVersion.ToString()
        Write-Log -IsInfo -InfoMessage "Graph probe: PSEdition=$PsEdition PSVersion=$PsVersion" -LogFile $LogFile -ErrorAction:SilentlyContinue

        # Try several known submodules — Authentication is the only strictly-required one,
        # but checking for ANY Microsoft.Graph.* installation gives a friendlier error if
        # the umbrella module was partially installed.
        $AuthModule = Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication" -ErrorAction:SilentlyContinue | Sort-Object Version -Desc | Select-Object -First 1
        $AnyGraph   = Get-Module -ListAvailable -Name "Microsoft.Graph*" -ErrorAction:SilentlyContinue | Sort-Object Version -Desc | Select-Object -First 1

        if ($null -eq $AuthModule) {
            if ($null -ne $AnyGraph) {
                # Partial install — umbrella or some sub-modules present but Authentication is not.
                $InfoMessage = @"
Microsoft.Graph.Authentication module not found, but other Microsoft.Graph.* modules are available (e.g. $($AnyGraph.Name) $($AnyGraph.Version) at $($AnyGraph.ModuleBase)).
Graph-backed checks will be skipped. Try repairing the install with:
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
or reinstall the umbrella module:
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
Running PowerShell: $PsEdition $PsVersion
"@
            }
            else {
                # Nothing found at all — most often "installed in different PS edition".
                $CurrentPaths = ($env:PSModulePath -split [System.IO.Path]::PathSeparator) -join "`n    "
                $InfoMessage = @"
Microsoft.Graph SDK is not installed for this PowerShell ($PsEdition $PsVersion).
If you installed it in a different PowerShell edition (e.g. installed in Windows PowerShell 5.1 but running this in PowerShell 7), re-install it here with:
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
PSModulePath being searched:
    $CurrentPaths
Graph-backed checks (Shadow AI, Copilot Agents, DSPM blueprints) will be skipped.
"@
            }
            Write-Host "$(Get-Date) $InfoMessage" -ForegroundColor:Yellow
            Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
            return
        }

        Write-Log -IsInfo -InfoMessage "Graph probe: found Microsoft.Graph.Authentication $($AuthModule.Version) at $($AuthModule.ModuleBase)" -LogFile $LogFile -ErrorAction:SilentlyContinue

        # Import the submodules we need. -ErrorAction:Stop so a load failure is loud, not silent.
        $RequiredSubmodules = @(
            "Microsoft.Graph.Authentication",
            "Microsoft.Graph.Sites",
            "Microsoft.Graph.Identity.DirectoryManagement",
            "Microsoft.Graph.Identity.SignIns",
            "Microsoft.Graph.Applications"
        )
        $LoadedSubmodules = @()
        $MissingSubmodules = @()
        foreach ($sub in $RequiredSubmodules) {
            try {
                Import-Module $sub -ErrorAction:Stop -WarningAction:SilentlyContinue
                $LoadedSubmodules += $sub
            }
            catch {
                $MissingSubmodules += $sub
                Write-Log -IsInfo -InfoMessage "Graph probe: failed to import $sub - $($_.Exception.Message)" -LogFile $LogFile -ErrorAction:SilentlyContinue
            }
        }
        if ($MissingSubmodules.Count -gt 0) {
            Write-Host "$(Get-Date) Some Microsoft.Graph submodules could not be loaded: $($MissingSubmodules -join ', '). Checks needing those will report Not Assessed." -ForegroundColor:Yellow
        }

        $RequiredScopes = @(
            "Sites.Read.All",
            "Directory.Read.All",
            "Application.Read.All",
            "InformationProtectionPolicy.Read",
            "Policy.Read.All",
            "RoleManagement.Read.Directory"
        )

        $InfoMessage = "Connecting to Microsoft Graph (interactive)"
        Write-Host "$(Get-Date) $InfoMessage"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue

        $GraphEnvironment = "Global"
        switch ($global:EnvironmentName) {
            "O365USGovGCCHigh" { $GraphEnvironment = "USGov" }
            "O365USGovDoD" { $GraphEnvironment = "USGovDoD" }
            Default { $GraphEnvironment = "Global" }
        }

        # Use -ErrorAction Stop so a cancelled browser sign-in surfaces as a catchable error
        # instead of being swallowed silently into an ambiguous half-connected state.
        try {
            Connect-MgGraph -Scopes $RequiredScopes -Environment $GraphEnvironment -NoWelcome -ErrorAction:Stop -WarningAction:SilentlyContinue | Out-Null
        }
        catch {
            Write-Host "$(Get-Date) Microsoft Graph sign-in did not complete: $($_.Exception.Message). Graph-backed checks will report limited information." -ForegroundColor:Yellow
            Write-Log -IsInfo -InfoMessage "Graph sign-in failed: $($_.Exception.Message)" -LogFile $LogFile -ErrorAction:SilentlyContinue
            return
        }

        $Context = Get-MgContext -ErrorAction:SilentlyContinue
        if ($null -eq $Context) {
            Write-Host "$(Get-Date) Microsoft Graph context unavailable after Connect-MgGraph. Graph-backed checks will report limited information." -ForegroundColor:Yellow
            return
        }

        # Validate that at least the highest-value scope was granted; an existing legacy context
        # may otherwise look "connected" while missing the scopes our checks need.
        $GrantedScopes = @($Context.Scopes)
        $MissingCriticalScopes = @($RequiredScopes | Where-Object { $GrantedScopes -notcontains $_ })
        if ($MissingCriticalScopes.Count -eq $RequiredScopes.Count) {
            Write-Host "$(Get-Date) Microsoft Graph context exists but none of the required scopes were granted. Graph-backed checks will report limited information." -ForegroundColor:Yellow
            return
        }

        $global:GraphConnectionEstablished = $true
        $InfoMessage = "Microsoft Graph connection established as $($Context.Account) (granted scopes: $($GrantedScopes.Count); missing: $($MissingCriticalScopes.Count))"
        Write-Host "$(Get-Date) $InfoMessage"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {
        $global:GraphConnectionEstablished = $false
        Write-Host "$(Get-Date) Microsoft Graph connection unavailable: $($_.Exception.Message). Graph-backed checks will report limited information." -ForegroundColor:Yellow
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
}

enum CheckType {
    ObjectPropertyValue
    PropertyValue
}

[Flags()]
enum CAMPBlueprint {
    None = 0
    SecureByDefault = 1
    LightweightDLP = 2
    ShadowAI = 4
    CopilotAgents = 8
    DSPM = 16
    ReduceFalsePositives = 32
}

enum CAMPMaturityLevel {
    None = 0
    Good = 1
    Better = 2
    Best = 3
}

[Flags()]
enum CAMPService {
    DLP = 1
    OATP = 2
}

enum CAMPConfigLevel {
    None = 0
    Recommendation = 4
    Ok = 5
    Informational = 10
    TooStrict = 15
}

enum CAMPResult {
    Pass = 1
    Recommendation = 2
    Fail = 3
}

Class CAMPCheckConfig {

    CAMPCheckConfig() {
        # Constructor

        $this.Results += New-Object -TypeName CAMPCheckConfigResult -Property @{
            Level = [CAMPConfigLevel]::Recommendation
        }

        $this.Results += New-Object -TypeName CAMPCheckConfigResult -Property @{
            Level = [CAMPConfigLevel]::Ok
        }

        $this.Results += New-Object -TypeName CAMPCheckConfigResult -Property @{
            Level = [CAMPConfigLevel]::Informational 
        }

        $this.Results += New-Object -TypeName CAMPCheckConfigResult -Property @{
            Level = [CAMPConfigLevel]::TooStrict
        }

    }

    # Set the result for this mode
    SetResult([CAMPConfigLevel]$Level, $Result) {
        ($this.Results | Where-Object { $_.Level -eq $Level }).Value = $Result
        # The level of this configuration should be its strongest result (e.g if its currently Ok and we have a Informational pass, we should make the level Informational)
        if ($Result -eq "Pass" -and ($this.Level -lt $Level -or $this.Level -eq [CAMPConfigLevel]::None)) {
            $this.Level = $Level
        } 
        elseif ($Result -eq "Fail" -and ($Level -eq [CAMPConfigLevel]::Recommendation -and $this.Level -eq [CAMPConfigLevel]::None)) {
            $this.Level = $Level
        }

    }

    $Check
    $Object
    $ConfigItem
    $ConfigData
    $InfoText
    [string]$RemediationAction = ""
    [array]$Results
    [CAMPConfigLevel]$Level
}

Class CAMPCheckConfigResult {
    [CAMPConfigLevel]$Level = [CAMPConfigLevel]::Ok
    $Value
}
Class CAMPRemediationInfo {
    [bool]$RemediationAvailable = $false
    [string]$RemediationText = ""
}

Class CAMPCheck {
    <#

        Check definition

        The checks defined below allow contextual information to be added in to the report HTML document.
        - Control               : A unique identifier that can be used to index the results back to the check
        - Area                  : The area that this check should appear within the report
        - PassText              : The text that should appear in the report when this 'control' passes
        - FailRecommendation    : The text that appears as a title when the 'control' fails. Short, descriptive. E.g "Do this"
        - Importance            : Why this is important
        - ExpandResults         : If we should create a table in the callout which points out which items fail and where
        - ObjectType            : When ExpandResults is set to, For Object, Property Value checks - what is the name of the Object, e.g a Spam Policy
        - ItemName              : When ExpandResults is set to, what does the check return as ConfigItem, for instance, is it a Transport Rule?
        - DataType              : When ExpandResults is set to, what type of data is returned in ConfigData, for instance, is it a Domain?    

    #>

    [Array] $Config = @()
    [string] $Control
    [string] $ParentArea
    [String] $Area
    [String] $Name
    [String] $PassText
    [String] $FailRecommendation
    [Boolean] $ExpandResults = $false
    [String] $ObjectType
    [String] $ItemName
    [String] $DataType
    [String] $Importance
    [CAMPService]$Services = [CAMPService]::DLP
    [CheckType] $CheckType = [CheckType]::PropertyValue
    [CAMPRemediationInfo] $CAMPRemediationInfo
    [string] $LogFile 
    [string] $ExchangeEnvironmentNameForCheck = $global:EnvironmentName
    $Links
    $CAMPParams

    # Microsoft Purview Deployment Model alignment.
    # Blueprint = which deployment models this check supports (any combination of CAMPBlueprint flags).
    # MaturityLevel = where on the Good/Better/Best progression this check falls (per Lightweight DLP nomenclature).
    # BlueprintStages = per-blueprint step number (e.g. @{ "SecureByDefault" = 2 } for SbD Step 2).
    # Foundational = if $true, this check is included in every report regardless of -Blueprint filter
    #                (because it represents baseline Purview hygiene). Legacy CAMP checks default to $true.
    # RequiredCollections / RequiredGraphScopes / RequiredLicenses tell the runtime (and future docs)
    # what the check needs to run; CommercialOnly = $true means the check is not available in GCCH/DoD.
    [CAMPBlueprint] $Blueprint = [CAMPBlueprint]::None
    [CAMPMaturityLevel] $MaturityLevel = [CAMPMaturityLevel]::None
    [hashtable] $BlueprintStages = @{}
    [bool] $Foundational = $false
    [string[]] $RequiredCollections = @()
    [string[]] $RequiredGraphScopes = @()
    [string[]] $RequiredLicenses = @()
    [bool] $CommercialOnly = $false
    [string] $UnavailableReason = ""

    [CAMPResult] $Result = [CAMPResult]::Pass
    [int] $FailCount = 0
    [int] $PassCount = 0
    [int] $InfoCount = 0
    [Boolean] $Completed = $false
    
    # Overridden by check
    GetResults($Config) { }

    # Helper for new-blueprint checks: mark this check as "skipped because the data source is missing"
    # (e.g. Microsoft.Graph not installed, the user declined consent, or the tenant lacks the licensed feature).
    # Sets Completed=$false so the HTML/JSON/CSV/Markdown outputs surface it consistently across modules.
    SetUnavailable([string]$Reason) {
        $this.Completed = $false
        $this.UnavailableReason = $Reason
    }

    # Convenience used by Graph-backed checks to ask "is this collection key usable?"
    # Returns $false ONLY when the legacy CAMP collection layer signaled a hard error
    # (the literal string "Error") or the key was never set. A $null value or empty
    # array is treated as a valid empty result — the check should iterate it (foreach
    # over $null is a no-op in PowerShell) and emit a "no items configured" finding
    # rather than mis-reporting it as "data source unavailable". This mirrors the
    # convention used by the legacy CAMP check files (check-IP101.ps1 etc.) which
    # only branch on `-eq "Error"`.
    [bool] HasCollection($Config, [string]$Key) {
        if ($null -eq $Config) { return $false }
        if (-not $Config.ContainsKey($Key)) { return $false }
        $value = $Config[$Key]
        if ($value -is [string] -and $value -eq "Error") { return $false }
        return $true
    }

    # Emit a single Recommendation-level Config row pointing the admin at a portal
    # surface, then mark the check Completed. Used by checks that target preview or
    # portal-only Purview features where there's no reliable PowerShell verification
    # path. Prevents the check from disappearing into the "Not assessed" section —
    # it shows up as an actionable Recommendation in the main report instead.
    EmitAwarenessRecommendation([string]$ObjectName, [string]$ConfigItem, [string]$ConfigData, [string]$InfoText) {
        $cfg = [CAMPCheckConfig]::new()
        $cfg.Object     = $ObjectName
        $cfg.ConfigItem = $ConfigItem
        $cfg.ConfigData = $ConfigData
        $cfg.InfoText   = $InfoText
        $cfg.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
        $this.AddConfig($cfg)
        $this.Completed = $true
    }

    AddConfig([CAMPCheckConfig]$Config) {
        $this.Config += $Config

        $this.FailCount = @($this.Config | Where-Object { $_.Level -eq [CAMPConfigLevel]::None }).Count
        $this.PassCount = @($this.Config | Where-Object { $_.Level -eq [CAMPConfigLevel]::Ok -or $_.Level -eq [CAMPConfigLevel]::Informational }).Count
        $this.InfoCount = @($this.Config | Where-Object { $_.Level -eq [CAMPConfigLevel]::Recommendation }).Count

        If ($this.FailCount -eq 0 -and $this.InfoCount -eq 0) {
            $this.Result = [CAMPResult]::Pass
        }
        elseif ($this.FailCount -eq 0 -and $this.InfoCount -gt 0) {
            $this.Result = [CAMPResult]::Recommendation
        }
        else {
            $this.Result = [CAMPResult]::Fail    
        }
        
       

    }

    # Run
    Run($Config) {
        Write-Host "$(Get-Date) Analysis - $($this.Area) - $($this.Name)"

        $this.GetResults($Config)

        # If there is no results to expand, turn off ExpandResults
        if ($this.Config.Count -eq 0) {
            $this.ExpandResults = $false
        }

        
    }

}

Class CAMPOutput {

    [String]    $Name
    [Boolean]   $Completed = $False
    $VersionCheck
    $DefaultOutputDirectory
    $Result

    # Function overridden
    RunOutput($Checks, $Collection) {

    }

    Run($Checks, $Collection) {

        $this.RunOutput($Checks, $Collection)

        $this.Completed = $True
    }

}
Class RemediationAction {

    [String]    $Name
    [Boolean]   $Completed = $False
    $VersionCheck
    $DefaultOutputDirectory
    $Result

    # Function overridden
    RunOutput($Checks, $Collection) {

    }

    Run($Checks, $Collection) {

        $this.RunOutput($Checks, $Collection)

        $this.Completed = $True
    }

}

Function Get-CAMPCheckDefs {
    Param
    (
        [string]$LogFile,
        $CAMPParams,
        $Collection
    )

    $Checks = @()

    # Load individual check definitions
    $CheckFiles = Get-ChildItem "$PSScriptRoot\Checks"

    # DLP check file full name
    $DLPCheckFileName = $null
    
    #Setting DLP check file name
    ForEach ($CheckFile in $CheckFiles) {
        if (($CheckFile.BaseName -match '^check-(.*)$') -and ($matches[1] -like "DLP")) {
            $DLPCheckFileName = $CheckFile.FullName
        }
    }
    
    
    #Creating DLP check objects for each improvement actions

    #read xml doc
    if ($($Collection["GetRequiredSolution"]) -icontains "DLP") {
        [xml]$CheckData = Get-Content "$PSScriptRoot\DLPImprovementActions\ActionsInformation.xml"
        if ($null -eq $CheckData -or $CheckData -eq "") {
            Write-Host "$(Get-Date) ActionsInformation.xml file does not exist/is corrupt in $PSScriptRoot\DLPImprovementActions\ActionsInformation.xml." -ForegroundColor Orange           
        }

        if ($null -ne $DLPCheckFileName -or $DLPCheckFileName -ne "") {
            Write-Verbose "Importing DLP"
            . $DLPCheckFileName
            foreach ($Item in $CheckData.ImprovementActions.ActionItem) {
                #List of SIT
                $ListOfSIT = @()
                $AllSITS = $Item.SITs.SIT

            
                #Adding custom SITS
                <#      if($($Collection["GetDLPCustomSIT"]) -ne "Error")
            {
                $CustomSIT = $($Collection["GetDLPCustomSIT"]).Name
                foreach ($sit in $CustomSIT) {
                    $ListOfSIT += $sit
                }
            }
    #>

                if ($($Collection["GetOrganisationRegion"]) -eq "Error") {
                    foreach ($sit in $AllSITS) {
                        $ListOfSIT += $sit.InnerText
                    }
                }
                else {
                    foreach ($sit in $AllSITS) {
                        if ($($Collection["GetOrganisationRegion"]) -contains $($sit.Geo)) {
                            $ListOfSIT += $sit.InnerText
                        }
                    }

                }
    
                #Hash table of links
                $LinksInfo = @{}
                if ($global:EnvironmentName -ieq "O365USGovGCCHigh") {
                    $AllLinks = $Item.GCCLinks.Link
                }
                elseif ($global:EnvironmentName -ieq "O365USGovDoD") {
                    $AllLinks = $Item.DODLinks.Link
                }
                else {
                    $AllLinks = $Item.Links.Link
                }
                foreach ($url in $AllLinks) {
                    $LinksInfo[$url.LinkText] = $url.ActualURL
                }
                $InfoParams = @{}
                $InfoParams["Control"] = $Item.CheckName
                $InfoParams["ParentArea"] = $Item.ParentArea
                $InfoParams["Area"] = $Item.Area
                $InfoParams["Name"] = $Item.Name
                $InfoParams["RemediationPolicyName"] = $Item.RemediationPolicyName
                $InfoParams["PassText"] = $Item.PassText
                $InfoParams["FailRecommendation"] = $Item.FailRecommendation
                $InfoParams["Importance"] = $Item.Importance
                $InfoParams["SIT"] = $ListOfSIT
                $InfoParams["Links"] = $LinksInfo
                $Check = New-Object -TypeName "DLP" -ArgumentList $InfoParams
                # Set the CAMPParams
                $Check.CAMPParams = $CAMPParams
                $Check.LogFile = $LogFile
    
                $Checks += $Check
            }
    
        }
    }


    # Creating Non-DLP check objects for each improvement actions.
    # The original CAMP scheme inferred a "solution code" from the filename: it stripped the
    # last 3 chars (the "101"/"102" suffix) and matched the leading prefix against GetRequiredSolution.
    # New blueprint-aligned checks (AI-*, COP-*, DSPM-*, FP-*) don't map to any of the 8 legacy
    # solution codes, so we explicitly opt them into the load regardless of the -Solution filter
    # (they're still subject to the -Blueprint filter at run time). Anything else still respects
    # the existing solution-prefix matching for full backwards compatibility.
    $BlueprintOnlyPrefixes = @("AI", "COP", "DSPM", "FP")
    ForEach ($CheckFile in $CheckFiles) {
        if ($CheckFile.BaseName -match '^check-(.*)$' -and ($matches[1] -notlike "DLP")) {
            $solutioname = $matches[1]
            $length = $solutioname.length
            $solutioname = $solutioname.substring(0, $length - 3)

            $IsBlueprintOnly = $BlueprintOnlyPrefixes -icontains $solutioname

            if ($IsBlueprintOnly -or
                (($null -ne $($Collection["GetRequiredSolution"])) -and ($($Collection["GetRequiredSolution"]) -icontains "$solutioname"))) {
                Write-Verbose "Importing $($matches[1])"
                . $CheckFile.FullName
                $Check = New-Object -TypeName $matches[1]
                # Set the CAMPParams
                $Check.CAMPParams = $CAMPParams
                $Check.LogFile = $LogFile
                $Checks += $Check
            }
        
        }
    }

    ForEach ($CheckFile in $CheckFiles) {
        if ($CheckFile.BaseName -match '^check-(.*)$' -and ($matches[1] -like "ComplianceManager")) {
            #write-host "abc"
            Write-Verbose "Importing $($matches[1])"
            . $CheckFile.FullName
            $Check = New-Object -TypeName $matches[1]
            # Set the CAMPParams
            $Check.CAMPParams = $CAMPParams
            $Check.LogFile = $LogFile
            $Checks += $Check
        
        
        }
    }
    $Checks = $Checks | Sort-Object -Property @{ expression = 'ParentArea' ; descending = $true }, @{expression = 'Area' ; descending = $false }

    # Auto-mark any check that has no Blueprint as Foundational so the -Blueprint filter
    # keeps surfacing legacy baseline-hygiene findings (Audit, eDiscovery, basic IRM, etc.)
    # alongside the blueprint-specific findings.
    foreach ($Check in $Checks) {
        if ($Check.Blueprint -eq [CAMPBlueprint]::None -and -not $Check.Foundational) {
            $Check.Foundational = $true
        }
    }

    Return $Checks
}

Function Get-CAMPRemediationAction {
    Param
    (
        $VersionCheck
    )

    $RemediationActions = @()
    # Load individual check definitions
    $RemediationActionOutputFiles = Get-ChildItem "$PSScriptRoot\Remediation"

    ForEach ($RemediationActionOutputFile in $RemediationActionOutputFiles) {
        if ($RemediationActionOutputFile.BaseName -match '^remediation(.*)$') {
            Write-Verbose "Importing $($matches[1])"
            . $RemediationActionOutputFile.FullName
            $RemediationAction = New-Object -TypeName $matches[1]

            # For default output directory
            $RemediationAction.DefaultOutputDirectory = Get-CAMPDirectory

            # Provide versioncheck
            $RemediationAction.VersionCheck = $VersionCheck

            $RemediationActions += $RemediationAction
        }

    }

    Return $RemediationActions
}
Function Get-CAMPOutputs {
    Param
    (
        $VersionCheck,
        $Modules,
        $Options
    )

    $Outputs = @()

    # Load individual check definitions
    $OutputFiles = Get-ChildItem "$PSScriptRoot\Outputs"

    # Warn if the caller asked for an output format that no module under Outputs/ provides yet.
    # The original CAMP would silently no-op; that's confusing for users opting into the new
    # -OutputFormat CSV / Markdown paths before those modules ship.
    $AvailableModuleNames = @()
    ForEach ($OutputFile in $OutputFiles) {
        if ($OutputFile.BaseName -match '^output-(.*)$') {
            $AvailableModuleNames += $matches[1]
        }
    }
    if ($null -ne $Modules) {
        $MissingModules = @($Modules | Where-Object { $AvailableModuleNames -inotcontains $_ })
        foreach ($missing in $MissingModules) {
            Write-Host "$(Get-Date) WARNING: Requested output format '$missing' has no Outputs\output-$missing.ps1 module installed. Skipping." -ForegroundColor:Yellow
        }
    }

    ForEach ($OutputFile in $OutputFiles) {
        if ($OutputFile.BaseName -match '^output-(.*)$') {
            # Determine if this type should be loaded (case-insensitive match against requested formats)
            If (($Modules | ForEach-Object { $_.ToLower() }) -contains $matches[1].ToLower()) {
                Write-Verbose "Importing $($matches[1])"
                . $OutputFile.FullName
                $Output = New-Object -TypeName $matches[1]

                # Load any of the options in to the module
                If ($Options) {

                    If ($Options[$matches[1]].Keys) {
                        ForEach ($Opt in $Options[$matches[1]].Keys) {
                            # Ensure this property exists before we try set it and get a null ref error
                            $ModProperties = $($Output | Get-Member | Where-Object { $_.MemberType -eq "Property" }).Name
    
                            If ($ModProperties -contains $Opt) {
                                $Output.$Opt = $Options[$matches[1]][$Opt]
                            }
                            else {
                                Throw("There is no option $($Opt) on output module $($matches[1])")
                            }
                        }
                    }
                }

                # For default output directory
                $Output.DefaultOutputDirectory = Get-CAMPDirectory

                # Provide versioncheck
                $Output.VersionCheck = $VersionCheck
                
                $Outputs += $Output
            }

        }
    }

    Return $Outputs
}

# Get DLP settings
Function Get-DataLossPreventionSettings {
    Param(
        $Collection,
        [string]$LogFile
    )
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        $Collection["GetDlpComplianceRule"] = Get-DlpComplianceRule -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage 
        $Collection["GetDLPCustomSIT"] = Get-DlpSensitiveInformationType -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage | Where-Object { $_.Publisher -ne "Microsoft Corporation" } 
        $Collection["GetDlpCompliancePolicy"] = Get-DlpCompliancePolicy -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage 
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {        
        $Collection["GetDlpComplianceRule"] = "Error"
        $Collection["GetDLPCustomSIT"] = "Error"
        $Collection["GetDlpCompliancePolicy"] = "Error"
        Write-Host "Error:$(Get-Date) There was an issue in fetching Data Loss Prevention information. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
    }

    Return $Collection
}

# Get Information Protection settings
Function Get-InformationProtectionSettings {
    Param(
        $Collection,
        [string]$LogFile
    )
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        $Collection["GetLabel"] = Get-Label -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage 
        try {
            $Collection["GetLabelPolicy"] = Get-LabelPolicy -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage 
        }
        catch {
            $Collection["GetLabelPolicy"] = "Error"
        }
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {
        $Collection["GetLabel"] = "Error"
        $Collection["GetLabelPolicy"] = "Error"
        Write-Host "Error:$(Get-Date) There was an issue in fetching Information Protection information. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
         
    }
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        $Collection["GetAutoSensitivityLabelPolicy"] = Get-AutoSensitivityLabelPolicy -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {
        $Collection["GetAutoSensitivityLabelPolicy"] = "Error"
        Write-Host "Error:$(Get-Date) There was an issue in fetching AutoSensitivity Label Policy information. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        $Collection["GetIRMConfiguration"] = Get-EXOPIRMConfiguration -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {
        $Collection["GetIRMConfiguration"] = "Error"
        Write-Host "Error:$(Get-Date) There was an issue in fetching IRM Configuration information. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
    
    }
    Return $Collection
}

# Get Communication Compliance settings
Function Get-CommunicationComplianceSettings {
    Param(
        $Collection,
        [string]$LogFile
    )
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        $Collection["GetSupervisoryReviewPolicyV2"] = Get-SupervisoryReviewPolicyV2 -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        try {
            $Collection["GetSupervisoryReviewOverallProgressReport"] = Get-SupervisoryReviewOverallProgressReport -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        
        }
        catch {
            $Collection["GetSupervisoryReviewOverallProgressReport"] = "Error"
        }
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {
        $Collection["GetSupervisoryReviewPolicyV2"] = "Error"
        $Collection["GetSupervisoryReviewOverallProgressReport"] = "Error"
        Write-Host "Error:$(Get-Date) There was an issue in fetching Communication Compliance information. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
         
    }
    Return $Collection
}

# Get Data Lifecycle Management settings
Function Get-InformationGovernanceSettings {
    Param(
        $Collection,
        [string]$LogFile
    )
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        $Collection["GetRetentionCompliancePolicy"] = Get-RetentionCompliancePolicy -DistributionDetail -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        $Collection["GetRetentionComplianceRule"] = Get-RetentionComplianceRule -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        $Collection["GetComplianceTag"] = Get-ComplianceTag -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {
        $Collection["GetRetentionCompliancePolicy"] = "Error"
        $Collection["GetRetentionComplianceRule"] = "Error"
        $Collection["GetComplianceTag"] = "Error"
        Write-Host "Error:$(Get-Date) There was an issue in fetching Retention Compliance information. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
         
    }
    Return $Collection
}

# Get Audit settings
Function Get-AuditSettings {
    Param(
        $Collection,
        [string]$LogFile
    )
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        $Collection["GetAdminAuditLogConfig"] = Get-EXOPAdminAuditLogConfig -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {
        $Collection["GetAdminAuditLogConfig"] = "Error"
        Write-Host "Error:$(Get-Date) There was an issue in fetching Audit Configuration information. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue      
    }
    Return $Collection
}
#get eDiscovery
Function Get-eDiscoverySettings {
    Param(
        $Collection,
        [string]$LogFile
    )
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        $Collection["GetComplianceCase"] = Get-ComplianceCase -CaseType AdvancedEdiscovery -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        $Collection["GetComplianceCaseCore"] = Get-ComplianceCase  -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {
        $Collection["GetComplianceCase"] = "Error"
        $Collection["GetComplianceCaseCore"] = "Error"
        Write-Host "Error:$(Get-Date) There was an issue in fetching Audit Configuration information. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue      
    }
    Return $Collection
}

#Get Insider Risk Management Settings
Function Get-InsiderRiskManagementSettings {
    Param(
        $Collection,
        [string]$LogFile
    )
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        $Collection["GetInsiderRiskPolicy"] = Get-InsiderRiskPolicy -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {
        $Collection["GetInsiderRiskPolicy"] = "Error"
        Write-Host "Error:$(Get-Date) There was an issue in fetching Insider Risk Management information. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue      
    }
    Return $Collection
}

# Get Accepted Domains
Function Get-AcceptedDomains {
    Param(
        $Collection,
        [string]$LogFile
    )
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        $Collection["AcceptedDomains"] = Get-EXOPAcceptedDomain -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {
        $Collection["AcceptedDomains"] = "Error"
        Write-Host "Error:$(Get-Date) There was an issue in fetching tenant name information. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue      
    }
    Return $Collection
}

#Get Alert Policies
Function Get-AlertPolicies {
    Param(
        $Collection,
        [string]$LogFile
    )
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        $Collection["GetProtectionAlert"] = Get-ProtectionAlert | Where-Object { $_.Severity -eq "High" } -ErrorAction:SilentlyContinue -WarningVariable +WarnMessage
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    catch {
        $Collection["GetProtectionAlert"] = "Error"
        Write-Host "Error:$(Get-Date) There was an issue in fetching Alert Policies Configuration information. Please try running the tool again after some time." -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue      
    }
    Return $Collection
}

# Get Microsoft Graph backed data used by Shadow AI, Secure Copilot Agents, and DSPM checks.
# Every key falls back to "Error" (or remains $null) when the Graph SDK is missing or the
# user declined consent, allowing the checks themselves to degrade gracefully.
Function Get-CAMPGraphCollection {
    Param(
        $Collection,
        [string]$LogFile
    )

    # Pre-populate every Graph key so per-check $Config[...] lookups never explode.
    foreach ($key in @("GetGraphContext", "GetSpoSites", "GetContainerLabels", "GetEntraApps",
                       "GetEntraDirectoryRoles", "GetEntraConditionalAccessPolicies",
                       "GetDspmAiSignals", "GetSpoTenantSettings")) {
        if (-not $Collection.ContainsKey($key)) {
            $Collection[$key] = "Error"
        }
    }

    if (-not $global:GraphConnectionEstablished) {
        Write-Log -IsInfo -InfoMessage "Skipping Graph-backed data collection (Graph not connected)" -LogFile $LogFile -ErrorAction:SilentlyContinue
        return $Collection
    }

    try {
        $Collection["GetGraphContext"] = Get-MgContext -ErrorAction:SilentlyContinue
    } catch { $Collection["GetGraphContext"] = "Error" }

    try {
        # First 200 SPO sites with sensitivity labels — enough for a representative scan
        # without blowing up tenants with thousands of sites.
        $Collection["GetSpoSites"] = Get-MgSite -Search "*" -Top 200 -ErrorAction:SilentlyContinue
    } catch {
        $Collection["GetSpoSites"] = "Error"
        Write-Log -IsInfo -InfoMessage "Graph: Get-MgSite unavailable (likely missing Sites.Read.All consent)" -LogFile $LogFile -ErrorAction:SilentlyContinue
    }

    try {
        $Collection["GetEntraApps"] = Get-MgApplication -Top 999 -ErrorAction:SilentlyContinue
    } catch {
        $Collection["GetEntraApps"] = "Error"
        Write-Log -IsInfo -InfoMessage "Graph: Get-MgApplication unavailable (likely missing Application.Read.All consent)" -LogFile $LogFile -ErrorAction:SilentlyContinue
    }

    try {
        $Collection["GetEntraDirectoryRoles"] = Get-MgDirectoryRole -ErrorAction:SilentlyContinue
    } catch { $Collection["GetEntraDirectoryRoles"] = "Error" }

    try {
        $Collection["GetEntraConditionalAccessPolicies"] = Get-MgIdentityConditionalAccessPolicy -ErrorAction:SilentlyContinue
    } catch { $Collection["GetEntraConditionalAccessPolicies"] = "Error" }

    Return $Collection
}


#Get Organisation Region
Function Get-OrganisationRegion {
    Param(
        $Collection,
        [string]$LogFile,
        [System.Collections.ArrayList] $GeoList
    )
    
    
    try {
        [System.Collections.ArrayList]$WarnMessage = @()
        [System.Collections.ArrayList] $RegionNamesList = @()
        $Collection["GetOrganisationConfig"] = Get-EXOPOrganizationConfig -ErrorAction:SilentlyContinue
            
        if ($($GeoList.Count) -gt 0) {
            $Collection["GetOrganisationRegion"] = $GeoList
            $Collection["GetOrganisationRegion"].add("INTL") | out-null
        }
        else {
            $RegionsList = $Collection["GetOrganisationConfig"].AllowedMailboxRegions 
            foreach ($region in $RegionsList) {
                $RegionName = $($region.Split("="))[0]
                $RegionName = $RegionName.ToUpper()
                $RegionNamesList.add($RegionName) | Out-Null
            }
            $Collection["GetOrganisationRegion"] = $RegionNamesList
            $Collection["GetOrganisationRegion"].add("INTL") | out-null
        }
        Write-Log -IsWarn -WarnMessage $WarnMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        
            
    }
    catch {
        $Collection["GetOrganisationConfig"] = "Error"
        if ($($GeoList.Count) -gt 0) {
            $Collection["GetOrganisationRegion"] = $GeoList
            $Collection["GetOrganisationRegion"].add("INTL") | out-null
        }
        else {
            $Collection["GetOrganisationRegion"] = "Error"
            Write-Host "Warning:$(Get-Date) There was an issue in fetching your tenant's geolocation. The generated report will have recommendations for all geos across the globe." -ForegroundColor:Yellow
            
        }
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue      
    }
    
        
    Return $Collection
}

#Get Solution Config
Function Get-PersonalizedSolution {
    Param(
        $Collection,
        [string]$LogFile,
        [System.Collections.ArrayList] $SolutionList
    )
       
    [System.Collections.ArrayList] $SolutionsList = @()
    if ($($SolutionList.Count) -gt 0) {
        $Collection["GetRequiredSolution"] = $SolutionList
        $Collection["GetRequiredSolution"].add("INTL") | out-null
    }
    else {
        $SolutionTable = Get-SolutionTable
        [int] $count = 1
        while ($count -le 8) {
            $SolutionList.add($($($SolutionTable[$count]).Code)) | out-null
            $count = $count + 1
        }

        $Collection["GetRequiredSolution"] = $SolutionsList
        $Collection["GetRequiredSolution"].add("INTL") | out-null
    }
    Return $Collection
}
               
# Get user configurations
Function Get-CAMPCollection {
    Param
    (
        [String]$LogFile,
        [System.Collections.ArrayList] $GeoList,
        [System.Collections.ArrayList] $SolutionList
    )
    $Collection = @{}

    [CAMPService]$Collection["Services"] = [CAMPService]::DLP
    try {
        Write-EXOPAdminAuditLog -Comment "Configuration Analyzer for Microsoft Purview Started at- $(Get-Date)"

    }
    catch {
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    if ($SolutionList -icontains "DLP") {
        $InfoMessage = "Getting DLP Settings"
        Write-Host "$(Get-Date) $InfoMessage"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        $Collection = Get-DataLossPreventionSettings -Collection $Collection -LogFile $LogFile
    }

    # IP settings are needed for both IP and DLP solutions (DLP checks may reference sensitivity labels)
    if (($SolutionList -icontains "IP") -or ($SolutionList -icontains "DLP")) {
        $InfoMessage = "Getting Information Protection Settings"
        Write-Host "$(Get-Date) $InfoMessage"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        $Collection = Get-InformationProtectionSettings -Collection $Collection -LogFile $LogFile
    }

    if ($SolutionList -icontains "CC") {
        $InfoMessage = "Getting Communication Compliance Settings"
        Write-Host "$(Get-Date) $InfoMessage"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        $Collection = Get-CommunicationComplianceSettings -Collection $Collection -LogFile $LogFile
    }
    
    if (($SolutionList -icontains "IG") -or ($SolutionList -icontains "RM")) {
        $InfoMessage = "Getting Data Lifecycle Management Settings"
        Write-Host "$(Get-Date) $InfoMessage"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        $Collection = Get-InformationGovernanceSettings -Collection $Collection -LogFile $LogFile
    }
    
    if ($SolutionList -icontains "Audit" ) {
        $InfoMessage = "Getting Audit Settings"
        Write-Host "$(Get-Date) $InfoMessage"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        $Collection = Get-AuditSettings -Collection $Collection -LogFile $LogFile
    }

    if ($SolutionList -icontains "eDiscovery") {
        $InfoMessage = "Getting eDiscovery Settings"
        Write-Host "$(Get-Date) $InfoMessage"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        $Collection = Get-eDiscoverySettings -Collection $Collection -LogFile $LogFile
    }

    if ($SolutionList -icontains "IRM") {
        $InfoMessage = "Getting Insider Risk Management Settings"
        Write-Host "$(Get-Date) $InfoMessage"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        $Collection = Get-InsiderRiskManagementSettings -Collection $Collection -LogFile $LogFile
    }

    $InfoMessage = "Getting Accepted Domains"
    Write-Host "$(Get-Date) $InfoMessage"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    $Collection = Get-AcceptedDomains -Collection $Collection -LogFile $LogFile
    
    $InfoMessage = "Getting Alert Policies Settings"
    Write-Host "$(Get-Date) $InfoMessage"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    $Collection = Get-AlertPolicies -Collection $Collection -LogFile $LogFile

    $InfoMessage = "Getting Microsoft Graph backed signals (best effort)"
    Write-Host "$(Get-Date) $InfoMessage"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    $Collection = Get-CAMPGraphCollection -Collection $Collection -LogFile $LogFile

    $InfoMessage = "Getting Organization's region information"
    Write-Host "$(Get-Date) $InfoMessage"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    $Collection = Get-OrganisationRegion -GeoList $GeoList -Collection $Collection -LogFile $LogFile

    $InfoMessage = "Getting Organization's solution preference information"
    Write-Host "$(Get-Date) $InfoMessage"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    $Collection = Get-PersonalizedSolution -SolutionList $SolutionList -Collection $Collection -LogFile $LogFile

    Return $Collection
}


Function Get-CAMPReport {
    <#
    
        .SYNOPSIS
            The Configuration Analyzer for Microsoft Purview (CAMP)

        .DESCRIPTION
            Configuration Analyzer for Microsoft Purview (CAMP)

            The Get-CAMPReport command generates a HTML report highlighting known issues in your compliance configurations in achieving data protection guidelines and recommends best practices to follow.

            Output report uses open source components for HTML formatting:
            - Bootstrap - MIT License https://getbootstrap.com/docs/4.0/about/license/
            - Fontawesome - CC BY 4.0 License - https://fontawesome.com/license/free

       
        .PARAMETER NoVersionCheck
            Prevents Configuration Analyzer for Microsoft Purview from determining if it's running the latest version. It's always very important to be running the latest
            version of Configuration Analyzer for Microsoft Purview. We will change guidelines as the product and the recommended practices article changes. Not running the
            latest version might provide recommendations that are no longer valid.
        
        .PARAMETER TurnOffDataCollection 
            Disables data collection. It can be used by users who wish to turn off data collection by Microsoft. Turning it off 
            will delete the UserConsent file present in the output Report folder and ultimately will not consider acceptance in 
            further running instance of the tool.

		.PARAMETER Geo 
            This will generate a report based on the geolocations entered by you.You need to input appropriate numbers from the following list corresponding to the regions. 
			Input	Region
				1	Asia-Pacific
				2	Australia
				3	Canada
				4	Europe (excl. France) / Middle East / Africa
				5	France
				6	India
				7	Japan
				8	Korea
				9	North America (excl. Canada)
				10	South America
				11	South Africa
				12	Switzerland
				13	United Arab Emirates
				14	United Kingdom


		.PARAMETER Solution
            This will generate a report only for the solutions entered by you. You need to input appropriate numbers from the following list corresponding to the solution.
			Input	Solution
				1	Data Loss Prevention
				2	Information Protection
				3	Data Lifecycle Management
				4	Records Management
				5	Communication Compliance
				6	Insider Risk Management
				7	Audit
				8	eDiscovery

        .PARAMETER  ExchangeEnvironmentName
        This will generate CAMP report for Security & Compliance PowerShell in a Microsoft 365 DoD organization or Microsoft GCC High organization
         O365USGovDoD
           This will generate CAMP report for Security & Compliance PowerShell in a Microsoft 365 DoD organization.
         O365USGovGCCHigh
           This will generate CAMP report for Security & Compliance PowerShell in a Microsoft GCC High organization.

        .PARAMETER Blueprint
            Filter the report to one or more Microsoft Purview Deployment Models ("blueprints").
            Accepts numbers 1..6:
                1   Secure by Default
                2   Lightweight guide to mitigate data leakage
                3   Prevent data leak to shadow AI
                4   Secure & govern Microsoft 365 Copilot agents
                5   Deploy and use Data Security Posture Management (DSPM)
                6   Reduce false positives with SITs & advanced classifiers
            Omit to include all blueprints (default, fully backward compatible).

        .PARAMETER OutputFormat
            One or more output formats to generate. Defaults to HTML.
            Valid values: HTML, JSON, CSV, Markdown.

        .PARAMETER Collection
            Internal only.
        .EXAMPLE 
            Get-CAMPReport
			This will generate a customized report based on the geolocation of your tenant. If an error occurs while fetching your tenant's geolocation, you will get a report covering all supported geolocations.
            .EXAMPLE
            Get-CAMPReport -Geo @(1,7)
			This will generate a customized report based on the geolocations entered by you. 
		.EXAMPLE
			Get-CAMPReport -Solution @(1,7)
			This will generate a customized report for the solutions entered by you. 
		.EXAMPLE
		    Get-CAMPReport -Solution @(1,7) -Geo @(9)
			This will generate a report only on for the solutions entered by you and based on the regions you have selected. 
        .EXAMPLE
            Get-CAMPReport -Blueprint @(1,2)
            This will generate a report covering only the Secure by Default and Lightweight DLP blueprints.
        .EXAMPLE
            Get-CAMPReport -OutputFormat HTML,JSON,CSV,Markdown
            This will generate the report in every supported output format.

    
#>
    Param(
        [CmdletBinding()]
        [Switch]$NoVersionCheck,    
        [Switch]$TurnOffDataCollection,
        [System.Collections.ArrayList] $Geo = @(),
        [System.Collections.ArrayList] $Solution = @(),
        # Filter the report to a specific Microsoft Purview Deployment Model. Accepts numbers 1..6:
        # 1 = Secure by Default, 2 = Lightweight DLP, 3 = Shadow AI, 4 = Copilot Agents,
        # 5 = DSPM, 6 = Reduce False Positives. Omit (default) to include all blueprints.
        [System.Collections.ArrayList] $Blueprint = @(),
        # One or more output formats. Defaults to HTML for backward compatibility.
        [ValidateSet('HTML','JSON','CSV','Markdown')]
        [string[]] $OutputFormat = @('HTML'),
        [string][validateset('O365Default', 'O365USGovDoD', 'O365USGovGCCHigh')] $ExchangeEnvironmentName = 'O365Default',
        $Collection
    )
    $OutputDirectoryName = Get-CAMPDirectory
    if(($TurnOffDataCollection -eq $true) -and ($(Test-Path -Path (Join-Path $OutputDirectoryName "UserConsent.txt") -PathType Leaf) -eq $true))
    {
        Remove-Item (Join-Path $OutputDirectoryName "UserConsent.txt")
    }
    if ((Test-Path -Path (Join-Path $OutputDirectoryName "UserConsent.txt") -PathType Leaf) -and ($(Get-Content (Join-Path $OutputDirectoryName "UserConsent.txt")) -ieq "Yes")) {
        $global:TelemetryEnabled = $true
    }
    else {
        $cntOfIterations = 1
        Write-Host "Data Collection: The software may collect information about you and your use of the software and send it to Microsoft. Microsoft may use this information to provide services and improve our products and services. You may turn off the telemetry as described in the repository. There are also some features in the software that may enable you and Microsoft to collect data from users of your applications. If you use these features, you must comply with applicable law, including providing appropriate notices to users of your applications together with a copy of Microsoft's privacy statement. Our privacy statement is located at https://go.microsoft.com/fwlink/?LinkID=824704. You can learn more about data collection and use in the help documentation and our privacy statement. Your use of the software operates as your consent to these practices." -ForegroundColor Yellow
        while ($cntOfIterations -lt 3) {
            Write-Host "Do you accept(Y/N):" -NoNewline -ForegroundColor Yellow
            $telemetryConsent = Read-Host -ErrorAction:SilentlyContinue
            $telemetryConsent = $telemetryConsent.Trim()
            if (($telemetryConsent -ieq "y") -or ($telemetryConsent -ieq "yes")) {
                if (Test-Path -Path (Join-Path $OutputDirectoryName "UserConsent.txt") -PathType Leaf) {
                    Remove-Item (Join-Path $OutputDirectoryName "UserConsent.txt")
                }
                New-Item (Join-Path $OutputDirectoryName "UserConsent.txt") | Out-Null
                Set-Content (Join-Path $OutputDirectoryName "UserConsent.txt") 'Yes' 
                $global:TelemetryEnabled = $true
                break
            }
            elseif (($telemetryConsent -ieq "n") -or ($telemetryConsent -ieq "no")) {
                break
            }
            Write-Host "Invalid input! Please try again." -ForegroundColor Red
            $cntOfIterations += 1
        }
        if ($cntOfIterations -eq 3) {
            return
        }
    }
    
    $global:EnvironmentName = $ExchangeEnvironmentName
    $LogDirectory = Join-Path $OutputDirectoryName "Logs"
    $FileName = "CAMP-$(Get-Date -Format 'yyyyMMddHHmmss').log"
    $LogFile = Join-Path $LogDirectory $FileName
    #Creating the logfiles folder if not present
    if ($(Test-Path -Path $LogDirectory) -eq $false) {
        New-Item -Path $LogDirectory -ItemType Directory -ErrorAction:SilentlyContinue | Out-Null
        #Creating the logfile
        New-Item -Path $LogFile -ItemType File -ErrorAction:SilentlyContinue | Out-Null
    }
    else {
        New-Item -Path $LogFile -ItemType File -ErrorAction:SilentlyContinue | Out-Null
    }
    #Check if log file exists
    if ($(Test-Path -Path $LogFile) -eq $False) {
        Write-Host "$(Get-Date) Log file cannot be created." -ForegroundColor:Red
    }
    Write-Log -MachineInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
    if (($(Get-GeoAcceptance -Geo $Geo) -eq $false ) -and ($(Get-SolutionAcceptance -Solution $Solution) -eq $false)) {     
        Show-GeoOptions
        Show-SolutionOptions 
        return
    }
    #Get actual region names
    
    [System.Collections.ArrayList] $GeoList = @()
    if (($(Get-GeoAcceptance -Geo $Geo) -eq $false )) {
               
        Show-GeoOptions 
        return
    }
    else {
        #Number To Region Mapping 
        $NumberToRegionMapping = Get-NumberRegionMappingHashTable

        #Mapping numbers to the actual region
        foreach ($RegionNumber in $Geo) {
            [string] $RegionName = $NumberToRegionMapping[$RegionNumber].Code
            $GeoList.add($RegionName) | out-null  
        }
    }

    #Get actual region names

    [System.Collections.ArrayList] $SolutionList = @()
    if ($(Get-SolutionAcceptance -Solution $Solution) -eq $false) {
                  
        Show-SolutionOptions 
        return
    }
    else {
        $ShowSolutionList = ""
        $SolutionTable = Get-SolutionTable
        if ($Solution.count -gt 0) {
            foreach ($count in $Solution) {
                [string] $Name = "$($($SolutionTable[$count]).Code)"
                #write-host "$Name"
                $SolutionList.add($Name) | out-null
                $ShowSolutionList += "$($($SolutionTable[$count]).FullName), "
            }
            $ShowSolutionList = $ShowSolutionList.TrimEnd(", ")
        }
        else {
            
            [int] $count = 1
            while ($count -le 8) {
                $SolutionList.add($($($SolutionTable[$count]).Code)) | out-null
                $count = $count + 1
            }
            $ShowSolutionList += "All Solutions"   
        }
    }
    # Easy to use for quick Configuration Analyzer for Microsoft Purview report to HTML
    If ($NoVersionCheck) {
        $PerformVersionCheck = $False
    }
    Else {
        $PerformVersionCheck = $True
    }
    

    try {
        $Result = Invoke-CAMP -PerformVersionCheck $PerformVersionCheck -Collection $Collection -Output $OutputFormat -BlueprintFilter $Blueprint -GeoList $GeoList -SolutionList $SolutionList -LogFile $LogFile -ExchangeEnvironmentName $ExchangeEnvironmentName-ErrorAction:SilentlyContinue
        $InfoMessage = "Complete! Output is in $($Result.Result)"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        Write-Host "$(Get-Date) $InfoMessage"

        try {
            Write-EXOPAdminAuditLog -Comment "Configuration Analyzer for Microsoft Purview Completed at - $(Get-Date)"
    
        }
        catch {
            $ErrorMessage = $_.ToString()
            $StackTraceInfo = $_.ScriptStackTrace
            Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
        }
    }
    catch {
        Write-Host "Error:$(Get-Date) There was an issue in running the tool. Please try running the tool again after some time." -ForegroundColor:Red
        Write-Host "Please refer to the documentation and FAQs available at https://github.com/OfficeDev/CAMP/blob/main/README.md to get guidance for resolving common issues. If the issue persists, please write to us at CAMPhelp@microsoft.com along with log file at $LogFile" -ForegroundColor:Red
        $ErrorMessage = $_.ToString()
        $StackTraceInfo = $_.ScriptStackTrace
        Write-Log -IsError -ErrorMessage $ErrorMessage -StackTraceInfo $StackTraceInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
    }
    finally {
        Write-Log -StopInfo -LogFile $LogFile -ErrorAction:SilentlyContinue
        
        $InfoMessage = "Get the log at $LogFile"  
        Write-Host "$(Get-Date) $InfoMessage" 

        try {
            if($($global:ConnectionEstablished) -eq $true)
            {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction:SilentlyContinue  
            }      
        }
        catch {
            
        }

        try {
            if ($($global:GraphConnectionEstablished) -eq $true) {
                Disconnect-MgGraph -ErrorAction:SilentlyContinue | Out-Null
                $global:GraphConnectionEstablished = $false
            }
        }
        catch {

        }
    }
   
}


Function Invoke-CAMP {
    Param(
        [CmdletBinding()]
        [Boolean]$PerformVersionCheck = $True,     
        $Output,
        $OutputOptions,
        $Collection,
        [System.Collections.ArrayList] $GeoList = @(),
        [System.Collections.ArrayList] $SolutionList = @(),
        [System.Collections.ArrayList] $BlueprintFilter = @(),
        [String]$LogFile
    )
    $InfoMessage = "Configuration Analyzer for Microsoft Purview Started"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue

    # Version check
    If ($PerformVersionCheck) {
        $InfoMessage = "Version Check Started"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        $VersionCheck = Invoke-CAMPVersionCheck 
        $InfoMessage = "Version Check Completed"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }

  
    $InfoMessage = "Establishing Connections"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    Invoke-CAMPConnections -LogFile $LogFile -ExchangeEnvironmentName $ExchangeEnvironmentName
    Invoke-CAMPGraphConnections -LogFile $LogFile
    $InfoMessage = "Connections Established"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
  


    # Get the collection in to memory. For testing purposes, we support passing the collection as an object
    If ($Null -eq $Collection) {
        $InfoMessage = "Fetching User Configurations"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        $Collection = Get-CAMPCollection -GeoList $GeoList -SolutionList $SolutionList -LogFile $LogFile
        $InfoMessage = "User Configurations Fetched"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    }

    # Get the output modules
    $InfoMessage = "Creating Output Objects"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    $OutputModules = Get-CAMPOutputs -VersionCheck $VersionCheck -Modules $Output -Options $OutputOptions
    $InfoMessage = "Output Objects Created"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    
    # Get the object of Configuration Analyzer for Microsoft Purview checks
    $InfoMessage = "Creating Check Objects"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    $Checks = Get-CAMPCheckDefs -CAMPParams $CAMPParams -Collection $Collection -LogFile $LogFile
    $InfoMessage = "Check Objects Created"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue

    
    
    # Apply blueprint filter (additive to Geo / Solution filters).
    # BlueprintFilter is a list of 1..6 integers matching the CAMPBlueprint flag positions:
    # 1=SecureByDefault, 2=LightweightDLP, 3=ShadowAI, 4=CopilotAgents, 5=DSPM, 6=ReduceFalsePositives.
    # An empty list (default) means "include every check regardless of blueprint".
    # Checks marked $Foundational=$true (legacy CAMP checks) are always included so a
    # `-Blueprint 3` (Shadow AI only) report still surfaces baseline tenant hygiene findings.
    [CAMPBlueprint] $BlueprintMask = [CAMPBlueprint]::None
    if ($null -ne $BlueprintFilter -and $BlueprintFilter.Count -gt 0) {
        $BlueprintMaskMap = @{
            1 = [CAMPBlueprint]::SecureByDefault
            2 = [CAMPBlueprint]::LightweightDLP
            3 = [CAMPBlueprint]::ShadowAI
            4 = [CAMPBlueprint]::CopilotAgents
            5 = [CAMPBlueprint]::DSPM
            6 = [CAMPBlueprint]::ReduceFalsePositives
        }
        foreach ($bp in $BlueprintFilter) {
            if ($BlueprintMaskMap.ContainsKey([int]$bp)) {
                $BlueprintMask = $BlueprintMask -bor $BlueprintMaskMap[[int]$bp]
            }
        }
    }

    # Perform checks inside classes/modules
    ForEach ($Check in ($Checks | Sort-Object Area)) {

        # Skip checks that don't match the blueprint filter (when one was supplied).
        # Foundational checks (the legacy 19) are always kept for context.
        if ($BlueprintMask -ne [CAMPBlueprint]::None) {
            if (-not $Check.Foundational -and (($Check.Blueprint -band $BlueprintMask) -eq 0)) {
                continue
            }
        }

        # Run DLP checks by default
        if ($check.Services -band [CAMPService]::DLP) {
            $Check.Run($Collection)
        }

       
    }

    # Get the Remedition Steps
    $InfoMessage = "Creating Remediation Objects"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    $RemediationActionModules = Get-CAMPRemediationAction -VersionCheck $VersionCheck  
    $InfoMessage = "Remediation Objects Created"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    ForEach ($a in $RemediationActionModules) {

        $a.Run($Checks, $Collection)
       
        
    }

    $TenantGeoLocations = $Collection["GetOrganisationRegion"] | Where-Object { $_ -ne "INTL" }
    if ($TenantGeoLocations -ne "Error") {
        $RegionString = ""
        $NumberToRegionMapping = Get-NumberRegionMappingHashTable
        foreach ($Region in $TenantGeoLocations) {
            foreach ($Numbers in $($NumberToRegionMapping.Keys)) {
                if ($($NumberToRegionMapping[$Numbers].Code) -eq $Region) {
                    if ($RegionString -eq "") {
                        $RegionString += "$($NumberToRegionMapping[$Numbers].Description)" 
                    }
                    else {
                        $RegionString += ", $($NumberToRegionMapping[$Numbers].Description)" 
                    }
                }
            }

        }
    }
    else {
        $RegionString = ""
        $RegionString += "All Geolocations"
    }
    $InfoMessage = "The following report is generated for following solutions:$ShowSolutionList" 
    Write-Host "$(Get-Date) $InfoMessage" -ForegroundColor Yellow
    $InfoMessage = "The following report is for following geolocations:$RegionString"  
    Write-Host "$(Get-Date) $InfoMessage" -ForegroundColor Yellow
    $OutputResults = @()
    $InfoMessage = "Generating Output"
    Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
    Write-Host "$(Get-Date) $InfoMessage" -ForegroundColor Green
    # Perform required outputs
    ForEach ($o in $OutputModules) {

        $o.Run($Checks, $Collection)
        $OutputResults += New-Object -TypeName PSObject -Property @{
            Name      = $o.name
            Completed = $o.completed
            Result    = $o.Result
        }

    }
    
    # If Telemetry is enabled (For Customers), then collect telemetry
    if ($($global:TelemetryEnabled) -eq $true) {
        $InfoMessage = "Collecting Telemetry"
        Write-Log -IsInfo -InfoMessage $InfoMessage -LogFile $LogFile -ErrorAction:SilentlyContinue

        $CAMPVersion = $VersionCheck.Version.ToString()

        # Setting tenant name
        if (($Collection["AcceptedDomains"] -eq "Error") -or ($Collection["AcceptedDomains"] -eq "") -or ($null -eq $Collection["AcceptedDomains"]) ) {
            if($null -ne $global:UserName)
            {
                if($global:UserName.Contains("@"))
                {
                    $DomainName = $global:UserName.Split("@")[1];
                }
                else 
                {
                    $DomainName = "Error"
                } 
            }
            else {
                $DomainName = "Error" 
            }          
        }
        else {
            $DomainName = ($Collection["AcceptedDomains"] | Where-Object { $_.InitialDomain -eq $True }).DomainName
        }

        # Setting organization name
        if ($Collection["GetOrganisationConfig"] -eq "Error") {
            $OrganizationName = "Error"
        }
        else {
            $OrganizationName = $Collection["GetOrganisationConfig"].DisplayName
        }
        
        $SolutionSummaryResult = @{}
        ForEach ($Area in ($Checks | Where-Object { $_.Completed -eq $true } | Group-Object Area)) {
            if($($Area.Name) -eq "Compliance Manager")
            {
                continue
            }
            $Pass = @($Area.Group | Where-Object { $_.Result -eq "Pass" }).Count
            $Fail = @($Area.Group | Where-Object { $_.Result -eq "Fail" }).Count
            $Info = @($Area.Group | Where-Object { $_.Result -eq "Recommendation" }).Count
            $SolutionSummaryResult[$($Area.Name)] = New-Object -TypeName PSObject -Property @{
                Pass = $Pass
                Info = $Info
                Fail = $Fail
            }
        }
        # Set the parameter for the URI
        $Parameters = @{
            CAMPVersion  = $CAMPVersion
            Domain       = $DomainName
            Organization = $OrganizationName
        }
        $AllSolutions = Get-SolutionTable
        foreach ($solution in $($AllSolutions.Values.FullName)) {
            $solutionName = $solution -replace '\s', ''
            if ($SolutionSummaryResult.ContainsKey($solution)) {
                $Parameters.Add($($solutionName + "_Pass"), $SolutionSummaryResult[$solution].Pass)
                $Parameters.Add($($solutionName + "_Info"), $SolutionSummaryResult[$solution].Info)
                $Parameters.Add($($solutionName + "_Fail"), $SolutionSummaryResult[$solution].Fail)           
            }
            else {
                $Parameters.Add($($solutionName + "_Pass"), 0)
                $Parameters.Add($($solutionName + "_Info"), 0)
                $Parameters.Add($($solutionName + "_Fail"), 0)
            }
        }
        $Parameters = $Parameters | ConvertTo-Json

        try
        {
            # URI to trigger the Telemetry Function 
            $URI = "Put Telemetry URL here"

            # Call the URI
            $ResponseMessage = Invoke-WebRequest -Uri $URI -ContentType "application/json" -Method POST -Body $Parameters -ErrorAction:SilentlyContinue                     
            Write-Log -IsInfo -InfoMessage $ResponseMessage -LogFile $LogFile -ErrorAction:SilentlyContinue

        }
        catch
        {
            $ResponseMessage = "Telemetry execution failed!"
            Write-Log -IsInfo -InfoMessage $ResponseMessage -LogFile $LogFile -ErrorAction:SilentlyContinue
        }
    }
    Return $OutputResults

}


function Invoke-CAMPVersionCheck {
    Param
    (
        $Terminate
    )

    Write-Host "$(Get-Date) Performing Configuration Analyzer for Microsoft Purview Version check... "

    # When detected we are running the preview release
    $CAMP = ""
    $CAMPVersion = ""
    $PSGalleryVersionNotFound = $False
    $CAMPVersionNotFound =$False

    try {
        $CAMPVersion = (Get-InstalledModule CAMP -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue | Sort-Object Version -Desc)[0].Version
    }
    catch {  
        $CAMPVersionNotFound = $True
    }

    try
    {
        $PSGalleryVersion = (Find-Module CAMP -Repository PSGallery -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue).Version
    }   
    catch {
        $PSGalleryVersionNotFound = $True
        }

        If ($CAMPVersionNotFound) {
            $Updated = $False
                Throw "CAMP is not installed. Run Install-Module CAMP."           
        }
        elseif ($PSGalleryVersionNotFound) {
                Throw "There was some issue in running the tool. Please try after some time." 
        }
        elseif ($PSGalleryVersion -gt $CAMPVersion) {
        $Updated = $False
        If ($Terminate) {
            Throw "CAMP is out of date. Your version is $CAMPVersion and the published version is $PSGalleryVersion. Run Update-Module CAMP."
        }
        else {
            Write-Host "$(Get-Date) CAMP is out of date. Your version: $($CAMPVersion) published version is $($PSGalleryVersion)"
        }
    }
    else {
        $Updated = $True
    }

    Return New-Object -TypeName PSObject -Property @{
        Updated        = $Updated
        Version        = $CAMPVersion
        GalleryVersion = $PSGalleryVersion
        Preview        = $Preview
    }
}

#Creating log file and directory

#Writing in log file
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Switch]$IsError = $false,
        [Parameter(Mandatory = $false)]
        [Switch]$IsWarn = $false,
        [Parameter(Mandatory = $false)]
        [Switch]$IsInfo = $false,
        [Parameter(Mandatory = $false)]
        [Switch]$MachineInfo = $false,
        [Parameter(Mandatory = $false)]
        [Switch]$StopInfo = $false,
        [Parameter(Mandatory = $false)]
        [string]$ErrorMessage,
        [Parameter(Mandatory = $false)]
        [System.Collections.ArrayList]$WarnMessage,
        [Parameter(Mandatory = $false)]
        [string]$InfoMessage,
        [Parameter(Mandatory = $false)]
        [string]$StackTraceInfo,
        [String]$LogFile
    )   

    if ($MachineInfo) {
        $ComputerInfoObj = Get-ComputerInfo 
        $CompName = $ComputerInfoObj.CsName
        $OSName = $ComputerInfoObj.OsName
        $OSVersion = $ComputerInfoObj.OsVersion
        $PowerShellVersion = $PSVersionTable.PSVersion
        try {
            "********************************************************************************************" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            "Logging Started" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            "Start time: $(Get-Date)" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            "Computer Name: $CompName" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            "Operating System Name: $OSName" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            "Operating System Version: $OSVersion" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            "PowerShell Version: $PowerShellVersion" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            "********************************************************************************************" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
         
        }
        catch {
            Write-Host "$(Get-Date) The local machine information cannot be logged." -ForegroundColor:Yellow
        }

    }
    if ($StopInfo) {
        try {
            "********************************************************************************************" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            "Logging Ended" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            "End time: $(Get-Date)" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            "********************************************************************************************" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            
            if ($($global:ErrorOccurred) -eq $true) {
                Write-Host "Warning:$(Get-Date) The report generated may have reduced information due to errors in running the tool. These errors may occur due to multiple reasons. Please refer documentation for more details." -ForegroundColor:Yellow
            }
         
        }
        catch {
            Write-Host "$(Get-Date) The finishing time information cannot be logged." -ForegroundColor:Yellow
        }
    }
    #Error
    if ($IsError) {
        if ($($global:ErrorOccurred) -eq $false) {
            $global:ErrorOccurred = $true
        }
        $Log_content = "$(Get-Date) ERROR: $ErrorMessage"
        try {
            $Log_content | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            "TRACE: $StackTraceInfo" | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
        }
        catch {
            Write-Host "$(Get-Date) An error event cannot be logged." -ForegroundColor:Yellow  
        }           
    }
    #Warning
    if ($IsWarn) {
        foreach ($Warnmsg in $WarnMessage) {
            $Log_content = "$(Get-Date) WARN: $Warnmsg"
            try {
                $Log_content | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
            }
            catch {
                Write-Host "$(Get-Date) A warning event cannot be logged." -ForegroundColor:Yellow 
            }
        }
    }
    #General
    if ($IsInfo) {
        $Log_content = "$(Get-Date) INFO: $InfoMessage"
        try {
            $Log_content | Out-File $LogFile -Append -ErrorAction:SilentlyContinue
        }
        catch {
            Write-Host "$(Get-Date) A general event cannot be logged." -ForegroundColor:Yellow 
        }
        
    }
}

# Get the Number Region Mapping HashTable
function Get-NumberRegionMappingHashTable {
    #Number To Region Mapping 
    $NumberToRegionMapping = @{}
    $NumberToRegionMapping[1] = New-Object -TypeName PSObject -Property @{
        Code        = "APC"
        Description = "Asia-Pacific"
    }
    $NumberToRegionMapping[2] = New-Object -TypeName PSObject -Property @{
        Code        = "AUS"
        Description = "Australia"
    }
    $NumberToRegionMapping[3] = New-Object -TypeName PSObject -Property @{
        Code        = "CAN"
        Description = "Canada"
    }
    $NumberToRegionMapping[4] = New-Object -TypeName PSObject -Property @{
        Code        = "EUR"
        Description = "Europe (excl. France) / Middle East / Africa"
    }
    $NumberToRegionMapping[5] = New-Object -TypeName PSObject -Property @{
        Code        = "FRA"
        Description = "France"
    }
    $NumberToRegionMapping[6] = New-Object -TypeName PSObject -Property @{
        Code        = "IND"
        Description = "India"
    }
    $NumberToRegionMapping[7] = New-Object -TypeName PSObject -Property @{
        Code        = "JPN"
        Description = "Japan"
    }
    $NumberToRegionMapping[8] = New-Object -TypeName PSObject -Property @{
        Code        = "KOR"
        Description = "Korea"
    }
    $NumberToRegionMapping[9] = New-Object -TypeName PSObject -Property @{
        Code        = "NAM"
        Description = "North America (excl. Canada)"
    }
    $NumberToRegionMapping[10] = New-Object -TypeName PSObject -Property @{
        Code        = "LAM"
        Description = "South America"
    }
    $NumberToRegionMapping[11] = New-Object -TypeName PSObject -Property @{
        Code        = "ZAF"
        Description = "South Africa"
    }
    $NumberToRegionMapping[12] = New-Object -TypeName PSObject -Property @{
        Code        = "CHE"
        Description = "Switzerland"
    }
    $NumberToRegionMapping[13] = New-Object -TypeName PSObject -Property @{
        Code        = "ARE"
        Description = "United Arab Emirates"
    }
    $NumberToRegionMapping[14] = New-Object -TypeName PSObject -Property @{
        Code        = "GBR"
        Description = "United Kingdom"
    }
    
    
    return $NumberToRegionMapping
}


#Check if the geo param is in right format
function Get-GeoAcceptance {
    param (
        $Geo
    )

    $LegitimateGeo = $Geo | Where-Object { ($_ -ge 1) -and ($_ -le 14) }

    return ($($LegitimateGeo.Count) -eq $($Geo.Count))
}

# Display options for the user to choose
function Show-GeoOptions {
    Write-Host "Error:$(Get-Date) Please input appropriate numbers from the following list corresponding to the regions for which you wish to customize the report & run the tool again." -ForegroundColor:Red 
    #Number To Region Mapping 
    $NumberToRegionMapping = Get-NumberRegionMappingHashTable
    Write-Host "*******************************************************************************"
    write-host "For Geo Location"
    Write-Host "*******************************************************************************"
    [int] $count = 1
    while ($count -le 14) {
        Write-Host "$count--->$($($NumberToRegionMapping[$count]).Description)"
        $count = $count + 1
    }

    
    Write-Host "*******************************************************************************"
    Write-Host "Example: Get-CAMPReport -Geo @(1,7) -Solution @(1,7)"
    Write-Host "or"
    Write-Host "Get-CAMPReport -Geo @(1,7)"
    Write-Host ""
    Write-Host ""
    
}

function Get-SolutionTable {
    #Number To Region Mapping 
    $SolutionTable = @{}
    $SolutionTable[1] = New-Object -TypeName PSObject -Property @{
        Code     = "DLP"
        FullName = "Data Loss Prevention"
         
    }
    $SolutionTable[2] = New-Object -TypeName PSObject -Property @{
        Code     = "IP"
        FullName = "Information Protection"
    }
    $SolutionTable[3] = New-Object -TypeName PSObject -Property @{
        Code     = "IG"
        FullName = "Data Lifecycle Management"
    }
    $SolutionTable[4] = New-Object -TypeName PSObject -Property @{
        Code     = "RM"
        FullName = "Records Management"
    }
    $SolutionTable[5] = New-Object -TypeName PSObject -Property @{
        Code     = "CC"
        FullName = "Communication Compliance"
    }
    $SolutionTable[6] = New-Object -TypeName PSObject -Property @{
        Code     = "IRM"
        FullName = "Insider Risk Management"
    }
    $SolutionTable[7] = New-Object -TypeName PSObject -Property @{
        Code     = "Audit"
        FullName = "Audit"
    }
    $SolutionTable[8] = New-Object -TypeName PSObject -Property @{
        Code     = "eDiscovery"
        FullName = "eDiscovery"
    }

    return $SolutionTable
}


#Check if the geo param is in right format
function Get-SolutionAcceptance {
    Param (
        $Solution
    )
    
    $ValidSolution = $Solution | Where-Object { ($_ -ge 1) -and ($_ -le 8) }
    return ($($ValidSolution.Count) -eq $($Solution.Count))
}

function Show-SolutionOptions {
  
    Write-Host "Error:$(Get-Date) Please input appropriate numbers from the following list corresponding to solution for which you wish to customize the report & run the tool again." -ForegroundColor:Red 
    $SolutionTable = Get-SolutionTable
    Write-Host "*******************************************************************************"
    write-host "Solution"
    Write-Host "*******************************************************************************"
    [int] $count = 1
    while ($count -le 8) {
        Write-Host "$count--->$($($SolutionTable[$count]).FullName)"
        $count = $count + 1
    }

    Write-Host "*******************************************************************************"
    Write-Host "Example: Get-CAMPReport -Geo @(1,7) -Solution @(1,7)"
    Write-Host "or"
    Write-Host "Get-CAMPReport -Solution @(1,7)"
    Write-Host ""
    Write-Host ""
    
}
