using module "..\CAMP.psm1"

class AI103 : CAMPCheck {
    <#
        Apply DLP to the Microsoft 365 Copilot location
        Based on Microsoft Purview Deployment Models: Prevent data leak to shadow AI, Secure and govern Microsoft 365 Copilot agents
    #>

    AI103() {
        $this.Control            = "AI-103"
        $this.ParentArea         = "Microsoft Purview AI"
        $this.Area               = "AI & Shadow IT"
        $this.Name               = "Apply DLP to the Microsoft 365 Copilot Location"
        $this.PassText           = "Your organization has enabled DLP policies that include a Microsoft 365 Copilot location"
        $this.FailRecommendation = "Your organization should apply DLP policies to the Microsoft 365 Copilot location"
        $this.Importance         = "The Prevent data leak to shadow AI deployment model Step 3 and the Secure and govern Microsoft 365 Copilot agents deployment model Step 2 recommend applying DLP controls to Microsoft 365 Copilot experiences. This requires Microsoft 365 E5 Compliance or equivalent DLP licensing and Microsoft 365 Copilot licensing for the workloads being governed. Several Copilot DLP features are commercial-only at the time of writing, so this check is marked CommercialOnly and may be unavailable in GCCH or DoD."
        $this.ExpandResults      = $True
        $this.ItemName           = "DLP Policy"
        $this.DataType           = "Copilot Location"

        $this.Blueprint        = [CAMPBlueprint]::ShadowAI -bor [CAMPBlueprint]::CopilotAgents
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "ShadowAI" = 3; "CopilotAgents" = 2 }
        $this.RequiredCollections = @("GetDlpCompliancePolicy")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance", "Microsoft 365 Copilot")
        $this.CommercialOnly      = $true

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 3"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step3"
                "Microsoft Purview DLP"         = "https://purview.microsoft.com/datalossprevention"
                "Endpoint DLP"                  = "https://learn.microsoft.com/purview/endpoint-dlp-learn-about"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 3"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step3"
                "Microsoft Purview DLP"         = "https://purview.microsoft.com/datalossprevention"
                "Endpoint DLP"                  = "https://learn.microsoft.com/purview/endpoint-dlp-learn-about"
            }
        }
        else {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 3"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step3"
                "Microsoft Purview DLP"         = "https://purview.microsoft.com/datalossprevention"
                "Endpoint DLP"                  = "https://learn.microsoft.com/purview/endpoint-dlp-learn-about"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs DLP compliance policies from Security & Compliance PowerShell.")
                return
            }
        }

        $LocationPropertyNames = @("MicrosoftCopilotChatLocation", "Microsoft365CopilotLocation", "CopilotExperienceLocation")
        $EnabledPoliciesChecked = 0
        $PoliciesWithCopilotLocation = @()

        ForEach ($Policy in $Config["GetDlpCompliancePolicy"]) {
            $PolicyName = $Policy.Name
            if ([string]::IsNullOrWhiteSpace([string]$PolicyName)) { $PolicyName = $Policy.Identity }

            $Mode = $null
            $PolicyStatus = $null
            $EnabledValue = $null
            if ($null -ne $Policy.PSObject.Properties["Mode"]) { $Mode = [string]$Policy.PSObject.Properties["Mode"].Value }
            if ($null -ne $Policy.PSObject.Properties["PolicyStatus"]) { $PolicyStatus = [string]$Policy.PSObject.Properties["PolicyStatus"].Value }
            if ($null -ne $Policy.PSObject.Properties["Enabled"]) { $EnabledValue = $Policy.PSObject.Properties["Enabled"].Value }

            $IsEnabled = $false
            if ($Mode -ieq "Enable" -or $Mode -ieq "Enabled") { $IsEnabled = $true }
            elseif ($PolicyStatus -ieq "Active" -or $PolicyStatus -ieq "Enabled") { $IsEnabled = $true }
            elseif ($EnabledValue -is [bool] -and $EnabledValue -eq $true) { $IsEnabled = $true }
            elseif ([string]$EnabledValue -match "(?i)^(true|enabled|active)$") { $IsEnabled = $true }

            if (-not $IsEnabled) { continue }
            $EnabledPoliciesChecked++

            $LocationMatches = @()
            foreach ($PropertyName in $LocationPropertyNames) {
                $LocationProperty = $Policy.PSObject.Properties[$PropertyName]
                if ($null -eq $LocationProperty) { continue }

                $LocationValues = @($LocationProperty.Value) | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) -and [string]$_ -ine "None" -and [string]$_ -ine "NotConfigured" }
                if ($LocationValues.Count -gt 0) {
                    $LocationMatches += "$PropertyName=$($LocationValues -join ', ')"
                }
            }

            if ($LocationMatches.Count -gt 0) {
                $PoliciesWithCopilotLocation += $PolicyName
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object     = $PolicyName
                $ConfigObject.ConfigItem = "Microsoft 365 Copilot location configured"
                $ConfigObject.ConfigData = $LocationMatches -join "; "
                $ConfigObject.InfoText   = "Confirm the rules under this policy enforce the intended restrictions for Microsoft 365 Copilot prompts, responses, and grounding content."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)
            }
        }

        if ($PoliciesWithCopilotLocation.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "No DLP policy with Copilot location"
            $ConfigObject.ConfigItem = "Properties checked: $($LocationPropertyNames -join ', ')"
            $ConfigObject.ConfigData = "Enabled DLP policies checked: $EnabledPoliciesChecked"
            $ConfigObject.InfoText   = "Create or update an enabled DLP policy to include the Microsoft 365 Copilot location. Purview preview tenants have exposed this location as MicrosoftCopilotChatLocation, Microsoft365CopilotLocation, or CopilotExperienceLocation."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}

