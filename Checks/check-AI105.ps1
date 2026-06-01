using module "..\CAMP.psm1"

class AI105 : CAMPCheck {
    <#
        Configure communication compliance policy for risky generative AI prompts
        Based on Microsoft Purview Deployment Models: Prevent data leak to shadow AI
    #>

    AI105() {
        $this.Control            = "AI-105"
        $this.ParentArea         = "Microsoft Purview AI"
        $this.Area               = "AI & Shadow IT"
        $this.Name               = "Configure Communication Compliance Policy for Risky Generative AI Prompts"
        $this.PassText           = "Your organization has an enabled communication compliance policy targeting Copilot or generative AI prompts"
        $this.FailRecommendation = "Your organization should configure communication compliance policies for risky Copilot and generative AI prompts"
        $this.Importance         = "The Prevent data leak to shadow AI deployment model Step 4 recommends monitoring risky prompts after discovery and restriction controls are in place. Communication compliance requires Microsoft 365 E5 Compliance or equivalent licensing and appropriate Communication Compliance roles. This control helps reviewers identify sensitive, inappropriate, or risky generative AI prompts that need investigation or education."
        $this.ExpandResults      = $True
        $this.ItemName           = "Communication Compliance Policy"
        $this.DataType           = "AI Prompt Coverage"

        $this.Blueprint        = [CAMPBlueprint]::ShadowAI
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "ShadowAI" = 4 }
        $this.RequiredCollections = @("GetSupervisoryReviewPolicyV2")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 4"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step4"
                "Communication compliance"      = "https://learn.microsoft.com/purview/communication-compliance"
                "Microsoft Purview portal"      = "https://purview.microsoft.com"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 4"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step4"
                "Communication compliance"      = "https://learn.microsoft.com/purview/communication-compliance"
                "Microsoft Purview portal"      = "https://purview.microsoft.com"
            }
        }
        else {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 4"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step4"
                "Communication compliance"      = "https://learn.microsoft.com/purview/communication-compliance"
                "Microsoft Purview portal"      = "https://purview.microsoft.com"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs communication compliance policies from Security & Compliance PowerShell.")
                return
            }
        }

        $FoundEnabledAiPolicy = $false
        $FoundAnyAiPolicy = $false

        ForEach ($Policy in $Config["GetSupervisoryReviewPolicyV2"]) {
            $PolicyName = $Policy.Name
            if ([string]::IsNullOrWhiteSpace([string]$PolicyName)) { $PolicyName = $Policy.Identity }

            $PolicyStatus = $null
            $Mode = $null
            $Disabled = $null
            if ($null -ne $Policy.PSObject.Properties["PolicyStatus"]) { $PolicyStatus = [string]$Policy.PSObject.Properties["PolicyStatus"].Value }
            if ($null -ne $Policy.PSObject.Properties["Mode"]) { $Mode = [string]$Policy.PSObject.Properties["Mode"].Value }
            if ($null -ne $Policy.PSObject.Properties["Disabled"]) { $Disabled = $Policy.PSObject.Properties["Disabled"].Value }

            $IsEnabled = $false
            if ($PolicyStatus -ieq "Active" -or $PolicyStatus -ieq "Enabled") { $IsEnabled = $true }
            elseif ($Mode -ieq "Enable" -or $Mode -ieq "Enabled") { $IsEnabled = $true }
            elseif ($Disabled -is [bool] -and $Disabled -eq $false) { $IsEnabled = $true }
            elseif ([string]$Disabled -match "(?i)^false$") { $IsEnabled = $true }

            $SignalParts = @()
            foreach ($PropertyName in @("Workload", "Locations", "Conditions")) {
                $Property = $Policy.PSObject.Properties[$PropertyName]
                if ($null -eq $Property) { continue }
                $PropertyText = ($Property.Value | Out-String).Trim()
                if (-not [string]::IsNullOrWhiteSpace($PropertyText)) {
                    $SignalParts += "$PropertyName=$PropertyText"
                }
            }

            $SignalText = $SignalParts -join "; "
            if ($SignalText -match "(?i)Copilot|GenerativeAI|Generative AI|AI Prompt|Prompt") {
                $FoundAnyAiPolicy = $true
                if ($SignalText.Length -gt 220) { $SignalText = $SignalText.Substring(0, 220) + "..." }

                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object     = $PolicyName
                $ConfigObject.ConfigItem = "Policy status: $PolicyStatus"
                $ConfigObject.ConfigData = $SignalText

                if ($IsEnabled) {
                    $FoundEnabledAiPolicy = $true
                    $ConfigObject.InfoText = "Confirm reviewers, classifiers, and escalation processes are tuned for risky Copilot or generative AI prompts."
                    $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                }
                else {
                    $ConfigObject.InfoText = "This policy appears to target Copilot or generative AI prompts but is not enabled. Enable it after validating scope and reviewers."
                    $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                }

                $this.AddConfig($ConfigObject)
            }
        }

        if (-not $FoundEnabledAiPolicy) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "No enabled AI prompt policy"
            $ConfigObject.ConfigItem = "Workload / Locations / Conditions"
            if ($FoundAnyAiPolicy) {
                $ConfigObject.ConfigData = "Only disabled or inactive policies appeared to target Copilot or generative AI prompts"
            }
            else {
                $ConfigObject.ConfigData = "No communication compliance policy targeted Copilot or generative AI prompts"
            }
            $ConfigObject.InfoText   = "Create or enable a communication compliance policy for risky generative AI prompts using the Shadow AI Step 4 guidance in Microsoft Purview."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}

