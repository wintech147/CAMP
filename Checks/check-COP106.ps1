using module "..\CAMP.psm1"

class COP106 : CAMPCheck {
    <#

        Apply Retention Policy to Microsoft 365 Copilot and Agent Interactions
        Based on Microsoft Purview Deployment Models: Secure & govern Microsoft 365 Copilot agents.

    #>

    COP106() {
        $this.Control = "COP-106"
        $this.ParentArea = "Microsoft Purview AI"
        $this.Area = "Copilot & Agents"
        $this.Name = "Apply Retention Policy to Microsoft 365 Copilot and Agent Interactions"
        $this.Blueprint = [CAMPBlueprint]::CopilotAgents
        $this.MaturityLevel = [CAMPMaturityLevel]::Better
        $this.BlueprintStages = @{
            "CopilotAgents" = 4
        }
        $this.Foundational = $false
        $this.RequiredCollections = @("GetRetentionCompliancePolicy")
        $this.RequiredLicenses = @("Microsoft 365 E5 Compliance", "Microsoft 365 Copilot")
        $this.CommercialOnly = $true
        $this.PassText = "Your organization has an enabled retention policy scoped to Copilot or agent interactions"
        $this.FailRecommendation = "Create or update a retention policy for Microsoft 365 Copilot and agent interactions"
        $this.Importance = "Step 4 of the Secure & govern Microsoft 365 Copilot agents deployment model applies retention so Microsoft 365 Copilot and agent interaction records remain available for investigations, regulatory reviews, and eDiscovery searches. Copilot retention locations are being renamed across previews, require Microsoft Purview Data Lifecycle Management licensing and Copilot licensing, and are CommercialOnly at the time of writing for GCCH/DoD tenants."
        $this.ExpandResults = $True
        $this.ItemName = "Retention Policy"
        $this.DataType = "Copilot Location"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 4" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step4"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.us/aiHub"
                "Microsoft 365 Copilot data security" = "https://learn.microsoft.com/microsoft-365-copilot/microsoft-365-copilot-overview"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 4" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step4"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.us/aiHub"
                "Microsoft 365 Copilot data security" = "https://learn.microsoft.com/microsoft-365-copilot/microsoft-365-copilot-overview"
            }
        }else
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 4" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step4"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.com/aiHub"
                "Microsoft 365 Copilot data security" = "https://learn.microsoft.com/microsoft-365-copilot/microsoft-365-copilot-overview"
            }
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config) {
        if (-not $this.HasCollection($Config, "GetRetentionCompliancePolicy")) {
            $this.SetUnavailable("Required collection GetRetentionCompliancePolicy is missing or returned an error.")
            return
        }

        $LocationPropertyNames = @("MicrosoftCopilotChatLocation", "Microsoft365CopilotLocation", "CopilotExperienceLocation", "TeamsCopilotLocation")
        $MatchingPolicyCount = 0

        foreach ($Policy in @($Config["GetRetentionCompliancePolicy"])) {
            $PolicyName = "Unnamed retention policy"
            foreach ($PropertyName in @("Name", "Identity", "Guid")) {
                if ($PolicyName -eq "Unnamed retention policy") {
                    if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains($PropertyName)) {
                        $PolicyName = [string]$Policy[$PropertyName]
                    }
                    elseif ($null -ne $Policy.PSObject.Properties[$PropertyName]) {
                        $PolicyName = [string]$Policy.PSObject.Properties[$PropertyName].Value
                    }
                }
            }

            $IsEnabled = $true
            foreach ($PropertyName in @("Enabled", "IsEnabled")) {
                $EnabledValue = $null
                if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains($PropertyName)) {
                    $EnabledValue = $Policy[$PropertyName]
                }
                elseif ($null -ne $Policy.PSObject.Properties[$PropertyName]) {
                    $EnabledValue = $Policy.PSObject.Properties[$PropertyName].Value
                }
                if ($null -ne $EnabledValue) {
                    if ($EnabledValue -is [bool]) {
                        $IsEnabled = $EnabledValue
                    }
                    elseif ([string]$EnabledValue -imatch "^(false|disabled|off|0|no)$") {
                        $IsEnabled = $false
                    }
                }
            }
            if ($null -ne $Policy.PSObject.Properties["Mode"] -and [string]$Policy.PSObject.Properties["Mode"].Value -imatch "^(disable|disabled)$") {
                $IsEnabled = $false
            }
            if (-not $IsEnabled) {
                continue
            }

            $MatchedLocations = @()
            foreach ($PropertyName in $LocationPropertyNames) {
                $LocationValue = $null
                if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains($PropertyName)) {
                    $LocationValue = $Policy[$PropertyName]
                }
                elseif ($null -ne $Policy.PSObject.Properties[$PropertyName]) {
                    $LocationValue = $Policy.PSObject.Properties[$PropertyName].Value
                }
                if ($null -ne $LocationValue) {
                    $LocationText = (@($LocationValue) | ForEach-Object { [string]$_ }) -join " "
                    if (-not [string]::IsNullOrWhiteSpace($LocationText) -and $LocationText -inotmatch "^(none|false|\{\})$") {
                        $MatchedLocations += "$PropertyName=$LocationText"
                    }
                }
            }

            if ($MatchedLocations.Count -gt 0) {
                $MatchingPolicyCount++
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = $PolicyName
                $ConfigObject.ConfigItem = "Copilot retention location"
                $ConfigObject.ConfigData = $MatchedLocations -join "; "
                $ConfigObject.InfoText = "This enabled retention policy includes a Copilot or agent interaction location."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)
            }
        }

        if ($MatchingPolicyCount -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "Retention policies"
            $ConfigObject.ConfigItem = "Copilot retention location"
            $ConfigObject.ConfigData = "No enabled retention policy with a Copilot location found"
            $ConfigObject.InfoText = "Create or update a retention policy that targets MicrosoftCopilotChatLocation, Microsoft365CopilotLocation, CopilotExperienceLocation, or TeamsCopilotLocation as those property names evolve across previews."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $True
    }
}
