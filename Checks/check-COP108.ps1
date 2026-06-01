using module "..\CAMP.psm1"

class COP108 : CAMPCheck {
    <#

        Configure Communication Compliance over Microsoft 365 Copilot Interactions
        Based on Microsoft Purview Deployment Models: Secure & govern Microsoft 365 Copilot agents.

    #>

    COP108() {
        $this.Control = "COP-108"
        $this.ParentArea = "Microsoft Purview AI"
        $this.Area = "Copilot & Agents"
        $this.Name = "Configure Communication Compliance over Microsoft 365 Copilot Interactions"
        $this.Blueprint = [CAMPBlueprint]::CopilotAgents -bor [CAMPBlueprint]::ShadowAI
        $this.MaturityLevel = [CAMPMaturityLevel]::Best
        $this.BlueprintStages = @{
            "CopilotAgents" = 4
            "ShadowAI" = 4
        }
        $this.Foundational = $false
        $this.RequiredCollections = @("GetSupervisoryReviewPolicyV2")
        $this.RequiredLicenses = @("Microsoft 365 E5 Compliance", "Microsoft 365 Copilot")
        $this.CommercialOnly = $true
        $this.PassText = "Your organization has an enabled Communication Compliance policy scoped to Copilot or AI interactions"
        $this.FailRecommendation = "Configure Communication Compliance policies for Microsoft 365 Copilot and AI interaction review"
        $this.Importance = "Step 4 of the Secure & govern Microsoft 365 Copilot agents deployment model extends Communication Compliance to risky or inappropriate Microsoft 365 Copilot and agent interactions and routes them to reviewers. Copilot-scoped supervisory review workloads require Microsoft Purview Communication Compliance licensing and Copilot licensing, and are CommercialOnly at the time of writing for GCCH/DoD tenants."
        $this.ExpandResults = $True
        $this.ItemName = "Communication Compliance Policy"
        $this.DataType = "Copilot Scope"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 4" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step4"
                "Microsoft Purview portal - Communication Compliance" = "https://aka.ms/mcca-gcch-cc-compliance-center"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 4" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step4"
                "Microsoft Purview portal - Communication Compliance" = "https://aka.ms/mcca-dod-cc-compliance-center"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }else
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 4" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step4"
                "Microsoft Purview portal - Communication Compliance" = "https://aka.ms/mcca-cc-compliance-center"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config) {
        if (-not $this.HasCollection($Config, "GetSupervisoryReviewPolicyV2")) {
            $this.SetUnavailable("Required collection GetSupervisoryReviewPolicyV2 is missing or returned an error.")
            return
        }

        $MatchingPolicyCount = 0
        foreach ($Policy in @($Config["GetSupervisoryReviewPolicyV2"])) {
            $PolicyName = "Unnamed Communication Compliance policy"
            foreach ($PropertyName in @("Name", "Identity", "Guid")) {
                if ($PolicyName -eq "Unnamed Communication Compliance policy") {
                    if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains($PropertyName)) {
                        $PolicyName = [string]$Policy[$PropertyName]
                    }
                    elseif ($null -ne $Policy.PSObject.Properties[$PropertyName]) {
                        $PolicyName = [string]$Policy.PSObject.Properties[$PropertyName].Value
                    }
                }
            }

            $IsEnabled = $true
            $EnabledValue = $null
            if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains("Enabled")) {
                $EnabledValue = $Policy["Enabled"]
            }
            elseif ($null -ne $Policy.PSObject.Properties["Enabled"]) {
                $EnabledValue = $Policy.PSObject.Properties["Enabled"].Value
            }
            if ($null -ne $EnabledValue) {
                if ($EnabledValue -is [bool]) {
                    $IsEnabled = $EnabledValue
                }
                elseif ([string]$EnabledValue -imatch "^(false|disabled|off|0|no)$") {
                    $IsEnabled = $false
                }
            }
            if ($null -ne $Policy.PSObject.Properties["Mode"] -and [string]$Policy.PSObject.Properties["Mode"].Value -imatch "^(disable|disabled)$") {
                $IsEnabled = $false
            }
            if ($null -ne $Policy.PSObject.Properties["Disabled"] -and [string]$Policy.PSObject.Properties["Disabled"].Value -imatch "^(true|enabled|on|1|yes)$") {
                $IsEnabled = $false
            }
            if (-not $IsEnabled) {
                continue
            }

            $ScopeMatches = @()
            foreach ($PropertyName in @("Workload", "Workloads", "Location", "Locations")) {
                $Value = $null
                if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains($PropertyName)) {
                    $Value = $Policy[$PropertyName]
                }
                elseif ($null -ne $Policy.PSObject.Properties[$PropertyName]) {
                    $Value = $Policy.PSObject.Properties[$PropertyName].Value
                }
                if ($null -ne $Value) {
                    $ValueText = (@($Value) | ForEach-Object { [string]$_ }) -join " "
                    if ($ValueText -imatch "Copilot|\bAI\b") {
                        $ScopeMatches += "$PropertyName=$ValueText"
                    }
                }
            }

            if ($ScopeMatches.Count -gt 0) {
                $MatchingPolicyCount++
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = $PolicyName
                $ConfigObject.ConfigItem = "Copilot or AI supervisory review scope"
                $ConfigObject.ConfigData = $ScopeMatches -join "; "
                $ConfigObject.InfoText = "This enabled Communication Compliance policy references Copilot or AI in Workload or Locations."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)
            }
        }

        if ($MatchingPolicyCount -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "Communication Compliance"
            $ConfigObject.ConfigItem = "Copilot or AI supervisory review scope"
            $ConfigObject.ConfigData = "No enabled policy with Copilot or AI workload/location found"
            $ConfigObject.InfoText = "Configure an enabled Communication Compliance policy whose Workload or Locations include Microsoft 365 Copilot or AI interactions."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $True
    }
}
