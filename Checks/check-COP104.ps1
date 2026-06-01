using module "..\CAMP.psm1"

class COP104 : CAMPCheck {
    <#

        Use DLP to Restrict Sensitive Files from Copilot Grounding
        Based on Microsoft Purview Deployment Models: Secure & govern Microsoft 365 Copilot agents.

    #>

    COP104() {
        $this.Control = "COP-104"
        $this.ParentArea = "Microsoft Purview AI"
        $this.Area = "Copilot & Agents"
        $this.Name = "Use DLP to Restrict Sensitive Files from Copilot Grounding"
        $this.Blueprint = [CAMPBlueprint]::CopilotAgents -bor [CAMPBlueprint]::ShadowAI
        $this.MaturityLevel = [CAMPMaturityLevel]::Better
        $this.BlueprintStages = @{
            "CopilotAgents" = 2
            "ShadowAI" = 2
        }
        $this.Foundational = $false
        $this.RequiredCollections = @("GetDlpComplianceRule", "GetDlpCompliancePolicy")
        $this.RequiredLicenses = @("Microsoft 365 E5 Compliance", "Microsoft 365 Copilot")
        $this.CommercialOnly = $true
        $this.PassText = "Your organization has at least one DLP rule that restricts sensitive content from Copilot grounding"
        $this.FailRecommendation = "Create DLP rules that restrict sensitive files from Microsoft 365 Copilot grounding"
        $this.Importance = "Step 2 of the Secure & govern Microsoft 365 Copilot agents deployment model uses DLP to prevent sensitive content from being processed by Copilot grounding and to reduce oversharing and shadow AI exposure. Copilot-scoped DLP actions and locations are evolving across previews, require Microsoft Purview DLP licensing, and are CommercialOnly at the time of writing for GCCH/DoD tenants."
        $this.ExpandResults = $True
        $this.ItemName = "DLP Rule"
        $this.DataType = "Copilot Restriction"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 2" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step2"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.us/aiHub"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 2" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step2"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.us/aiHub"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }else
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 2" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step2"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.com/aiHub"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config) {
        if (-not $this.HasCollection($Config, "GetDlpComplianceRule")) {
            $this.SetUnavailable("Required collection GetDlpComplianceRule is missing or returned an error.")
            return
        }
        if (-not $this.HasCollection($Config, "GetDlpCompliancePolicy")) {
            $this.SetUnavailable("Required collection GetDlpCompliancePolicy is missing or returned an error.")
            return
        }

        $PoliciesByName = @{}
        foreach ($Policy in @($Config["GetDlpCompliancePolicy"])) {
            $PolicyName = $null
            foreach ($PropertyName in @("Name", "Identity", "Guid")) {
                if ($null -eq $PolicyName) {
                    if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains($PropertyName)) {
                        $PolicyName = $Policy[$PropertyName]
                    }
                    elseif ($null -ne $Policy.PSObject.Properties[$PropertyName]) {
                        $PolicyName = $Policy.PSObject.Properties[$PropertyName].Value
                    }
                }
            }
            if ($null -ne $PolicyName -and -not [string]::IsNullOrWhiteSpace([string]$PolicyName)) {
                $PoliciesByName[[string]$PolicyName] = $Policy
            }
        }

        $MatchingRuleCount = 0
        foreach ($Rule in @($Config["GetDlpComplianceRule"])) {
            $RuleName = "Unnamed DLP rule"
            foreach ($PropertyName in @("Name", "Identity", "Guid")) {
                if ($RuleName -eq "Unnamed DLP rule") {
                    if ($Rule -is [System.Collections.IDictionary] -and $Rule.Contains($PropertyName)) {
                        $RuleName = [string]$Rule[$PropertyName]
                    }
                    elseif ($null -ne $Rule.PSObject.Properties[$PropertyName]) {
                        $RuleName = [string]$Rule.PSObject.Properties[$PropertyName].Value
                    }
                }
            }

            $ParentPolicyName = $null
            foreach ($PropertyName in @("ParentPolicyName", "Policy", "PolicyName")) {
                if ($null -eq $ParentPolicyName) {
                    if ($Rule -is [System.Collections.IDictionary] -and $Rule.Contains($PropertyName)) {
                        $ParentPolicyName = $Rule[$PropertyName]
                    }
                    elseif ($null -ne $Rule.PSObject.Properties[$PropertyName]) {
                        $ParentPolicyName = $Rule.PSObject.Properties[$PropertyName].Value
                    }
                }
            }

            $RuleProperties = @()
            if ($Rule -is [System.Collections.IDictionary]) {
                foreach ($Key in $Rule.Keys) {
                    $RuleProperties += [pscustomobject]@{ Name = [string]$Key; Value = $Rule[$Key] }
                }
            }
            else {
                $RuleProperties = @($Rule.PSObject.Properties)
            }

            $HasRestrictAccessAction = $false
            $HasCopilotScope = $false
            foreach ($Property in $RuleProperties) {
                $ValueText = ""
                if ($null -ne $Property.Value) {
                    $ValueText = (@($Property.Value) | ForEach-Object { [string]$_ }) -join " "
                }

                if ($Property.Name -imatch "RestrictAccess") {
                    if ($Property.Value -is [bool]) {
                        if ($Property.Value) { $HasRestrictAccessAction = $true }
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($ValueText) -and $ValueText -inotmatch "^(false|none|notconfigured|\{\})$") {
                        $HasRestrictAccessAction = $true
                    }
                }
                if ($ValueText -imatch "\bRestrictAccess\b") {
                    $HasRestrictAccessAction = $true
                }
                if ($Property.Name -imatch "Copilot" -or $ValueText -imatch "Copilot|RestrictedByCopilot|NotProcessedByCopilot") {
                    $HasCopilotScope = $true
                }
            }

            $SensitiveInfoValue = $null
            if ($Rule -is [System.Collections.IDictionary] -and $Rule.Contains("ContentContainsSensitiveInformation")) {
                $SensitiveInfoValue = $Rule["ContentContainsSensitiveInformation"]
            }
            elseif ($null -ne $Rule.PSObject.Properties["ContentContainsSensitiveInformation"]) {
                $SensitiveInfoValue = $Rule.PSObject.Properties["ContentContainsSensitiveInformation"].Value
            }

            $HasSensitiveInfoCondition = $false
            if ($null -ne $SensitiveInfoValue) {
                $SensitiveInfoText = (@($SensitiveInfoValue) | ForEach-Object { [string]$_ }) -join " "
                if (-not [string]::IsNullOrWhiteSpace($SensitiveInfoText) -and $SensitiveInfoText -inotmatch "^(false|none|\{\})$") {
                    $HasSensitiveInfoCondition = $true
                }
            }

            $PolicyHasCopilotLocation = $false
            $Policy = $null
            if ($null -ne $ParentPolicyName -and $PoliciesByName.ContainsKey([string]$ParentPolicyName)) {
                $Policy = $PoliciesByName[[string]$ParentPolicyName]
            }
            if ($null -ne $Policy) {
                $LocationValue = $null
                if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains("MicrosoftCopilotChatLocation")) {
                    $LocationValue = $Policy["MicrosoftCopilotChatLocation"]
                }
                elseif ($null -ne $Policy.PSObject.Properties["MicrosoftCopilotChatLocation"]) {
                    $LocationValue = $Policy.PSObject.Properties["MicrosoftCopilotChatLocation"].Value
                }
                if ($null -ne $LocationValue) {
                    $LocationText = (@($LocationValue) | ForEach-Object { [string]$_ }) -join " "
                    if (-not [string]::IsNullOrWhiteSpace($LocationText) -and $LocationText -inotmatch "^(none|false|\{\})$") {
                        $PolicyHasCopilotLocation = $true
                    }
                }
            }

            $MatchDescriptions = @()
            if ($HasRestrictAccessAction -and $HasCopilotScope) {
                $MatchDescriptions += "RestrictAccess action with Copilot scope"
            }
            if ($HasSensitiveInfoCondition -and $PolicyHasCopilotLocation) {
                $MatchDescriptions += "Sensitive information condition with MicrosoftCopilotChatLocation policy scope"
            }

            if ($MatchDescriptions.Count -gt 0) {
                $MatchingRuleCount++
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = $RuleName
                $ConfigObject.ConfigItem = "Copilot-scoped DLP rule"
                $ConfigObject.ConfigData = $MatchDescriptions -join "; "
                $ConfigObject.InfoText = "Parent policy: $ParentPolicyName"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)
            }
        }

        if ($MatchingRuleCount -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "DLP"
            $ConfigObject.ConfigItem = "Copilot grounding restriction"
            $ConfigObject.ConfigData = "No matching Copilot-scoped DLP rule found"
            $ConfigObject.InfoText = "Create a DLP rule that uses the RestrictAccess action for Copilot grounding or applies sensitive information conditions to a policy with MicrosoftCopilotChatLocation populated."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $True
    }
}
