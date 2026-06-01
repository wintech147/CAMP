using module "..\CAMP.psm1"

class DLP204 : CAMPCheck {
    <#

        DLP for Microsoft Teams Chats and Channel Messages
        Based on Microsoft Purview Deployment Models: Lightweight DLP and Shadow AI Blueprints

    #>

    DLP204() {
        $this.Control = "DLP-204"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Data Loss Prevention"
        $this.Name = "Enable DLP for Microsoft Teams Chats and Channel Messages"
        $this.PassText = "Your organization has Teams DLP policies that target external or guest sharing"
        $this.FailRecommendation = "Your organization should enable DLP for Microsoft Teams chats and channel messages that target external or guest users"
        $this.Importance = "The Lightweight DLP deployment model Step 2 expands DLP coverage to Teams chats and channel messages so sensitive content shared in collaboration spaces can be detected and restricted. Teams DLP requires licensing that includes Microsoft Purview DLP for Teams; advanced external-sharing controls may require Microsoft 365 E5 Compliance."
        $this.ExpandResults = $True
        $this.CheckType = [CheckType]::ObjectPropertyValue
        $this.ObjectType = "DLP Policy"
        $this.ItemName = "Teams Scope"
        $this.DataType = "External Sharing Condition"
        $this.Blueprint = [CAMPBlueprint]::LightweightDLP -bor [CAMPBlueprint]::ShadowAI
        $this.MaturityLevel = [CAMPMaturityLevel]::Better
        $this.BlueprintStages = @{ "LightweightDLP" = 2; "ShadowAI" = 2 }
        $this.RequiredCollections = @("GetDlpCompliancePolicy", "GetDlpComplianceRule")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses = @()
        $this.CommercialOnly = $false
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Lightweight DLP Step 2"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-gcch-dlp-compliance-center"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Lightweight DLP overview"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Lightweight DLP Step 2"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dod-dlp-compliance-center"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Lightweight DLP overview"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
            }
        }else
        {
            $this.Links = @{
                "Lightweight DLP Step 2"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2"
                "Microsoft Purview portal - Data Loss Prevention" = "https://purview.microsoft.com"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Lightweight DLP overview"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs DLP policies and rules from Security & Compliance PowerShell.")
                return
            }
        }

        $HasLocation = {
            param($Value)

            $Items = @($Value) | Where-Object { $null -ne $_ -and "$_".Trim() -ne "" -and "$_" -ine "None" }
            return ($Items.Count -gt 0)
        }

        $GetLocationText = {
            param($Value)

            $Items = @($Value) | Where-Object { $null -ne $_ -and "$_".Trim() -ne "" -and "$_" -ine "None" }
            if ($Items.Count -eq 0) {
                return "Not configured"
            }

            return ($Items -join ", ")
        }

        $GetExternalConditionValues = {
            param($Rule)

            $ExternalValues = @()
            foreach ($PropertyName in @("AccessScope", "SharedWith")) {
                $Property = $Rule.PSObject.Properties[$PropertyName]
                if ($null -ne $Property) {
                    foreach ($Value in @($Property.Value)) {
                        if ($null -ne $Value -and "$Value".Trim() -ne "" -and "$Value" -match "(?i)NotInOrganization|Outside|External|Guest|Anonymous|Anyone") {
                            $ExternalValues += "$PropertyName=$Value"
                        }
                    }
                }
            }

            return $ExternalValues
        }

        $PassingConfigs = @()
        $TeamsPoliciesWithoutExternalScope = @()
        $EnabledTeamsPolicies = @()

        ForEach ($CompliancePolicy in $Config["GetDlpCompliancePolicy"]) {
            if ($CompliancePolicy.Mode -ieq "Enable" -and (& $HasLocation $CompliancePolicy.TeamsLocation)) {
                $PolicyName = $CompliancePolicy.Name
                $EnabledTeamsPolicies += $PolicyName
                $ExternalRuleNames = @()
                $ExternalConditionValues = @()

                ForEach ($Rule in $Config["GetDlpComplianceRule"]) {
                    if ($Rule.ParentPolicyName -eq $PolicyName) {
                        $RuleExternalValues = & $GetExternalConditionValues $Rule
                        if ($RuleExternalValues.Count -gt 0) {
                            $ExternalRuleNames += $Rule.Name
                            $ExternalConditionValues += $RuleExternalValues
                        }
                    }
                }

                if ($ExternalRuleNames.Count -gt 0) {
                    $ConfigObject = [CAMPCheckConfig]::new()
                    $ConfigObject.Object = $PolicyName
                    $ConfigObject.ConfigItem = "Teams: $(& $GetLocationText $CompliancePolicy.TeamsLocation)"
                    $ConfigObject.ConfigData = "External/guest rule condition found in: $($ExternalRuleNames -join ', ') | $($ExternalConditionValues -join '; ')"
                    $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                    $PassingConfigs += $ConfigObject
                }
                else {
                    $TeamsPoliciesWithoutExternalScope += $PolicyName
                }
            }
        }

        if ($PassingConfigs.Count -gt 0) {
            foreach ($ConfigObject in $PassingConfigs) {
                $this.AddConfig($ConfigObject)
            }
        }
        elseif ($EnabledTeamsPolicies.Count -gt 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "Teams DLP Policies Need External Scope"
            $ConfigObject.ConfigItem = "Enabled Teams policies: $($EnabledTeamsPolicies -join ', ')"
            $ConfigObject.ConfigData = "No Teams DLP rule includes an AccessScope or SharedWith condition targeting external or guest users"
            $ConfigObject.InfoText = "Add a rule condition such as content shared with people outside the organization so Teams chats and channel messages are evaluated for external or guest exposure."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            $this.AddConfig($ConfigObject)
        }
        else {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Teams DLP Policy"
            $ConfigObject.ConfigItem = "No enabled DLP policy includes Teams"
            $ConfigObject.ConfigData = "Your organization has not enabled DLP for Microsoft Teams chats and channel messages"
            $ConfigObject.InfoText = "Create or enable a DLP policy that includes the Teams location, then add AccessScope or SharedWith conditions for external or guest sharing."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}

