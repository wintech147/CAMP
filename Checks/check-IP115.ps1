using module "..\CAMP.psm1"

class IP115 : CAMPCheck {
    <#
        Apply auto-labeling to All Credentials sensitive information
        Based on Microsoft Purview Deployment Models: Secure by Default, Lightweight DLP, and Shadow AI Blueprints
    #>

    IP115() {
        $this.Control            = "IP-115"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Information Protection"
        $this.Name               = "Apply Auto-Labeling to All-Credentials Sensitive Information"
        $this.PassText           = "Your organization has an enabled auto-labeling policy rule that detects the All Credentials sensitive information type"
        $this.FailRecommendation = "Your organization should configure enabled auto-labeling rules for the All Credentials sensitive information type"
        $this.Importance         = "Secure by Default Step 2 highlights identifying and protecting credentials because leaked secrets can quickly become tenant compromise. Lightweight DLP Step 3 recommends using automated detection and protection for high-risk sensitive information, including credentials that may appear in documents or messages. Auto-labeling for this scenario typically requires Microsoft 365 E5 Compliance or equivalent Information Protection advanced licensing."
        $this.ExpandResults      = $True
        $this.ItemName           = "Auto-Labeling Policy"
        $this.DataType           = "All Credentials Rule"

        $this.Blueprint        = [CAMPBlueprint]::SecureByDefault -bor [CAMPBlueprint]::LightweightDLP -bor [CAMPBlueprint]::ShadowAI
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "SecureByDefault" = 2; "LightweightDLP" = 3 }
        $this.RequiredCollections = @("GetAutoSensitivityLabelPolicy")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.microsoft.us"
                "Automatically apply a sensitivity label"          = "https://learn.microsoft.com/purview/apply-sensitivity-label-automatically"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.apps.mil"
                "Automatically apply a sensitivity label"          = "https://learn.microsoft.com/purview/apply-sensitivity-label-automatically"
            }
        }
        else {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://purview.microsoft.com"
                "Automatically apply a sensitivity label"          = "https://learn.microsoft.com/purview/apply-sensitivity-label-automatically"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs Get-AutoSensitivityLabelPolicy results.")
                return
            }
        }

        $EnabledPolicyCount = 0
        $MatchingRules = @()

        ForEach ($Policy in $Config["GetAutoSensitivityLabelPolicy"]) {
            $Mode = "$($Policy.Mode)"
            if ($Mode -ine "Enable") {
                continue
            }

            $EnabledPolicyCount++
            $PolicyName = $Policy.Name
            if ([string]::IsNullOrWhiteSpace($PolicyName)) { $PolicyName = $Policy.Identity }

            try {
                $Rules = Get-AutoSensitivityLabelRule -Policy $PolicyName -ErrorAction:Stop
            }
            catch {
                $this.EmitAwarenessRecommendation(
                    "<B>All-credentials auto-labeling (manual review for policy '$PolicyName')</B>",
                    "Get-AutoSensitivityLabelRule not available for this policy",
                    "The rule details for '$PolicyName' could not be enumerated.",
                    "Review the auto-labeling rule manually in Microsoft Purview > Information Protection > Auto-labeling > '$PolicyName'. Confirm it references the 'All credentials' sensitive information type."
                )
                return
            }

            $PolicyMatched = $false
            $RuleNames = @()
            foreach ($Rule in @($Rules)) {
                $SensitiveInfoParts = @()
                foreach ($SensitiveInfo in @($Rule.ContentContainsSensitiveInformation)) {
                    $SensitiveInfoParts += "$SensitiveInfo"
                    foreach ($Property in $SensitiveInfo.PSObject.Properties) {
                        if ($Property.Name -match "(?i)name|sensitive|type|id") {
                            $SensitiveInfoParts += "$($Property.Value)"
                        }
                    }
                }

                $SensitiveInfoText = $SensitiveInfoParts -join " "
                if ($SensitiveInfoText -match "(?i)\bAll\s+Credentials\b") {
                    $PolicyMatched = $true
                    $RuleName = $Rule.Name
                    if ([string]::IsNullOrWhiteSpace($RuleName)) { $RuleName = $Rule.Identity }
                    $RuleNames += $RuleName
                    $MatchingRules += "$PolicyName / $RuleName"
                }
            }

            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = $PolicyName
            if ($PolicyMatched) {
                $ConfigObject.ConfigItem = "All Credentials SIT detected"
                $ConfigObject.ConfigData = "Matching rules: $($RuleNames -join ', ')"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $ConfigObject.ConfigItem = "All Credentials SIT not detected"
                $ConfigObject.ConfigData = "Enabled policy rules do not reference All Credentials"
                $ConfigObject.InfoText = "Add the All Credentials sensitive information type to an enabled auto-labeling rule for high-risk credential content."
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            }
            $this.AddConfig($ConfigObject)
        }

        if ($EnabledPolicyCount -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Enabled Auto-Labeling Policies"
            $ConfigObject.ConfigItem = "No policies in Enable mode"
            $ConfigObject.ConfigData = "Get-AutoSensitivityLabelPolicy did not return enabled policies"
            $ConfigObject.InfoText = "Enable an auto-labeling policy and include the All Credentials sensitive information type in a rule."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }
        elseif ($MatchingRules.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "<B>Credential Auto-Labeling Gap</B>"
            $ConfigObject.ConfigItem = "No enabled rules reference All Credentials"
            $ConfigObject.ConfigData = "Enabled policies reviewed: $EnabledPolicyCount"
            $ConfigObject.InfoText = "Secure by Default Step 2 recommends prioritizing credential detections because credential leakage can enable rapid compromise."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}
