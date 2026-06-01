using module "..\CAMP.psm1"

class DLP207 : CAMPCheck {
    <#

        Adaptive Protection Conditions in DLP Rules
        Based on Microsoft Purview Deployment Models: Lightweight DLP and Secure by Default Blueprints

    #>

    DLP207() {
        $this.Control = "DLP-207"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Data Loss Prevention"
        $this.Name = "Wire Adaptive Protection Conditions into DLP Rules"
        $this.PassText = "Your organization has DLP rules that use Adaptive Protection or insider risk conditions"
        $this.FailRecommendation = "Your organization should wire Adaptive Protection or insider risk conditions into DLP rules"
        $this.Importance = "The Lightweight DLP Step 3 blueprint recommends Adaptive Protection so DLP enforcement can respond to elevated insider risk. This is a Microsoft 365 E5 Compliance capability and should be used to dynamically adjust DLP actions based on insider risk signals."
        $this.ExpandResults = $True
        $this.CheckType = [CheckType]::ObjectPropertyValue
        $this.ObjectType = "DLP Rule"
        $this.ItemName = "Adaptive Protection Condition"
        $this.DataType = "Rule Status"
        $this.Blueprint = [CAMPBlueprint]::LightweightDLP -bor [CAMPBlueprint]::SecureByDefault
        $this.MaturityLevel = [CAMPMaturityLevel]::Best
        $this.BlueprintStages = @{ "LightweightDLP" = 3; "SecureByDefault" = 3 }
        $this.RequiredCollections = @("GetDlpComplianceRule")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly = $false
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Lightweight DLP Step 3"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step3"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-gcch-dlp-compliance-center"
                "Adaptive Protection"                      = "https://learn.microsoft.com/purview/dlp-adaptive-protection-learn"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Lightweight DLP Step 3"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step3"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dod-dlp-compliance-center"
                "Adaptive Protection"                      = "https://learn.microsoft.com/purview/dlp-adaptive-protection-learn"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
            }
        }else
        {
            $this.Links = @{
                "Lightweight DLP Step 3"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step3"
                "Microsoft Purview portal - Data Loss Prevention" = "https://purview.microsoft.com"
                "Adaptive Protection"                      = "https://learn.microsoft.com/purview/dlp-adaptive-protection-learn"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs DLP rules from Security & Compliance PowerShell.")
                return
            }
        }

        $HasNonEmptyValue = {
            param($Value)

            if ($null -eq $Value) {
                return $false
            }

            if ($Value -is [bool]) {
                return $Value
            }

            if ($Value -is [string]) {
                return ($Value.Trim() -ne "" -and $Value -ine "None" -and $Value -ine "False")
            }

            if ($Value -is [System.Collections.IDictionary]) {
                return ($Value.Count -gt 0)
            }

            if ($Value -is [System.Collections.IEnumerable]) {
                $Items = @($Value) | Where-Object { $null -ne $_ -and "$_".Trim() -ne "" -and "$_" -ine "None" -and "$_" -ine "False" }
                return ($Items.Count -gt 0)
            }

            return $true
        }

        $AdaptiveRules = @()
        $AdaptiveConditionNames = @("InsiderRiskTypes", "InsiderRiskLevel", "InsiderRiskLevels", "AdaptiveProtection")

        ForEach ($Rule in $Config["GetDlpComplianceRule"]) {
            $Conditions = @()
            foreach ($ConditionName in $AdaptiveConditionNames) {
                $Property = $Rule.PSObject.Properties[$ConditionName]
                if ($null -ne $Property -and (& $HasNonEmptyValue $Property.Value)) {
                    $ConditionValues = @($Property.Value) | Where-Object { $null -ne $_ -and "$_".Trim() -ne "" }
                    $Conditions += "$ConditionName=$($ConditionValues -join ', ')"
                }
            }

            if ($Conditions.Count -gt 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = $Rule.Name
                $ConfigObject.ConfigItem = $Conditions -join "; "
                $ConfigObject.ConfigData = "Parent policy: $($Rule.ParentPolicyName)"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)

                $AdaptiveRules += $Rule.Name
            }
        }

        if ($AdaptiveRules.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Adaptive Protection DLP Rules"
            $ConfigObject.ConfigItem = "InsiderRiskTypes / InsiderRiskLevel / AdaptiveProtection not found"
            $ConfigObject.ConfigData = "No DLP rule uses Adaptive Protection or insider risk conditions"
            $ConfigObject.InfoText = "Enable Adaptive Protection with Microsoft 365 E5 Compliance and add insider risk conditions to DLP rules so enforcement can respond to elevated user risk."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}

