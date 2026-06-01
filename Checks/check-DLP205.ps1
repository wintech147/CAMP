using module "..\CAMP.psm1"

class DLP205 : CAMPCheck {
    <#

        DLP Actions for Unlabeled Sensitive Content
        Based on Microsoft Purview Deployment Models: Secure by Default and Lightweight DLP Blueprints

    #>

    DLP205() {
        $this.Control = "DLP-205"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Data Loss Prevention"
        $this.Name = "Restrict DLP Actions on Unlabeled Sensitive Content"
        $this.PassText = "Your organization has DLP rules that restrict unlabeled or scan-limited sensitive content"
        $this.FailRecommendation = "Your organization should configure DLP rules that restrict unlabeled or scan-limited sensitive content"
        $this.Importance = "Secure by Default Step 2 and the Lightweight DLP Step 2 blueprint recommend using DLP actions when sensitive content is unlabeled, cannot be fully scanned, or is detected in Exchange or endpoint locations. Core DLP is available with Microsoft 365 Business Premium and E3+IPG licensing; endpoint and advanced DLP capabilities may require Microsoft 365 E5 Compliance."
        $this.ExpandResults = $True
        $this.CheckType = [CheckType]::ObjectPropertyValue
        $this.ObjectType = "DLP Rule"
        $this.ItemName = "Rule Condition"
        $this.DataType = "Protected Workload"
        $this.Blueprint = [CAMPBlueprint]::SecureByDefault -bor [CAMPBlueprint]::LightweightDLP
        $this.MaturityLevel = [CAMPMaturityLevel]::Better
        $this.BlueprintStages = @{ "SecureByDefault" = 2; "LightweightDLP" = 2 }
        $this.RequiredCollections = @("GetDlpComplianceRule", "GetDlpCompliancePolicy")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses = @()
        $this.CommercialOnly = $false
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure by Default Step 2"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-step2"
                "Lightweight DLP Step 2"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-gcch-dlp-compliance-center"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Endpoint DLP getting started"             = "https://learn.microsoft.com/purview/endpoint-dlp-getting-started"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure by Default Step 2"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-step2"
                "Lightweight DLP Step 2"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dod-dlp-compliance-center"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Endpoint DLP getting started"             = "https://learn.microsoft.com/purview/endpoint-dlp-getting-started"
            }
        }else
        {
            $this.Links = @{
                "Secure by Default Step 2"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-step2"
                "Lightweight DLP Step 2"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2"
                "Microsoft Purview portal - Data Loss Prevention" = "https://purview.microsoft.com"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Endpoint DLP getting started"             = "https://learn.microsoft.com/purview/endpoint-dlp-getting-started"
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

        $HasLocation = {
            param($Value)

            $Items = @($Value) | Where-Object { $null -ne $_ -and "$_".Trim() -ne "" -and "$_" -ine "None" }
            return ($Items.Count -gt 0)
        }

        $PoliciesByName = @{}
        ForEach ($CompliancePolicy in $Config["GetDlpCompliancePolicy"]) {
            if ($null -ne $CompliancePolicy.Name -and "$($CompliancePolicy.Name)".Trim() -ne "") {
                $PoliciesByName["$($CompliancePolicy.Name)"] = $CompliancePolicy
            }
        }

        $MatchingRules = @()

        ForEach ($Rule in $Config["GetDlpComplianceRule"]) {
            $ParentPolicy = $null
            if ($null -ne $Rule.ParentPolicyName -and $PoliciesByName.ContainsKey("$($Rule.ParentPolicyName)")) {
                $ParentPolicy = $PoliciesByName["$($Rule.ParentPolicyName)"]
            }

            $HasExchangeOrEndpointLocation = $false
            $Workloads = @()
            if ($null -ne $ParentPolicy) {
                if (& $HasLocation $ParentPolicy.ExchangeLocation) {
                    $HasExchangeOrEndpointLocation = $true
                    $Workloads += "Exchange"
                }

                if (& $HasLocation $ParentPolicy.EndpointDlpLocation) {
                    $HasExchangeOrEndpointLocation = $true
                    $Workloads += "Endpoint"
                }
            }

            $ContentIsNotLabeled = $null
            if ($null -ne $Rule.PSObject.Properties["ContentIsNotLabeled"]) {
                $ContentIsNotLabeled = $Rule.PSObject.Properties["ContentIsNotLabeled"].Value
            }

            $ProcessingLimitExceeded = $null
            if ($null -ne $Rule.PSObject.Properties["ProcessingLimitExceeded"]) {
                $ProcessingLimitExceeded = $Rule.PSObject.Properties["ProcessingLimitExceeded"].Value
            }

            $HasContentIsNotLabeled = & $HasNonEmptyValue $ContentIsNotLabeled
            $HasProcessingLimitExceeded = & $HasNonEmptyValue $ProcessingLimitExceeded
            $HasSensitiveInfo = & $HasNonEmptyValue $Rule.ContentContainsSensitiveInformation
            $Conditions = @()

            if ($HasContentIsNotLabeled) {
                $Conditions += "ContentIsNotLabeled"
            }

            if ($HasProcessingLimitExceeded) {
                $Conditions += "ProcessingLimitExceeded"
            }

            if ($HasSensitiveInfo -and $HasExchangeOrEndpointLocation) {
                $Conditions += "Sensitive information in Exchange/Endpoint policy"
            }

            if ($Conditions.Count -gt 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = $Rule.Name
                $ConfigObject.ConfigItem = $Conditions -join ", "
                if ($Workloads.Count -gt 0) {
                    $ConfigObject.ConfigData = "Parent policy '$($Rule.ParentPolicyName)' covers: $($Workloads -join ', ')"
                }
                else {
                    $ConfigObject.ConfigData = "Rule contains an unlabeled or processing-limit condition"
                }
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)

                $MatchingRules += $Rule.Name
            }
        }

        if ($MatchingRules.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Unlabeled Sensitive Content DLP Rule"
            $ConfigObject.ConfigItem = "ContentIsNotLabeled / ProcessingLimitExceeded not found"
            $ConfigObject.ConfigData = "No DLP rule targets unlabeled content, processing-limit exceeded content, or sensitive information in Exchange or Endpoint DLP policies"
            $ConfigObject.InfoText = "Add DLP rule conditions for content that is not labeled or could not be fully scanned, or enforce sensitive information rules in Exchange and Endpoint DLP locations."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}
