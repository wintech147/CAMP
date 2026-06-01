using module "..\CAMP.psm1"

class IP109 : CAMPCheck {
    <#
        Configure client-side auto-labeling on confidential sensitivity labels
        Based on Microsoft Purview Deployment Models: Secure by Default and Lightweight DLP Blueprints
    #>

    IP109() {
        $this.Control            = "IP-109"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Information Protection"
        $this.Name               = "Configure Client-Side Auto-Labeling on Highly Confidential Labels"
        $this.PassText           = "Your organization has client-side auto-labeling enabled on at least one Confidential or Highly Confidential sensitivity label"
        $this.FailRecommendation = "Your organization should configure recommended or automatic client-side labeling for Confidential and Highly Confidential sensitivity labels"
        $this.Importance         = "Secure by Default Step 3 recommends using auto-labeling to help users consistently classify sensitive content before it is shared. Client-side recommended or automatic labeling for Confidential and Highly Confidential labels reduces missed classifications while keeping users in the productivity flow. This capability typically requires Microsoft 365 E5 Compliance or equivalent Information Protection advanced licensing."
        $this.ExpandResults      = $True
        $this.ItemName           = "Sensitivity Label"
        $this.DataType           = "Auto-Labeling Status"

        $this.Blueprint        = [CAMPBlueprint]::SecureByDefault -bor [CAMPBlueprint]::LightweightDLP
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "SecureByDefault" = 3; "LightweightDLP" = 3 }
        $this.RequiredCollections = @("GetLabel")
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
                $this.SetUnavailable("Required collection '$key' is not available. This check needs sensitivity label configuration from Get-Label.")
                return
            }
        }

        $ConfidentialLabelCount = 0
        $AutoLabelingLabels = @()
        $LabelsWithoutAutoLabeling = @()

        ForEach ($Label in $Config["GetLabel"]) {
            $LabelName = $Label.DisplayName
            if ([string]::IsNullOrWhiteSpace($LabelName)) {
                $LabelName = $Label.Name
            }

            if ($LabelName -notmatch "(?i)highly.*confidential|confidential") {
                continue
            }

            $ConfidentialLabelCount++
            $HasAutoLabeling = $false
            $Evidence = @()

            if ($null -ne $Label.LabelActions) {
                $ActionText = (@($Label.LabelActions) -join "; ")
                if ($ActionText -match "(?i)auto.?label|recommend.?label|auto.?apply") {
                    $HasAutoLabeling = $true
                    $Evidence += "LabelActions include auto-labeling"
                }
            }

            foreach ($Property in $Label.PSObject.Properties) {
                if ($Property.Name -match "(?i)^(RecommendLabel|AutoApplyType|AutoLabeling.+|AutoSensitivity.+|AutoApply.+)$") {
                    $ValueText = (@($Property.Value) -join "; ")
                    if (-not [string]::IsNullOrWhiteSpace($ValueText) -and
                        $ValueText -notmatch "(?i)^(false|none|disabled|null)$" -and
                        $Property.Name -notmatch "(?i)^AutoLabelOnlyServiceClient$") {
                        $HasAutoLabeling = $true
                        $Evidence += "$($Property.Name) is configured"
                    }
                }
            }

            if ($null -ne $Label.Settings) {
                foreach ($Setting in @($Label.Settings)) {
                    if ($Setting -match "(?i)(RecommendLabel|AutoApplyType|AutoLabeling|AutoSensitivity)" -and
                        $Setting -notmatch "(?i):(false|none|disabled|null)\s*$") {
                        $HasAutoLabeling = $true
                        $Evidence += "Advanced setting $Setting"
                    }
                }
            }

            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = $LabelName
            if ($HasAutoLabeling) {
                $AutoLabelingLabels += $LabelName
                $ConfigObject.ConfigItem = "Client-side auto-labeling configured"
                $ConfigObject.ConfigData = ($Evidence | Select-Object -Unique) -join "; "
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $LabelsWithoutAutoLabeling += $LabelName
                $ConfigObject.ConfigItem = "Client-side auto-labeling not detected"
                $ConfigObject.ConfigData = "No recommendation or auto-apply settings were found"
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            }
            $this.AddConfig($ConfigObject)
        }

        if ($ConfidentialLabelCount -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Confidential Labels"
            $ConfigObject.ConfigItem = "No Confidential or Highly Confidential labels found"
            $ConfigObject.ConfigData = "Your sensitivity label taxonomy does not include labels matching Confidential or Highly Confidential"
            $ConfigObject.InfoText = "Create Confidential and Highly Confidential labels, then configure recommended or automatic client-side labeling for content that matches sensitive information conditions."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }
        elseif ($AutoLabelingLabels.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "<B>Secure by Default Recommendation</B>"
            $ConfigObject.ConfigItem = "No Confidential labels have client-side auto-labeling"
            $ConfigObject.ConfigData = "Labels reviewed: $($LabelsWithoutAutoLabeling -join ', ')"
            $ConfigObject.InfoText = "Secure by Default Step 3 recommends configuring recommended or automatic labeling so sensitive content is classified in Office apps before it is shared."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}
