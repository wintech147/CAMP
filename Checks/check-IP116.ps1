using module "..\CAMP.psm1"

class IP116 : CAMPCheck {
    <#
        Keep label mismatch email notifications enabled
        Based on Microsoft Purview Deployment Models: Secure by Default Blueprint
    #>

    IP116() {
        $this.Control            = "IP-116"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Information Protection"
        $this.Name               = "Keep Label Mismatch Email Notifications Enabled"
        $this.PassText           = "Your organization keeps label mismatch email notifications enabled"
        $this.FailRecommendation = "Your organization should keep label mismatch email notifications enabled by leaving BlockSendLabelMismatchEmail set to False"
        $this.Importance         = "Secure by Default Step 1 prerequisites encourage user-facing signals that prevent accidental mishandling of protected content. Label mismatch notifications warn users when an email label and attachment label do not align, reducing risky sends without changing tenant state. This sensitivity labeling capability generally requires Microsoft 365 E3 with Information Protection and Governance or equivalent licensing."
        $this.ExpandResults      = $True
        $this.ItemName           = "Policy Setting"
        $this.DataType           = "Mismatch Notification Status"

        $this.Blueprint        = [CAMPBlueprint]::SecureByDefault
        $this.MaturityLevel    = [CAMPMaturityLevel]::Good
        $this.BlueprintStages  = @{ "SecureByDefault" = 1 }
        $this.RequiredCollections = @()
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E3 + Information Protection and Governance")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.microsoft.us"
                "Sensitivity label policy settings"               = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps#what-label-policies-can-do"
                "Manage sensitivity labels in Office apps"         = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.apps.mil"
                "Sensitivity label policy settings"               = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps#what-label-policies-can-do"
                "Manage sensitivity labels in Office apps"         = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
        else {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://purview.microsoft.com"
                "Sensitivity label policy settings"               = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps#what-label-policies-can-do"
                "Manage sensitivity labels in Office apps"         = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
    }

    GetResults($Config) {
        $ValuesFound = @()
        $Sources = @()
        $PolicyConfigError = ""

        try {
            $PolicyConfig = Get-PolicyConfig -ErrorAction:Stop
            foreach ($Property in $PolicyConfig.PSObject.Properties) {
                if ($Property.Name -ieq "BlockSendLabelMismatchEmail") {
                    $ValuesFound += $Property.Value
                    $Sources += "Get-PolicyConfig"
                }
            }
        }
        catch {
            $PolicyConfigError = $_.Exception.Message
        }

        if ($ValuesFound.Count -eq 0) {
            try {
                $Labels = Get-Label -ErrorAction:Stop
            }
            catch {
                $this.EmitAwarenessRecommendation(
                    "<B>Label mismatch email (manual review)</B>",
                    "BlockSendLabelMismatchEmail not exposed",
                    "Neither Get-PolicyConfig nor Get-Label returned the BlockSendLabelMismatchEmail property. Get-PolicyConfig error: $PolicyConfigError",
                    "Confirm BlockSendLabelMismatchEmail is False in Microsoft Purview > Information Protection > Label policies > Settings. The default is False (mismatch emails enabled)."
                )
                return
            }

            foreach ($Label in @($Labels)) {
                $Identity = $Label.Identity
                if ([string]::IsNullOrWhiteSpace($Identity)) { $Identity = $Label.Name }
                if ([string]::IsNullOrWhiteSpace($Identity)) { continue }

                try {
                    $DetailedLabel = Get-Label -Identity $Identity -ErrorAction:Stop
                }
                catch {
                    $DetailedLabel = $Label
                }

                foreach ($Property in $DetailedLabel.PSObject.Properties) {
                    if ($Property.Name -ieq "BlockSendLabelMismatchEmail") {
                        $ValuesFound += $Property.Value
                        $Sources += "Get-Label:$Identity"
                    }
                }
                foreach ($Setting in @($DetailedLabel.Settings)) {
                    if ($Setting -match "(?i)BlockSendLabelMismatchEmail\s*[:=]\s*(True|False)") {
                        $ValuesFound += $Matches[1]
                        $Sources += "Get-Label:$Identity"
                    }
                }
            }
        }

        if ($ValuesFound.Count -eq 0) {
            $this.EmitAwarenessRecommendation(
                "<B>Label mismatch email (manual review)</B>",
                "BlockSendLabelMismatchEmail not exposed",
                "Neither Get-PolicyConfig nor Get-Label returned BlockSendLabelMismatchEmail for this tenant or module version.",
                "Confirm BlockSendLabelMismatchEmail is False in Microsoft Purview > Information Protection > Label policies > Settings. The default is False (mismatch emails enabled)."
            )
            return
        }

        $BlocksMismatchEmail = $false
        foreach ($Value in $ValuesFound) {
            if ($Value -eq $true -or "$Value" -ieq "True") {
                $BlocksMismatchEmail = $true
            }
        }

        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object = "BlockSendLabelMismatchEmail"
        $ConfigObject.ConfigItem = "Sources: $((($Sources | Select-Object -Unique) -join ', '))"
        $ConfigObject.ConfigData = "Values: $($ValuesFound -join ', ')"
        if ($BlocksMismatchEmail) {
            $ConfigObject.InfoText = "Set BlockSendLabelMismatchEmail to False so users receive mismatch notifications when email and attachment labels do not align."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
        }
        else {
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
        }
        $this.AddConfig($ConfigObject)

        $this.Completed = $true
    }
}
