using module "..\CAMP.psm1"

class IP111 : CAMPCheck {
    <#
        Enable label inheritance from email attachments
        Based on Microsoft Purview Deployment Models: Secure by Default, Lightweight DLP, and Copilot Agents Blueprints
    #>

    IP111() {
        $this.Control            = "IP-111"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Information Protection"
        $this.Name               = "Enable Label Inheritance from Email Attachments"
        $this.PassText           = "Your organization has label inheritance enabled in at least one sensitivity label policy"
        $this.FailRecommendation = "Your organization should enable label inheritance from email attachments in sensitivity label policies"
        $this.Importance         = "Secure by Default Step 1 highlights label policy prerequisites that preserve protection as content moves between files, email, and collaboration experiences. Label inheritance from email attachments helps reduce accidental downgrades when users send protected content. This baseline sensitivity labeling capability generally requires Microsoft 365 E3 with Information Protection and Governance or equivalent licensing."
        $this.ExpandResults      = $True
        $this.ItemName           = "Label Policy"
        $this.DataType           = "Inheritance Setting"

        $this.Blueprint        = [CAMPBlueprint]::SecureByDefault -bor [CAMPBlueprint]::LightweightDLP -bor [CAMPBlueprint]::CopilotAgents
        $this.MaturityLevel    = [CAMPMaturityLevel]::Good
        $this.BlueprintStages  = @{ "SecureByDefault" = 1; "LightweightDLP" = 3 }
        $this.RequiredCollections = @("GetLabelPolicy")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E3 + Information Protection and Governance")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.microsoft.us"
                "Sensitivity label policy settings"               = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps#what-label-policies-can-do"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.apps.mil"
                "Sensitivity label policy settings"               = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps#what-label-policies-can-do"
            }
        }
        else {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://purview.microsoft.com"
                "Sensitivity label policy settings"               = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps#what-label-policies-can-do"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs sensitivity label policy settings from Get-LabelPolicy.")
                return
            }
        }

        $EnabledPolicyCount = 0
        $PoliciesWithInheritance = @()

        ForEach ($Policy in $Config["GetLabelPolicy"]) {
            $IsEnabled = ($Policy.Enabled -eq $true -or "$($Policy.Enabled)" -ieq "True")
            if (-not $IsEnabled) {
                continue
            }

            $EnabledPolicyCount++
            $PolicyName = $Policy.Name
            $InheritanceEnabled = $false
            $Evidence = @()

            foreach ($Setting in @($Policy.Settings)) {
                if ($Setting -match "(?i)(EnableLabelInheritance|EnableContainerSupport)\s*[:=]\s*True") {
                    $InheritanceEnabled = $true
                    $Evidence += $Setting
                }
            }

            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = $PolicyName
            if ($InheritanceEnabled) {
                $PoliciesWithInheritance += $PolicyName
                $ConfigObject.ConfigItem = "Label inheritance enabled"
                $ConfigObject.ConfigData = ($Evidence | Select-Object -Unique) -join "; "
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $ConfigObject.ConfigItem = "Label inheritance not detected"
                $ConfigObject.ConfigData = "EnableLabelInheritance or EnableContainerSupport was not True"
                $ConfigObject.InfoText = "Enable label inheritance in this policy so email and attachment labeling remain aligned."
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            }
            $this.AddConfig($ConfigObject)
        }

        if ($EnabledPolicyCount -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Enabled Label Policies"
            $ConfigObject.ConfigItem = "No enabled sensitivity label policies found"
            $ConfigObject.ConfigData = "Get-LabelPolicy did not return an enabled policy"
            $ConfigObject.InfoText = "Create or enable a sensitivity label policy, then turn on label inheritance for email attachment scenarios."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }
        elseif ($PoliciesWithInheritance.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "<B>Secure by Default Recommendation</B>"
            $ConfigObject.ConfigItem = "No enabled policy has label inheritance"
            $ConfigObject.ConfigData = "Enabled policies reviewed: $EnabledPolicyCount"
            $ConfigObject.InfoText = "Secure by Default Step 1 recommends enabling label policy prerequisites that preserve labels across email, attachments, sites, and Teams."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}
