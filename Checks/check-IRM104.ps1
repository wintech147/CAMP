using module "..\CAMP.psm1"

class IRM104 : CAMPCheck {
    <#
        Enable Adaptive Protection in Insider Risk Management
        Based on Microsoft Purview Deployment Models: Secure by Default and Lightweight DLP Blueprints
    #>

    IRM104() {
        $this.Control            = "IRM-104"
        $this.ParentArea         = "Insider Risk"
        $this.Area               = "Insider Risk Management"
        $this.Name               = "Enable Adaptive Protection in Insider Risk Management"
        $this.PassText           = "Your organization has an enabled Insider Risk Management Adaptive Protection policy"
        $this.FailRecommendation = "Your organization should enable Adaptive Protection in Insider Risk Management"
        $this.Importance         = "Secure by Default Step 2 and Lightweight DLP Step 3 recommend adaptive controls that increase protection when user risk is elevated. Insider Risk Management Adaptive Protection can dynamically inform DLP and other controls with risk context. This check requires Microsoft 365 E5 Compliance licensing and the Insider Risk Management cmdlets to be available."
        $this.ExpandResults      = $True
        $this.ItemName           = "Adaptive Protection Policy"
        $this.DataType           = "Enabled Status"

        $this.Blueprint        = [CAMPBlueprint]::SecureByDefault -bor [CAMPBlueprint]::LightweightDLP
        $this.MaturityLevel    = [CAMPMaturityLevel]::Best
        $this.BlueprintStages  = @{ "SecureByDefault" = 2; "LightweightDLP" = 3 }
        $this.RequiredCollections = @()
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Insider Risk Management" = "https://compliance.microsoft.us"
                "Learn about adaptive protection"             = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Insider Risk Management" = "https://compliance.apps.mil"
                "Learn about adaptive protection"             = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection"
            }
        }
        else {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Insider Risk Management" = "https://purview.microsoft.com"
                "Learn about adaptive protection"             = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection"
            }
        }
    }

    GetResults($Config) {
        # Try the (preview) cmdlet first — if/when Microsoft ships it in commercial
        # Security & Compliance PowerShell this check upgrades to a real programmatic
        # verification. Until then, fall back to an awareness-style Recommendation
        # pointing the admin at the portal, so the check still surfaces in the report
        # instead of disappearing into the "Not assessed" section.
        $Policies = $null
        $CmdletAvailable = $false
        try {
            $Policies = Get-InsiderRiskAdaptiveProtectionPolicy -ErrorAction:Stop
            $CmdletAvailable = $true
        }
        catch {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "<B>Adaptive Protection (manual review)</B>"
            $ConfigObject.ConfigItem = "Cannot verify via PowerShell in this tenant"
            $ConfigObject.ConfigData = "Get-InsiderRiskAdaptiveProtectionPolicy not available in this Security & Compliance PowerShell session."
            $ConfigObject.InfoText   = "Review Adaptive Protection manually in the Microsoft Purview portal: Insider Risk Management > Adaptive Protection. Confirm an Adaptive Protection policy exists and is enabled. Requires Microsoft 365 E5 Compliance."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            $this.AddConfig($ConfigObject)
            $this.Completed = $true
            return
        }

        $EnabledPolicies = @()

        foreach ($Policy in @($Policies)) {
            $PolicyName = $Policy.Name
            if ([string]::IsNullOrWhiteSpace($PolicyName)) { $PolicyName = $Policy.Identity }
            $StatusValues = @()
            foreach ($PropertyName in @("Enabled", "IsEnabled", "State", "Status", "Mode")) {
                $Property = $Policy.PSObject.Properties[$PropertyName]
                if ($null -ne $Property) { $StatusValues += "$PropertyName=$($Property.Value)" }
            }
            $StatusText = $StatusValues -join "; "
            $IsEnabled = ($Policy.Enabled -eq $true -or "$($Policy.Enabled)" -ieq "True" -or "$($Policy.IsEnabled)" -ieq "True" -or "$($Policy.State)" -match "(?i)^Enabled$" -or "$($Policy.Status)" -match "(?i)^Enabled$" -or "$($Policy.Mode)" -match "(?i)^Enable(d)?$")

            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = $PolicyName
            $ConfigObject.ConfigItem = "Adaptive Protection policy status"
            if ([string]::IsNullOrWhiteSpace($StatusText)) { $StatusText = "No status properties returned" }
            $ConfigObject.ConfigData = $StatusText
            if ($IsEnabled) {
                $EnabledPolicies += $PolicyName
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $ConfigObject.InfoText = "Enable Adaptive Protection so elevated insider risk can drive stronger data protection controls."
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            }
            $this.AddConfig($ConfigObject)
        }

        if (@($Policies).Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Adaptive Protection Policies"
            $ConfigObject.ConfigItem = "No Insider Risk Adaptive Protection policies found"
            $ConfigObject.ConfigData = "Get-InsiderRiskAdaptiveProtectionPolicy returned no policies"
            $ConfigObject.InfoText = "Create and enable an Adaptive Protection policy in Insider Risk Management."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }
        elseif ($EnabledPolicies.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "<B>Adaptive Protection Recommendation</B>"
            $ConfigObject.ConfigItem = "No enabled Adaptive Protection policy found"
            $ConfigObject.ConfigData = "Policies reviewed: $(@($Policies).Count)"
            $ConfigObject.InfoText = "Secure by Default and Lightweight DLP recommend enabling Adaptive Protection to connect insider risk context with data protection enforcement."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}
