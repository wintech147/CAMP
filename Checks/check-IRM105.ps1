using module "..\CAMP.psm1"

class IRM105 : CAMPCheck {
    <#
        Enable Insider Risk Management analytics
        Based on Microsoft Purview Deployment Models: Secure by Default, Lightweight DLP, and DSPM Blueprints
    #>

    IRM105() {
        $this.Control            = "IRM-105"
        $this.ParentArea         = "Insider Risk"
        $this.Area               = "Insider Risk Management"
        $this.Name               = "Enable Insider Risk Management Analytics"
        $this.PassText           = "Your organization has Insider Risk Management analytics enabled"
        $this.FailRecommendation = "Your organization should enable Insider Risk Management analytics"
        $this.Importance         = "Secure by Default Step 1 prerequisites include understanding data risk signals before expanding enforcement. Insider Risk Management analytics helps identify potential risky activity patterns and informs Lightweight DLP and DSPM prioritization. This check requires Microsoft 365 E5 Compliance licensing and the Insider Risk Management insights cmdlet to be available."
        $this.ExpandResults      = $True
        $this.ItemName           = "Insider Risk Analytics"
        $this.DataType           = "Analytics Status"

        $this.Blueprint        = [CAMPBlueprint]::SecureByDefault -bor [CAMPBlueprint]::LightweightDLP -bor [CAMPBlueprint]::DSPM
        $this.MaturityLevel    = [CAMPMaturityLevel]::Good
        $this.BlueprintStages  = @{ "SecureByDefault" = 1; "LightweightDLP" = 3 }
        $this.RequiredCollections = @()
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Insider Risk Management" = "https://compliance.microsoft.us"
                "Insider risk analytics"                      = "https://learn.microsoft.com/purview/insider-risk-management-settings-analytics"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Insider Risk Management" = "https://compliance.apps.mil"
                "Insider risk analytics"                      = "https://learn.microsoft.com/purview/insider-risk-management-settings-analytics"
            }
        }
        else {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Insider Risk Management" = "https://purview.microsoft.com"
                "Insider risk analytics"                      = "https://learn.microsoft.com/purview/insider-risk-management-settings-analytics"
            }
        }
    }

    GetResults($Config) {
        try {
            $InsightsConfig = Get-InsiderRiskInsightsConfig -ErrorAction:Stop
        }
        catch {
            $this.EmitAwarenessRecommendation(
                "<B>Insider Risk Management analytics (manual review)</B>",
                "Cannot verify via PowerShell in this tenant",
                "Get-InsiderRiskInsightsConfig was not available in this Security & Compliance PowerShell session.",
                "Enable Insider Risk Management analytics manually in Microsoft Purview > Insider Risk Management > Settings > Analytics. Requires the Insider Risk Management Admin role and Microsoft 365 E5 Compliance."
            )
            return
        }

        $StatusValues = @()
        $AnalyticsEnabled = $false
        $RecognizedProperty = $false

        foreach ($PropertyName in @("Enabled", "IsEnabled", "AnalyticsEnabled", "IsAnalyticsEnabled", "InsightsEnabled", "IsInsightsEnabled", "EnableAnalytics")) {
            $Property = $InsightsConfig.PSObject.Properties[$PropertyName]
            if ($null -ne $Property) {
                $RecognizedProperty = $true
                $StatusValues += "$PropertyName=$($Property.Value)"
                if ($Property.Value -eq $true -or "$($Property.Value)" -ieq "True") {
                    $AnalyticsEnabled = $true
                }
            }
        }

        foreach ($PropertyName in @("State", "Status", "Mode")) {
            $Property = $InsightsConfig.PSObject.Properties[$PropertyName]
            if ($null -ne $Property) {
                $RecognizedProperty = $true
                $StatusValues += "$PropertyName=$($Property.Value)"
                if ("$($Property.Value)" -match "(?i)^Enable(d)?$") {
                    $AnalyticsEnabled = $true
                }
            }
        }

        if (-not $RecognizedProperty) {
            $this.EmitAwarenessRecommendation(
                "<B>Insider Risk Management analytics (manual review)</B>",
                "Cannot verify analytics-enabled property",
                "Get-InsiderRiskInsightsConfig returned data but no recognized enabled-state property.",
                "Review Insider Risk Management analytics manually in Microsoft Purview > Insider Risk Management > Settings > Analytics."
            )
            return
        }

        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object = "Insider Risk Insights Configuration"
        $ConfigObject.ConfigItem = "Analytics configuration"
        $ConfigObject.ConfigData = ($StatusValues | Select-Object -Unique) -join "; "
        if ($AnalyticsEnabled) {
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
        }
        else {
            $ConfigObject.InfoText = "Enable Insider Risk Management analytics to generate baseline insights and prioritize risk reduction work."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
        }
        $this.AddConfig($ConfigObject)

        $this.Completed = $true
    }
}
