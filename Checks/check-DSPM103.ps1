using module "..\CAMP.psm1"

class DSPM103 : CAMPCheck {
    <#
        Confirm Insider Risk Management analytics for DSPM
        Based on Microsoft Purview Deployment Models: Deploy and use Data Security Posture Management
    #>

    DSPM103() {
        $this.Control            = "DSPM-103"
        $this.ParentArea         = "Data Security Posture Management"
        $this.Area               = "DSPM"
        $this.Name               = "Confirm Insider Risk Management Analytics is Enabled (DSPM Prerequisite)"
        $this.PassText           = "Your organization has Insider Risk Management analytics enabled for DSPM"
        $this.FailRecommendation = "Your organization should enable Insider Risk Management analytics for DSPM"
        $this.Importance         = "DSPM Step 2 requires Insider Risk Management analytics so DSPM can correlate user risk activity with sensitive data exposure. Insider Risk Management analytics generally requires Microsoft Purview E5 Compliance capabilities or equivalent licensing. DSPM is largely commercial-only in GCCH/DoD at the time of writing, so this check is marked CommercialOnly. This DSPM-tagged check intentionally surfaces the same analytics prerequisite independently for the DSPM scorecard."
        $this.ExpandResults      = $True
        $this.ItemName           = "IRM Analytics Component"
        $this.DataType           = "Enabled State"

        # Microsoft Purview Deployment Model alignment - REQUIRED for new checks
        $this.Blueprint        = [CAMPBlueprint]::DSPM
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "DSPM" = 2 }

        # Optional but recommended metadata - powers future docs and runtime gating
        $this.RequiredCollections = @()
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $true

        # Three-way link block - follow this exact pattern (mirrors check-IP106.ps1)
        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "DSPM deployment model"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 2: Configure analytics"         = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step2"
                "Microsoft Purview portal - DSPM"          = "https://purview.microsoft.com/dspm"
                "Insider Risk Management analytics"        = "https://learn.microsoft.com/purview/insider-risk-management-settings-analytics"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "DSPM deployment model"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 2: Configure analytics"         = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step2"
                "Microsoft Purview portal - DSPM"          = "https://purview.microsoft.com/dspm"
                "Insider Risk Management analytics"        = "https://learn.microsoft.com/purview/insider-risk-management-settings-analytics"
            }
        }
        else {
            $this.Links = @{
                "DSPM deployment model"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 2: Configure analytics"         = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step2"
                "Microsoft Purview portal - DSPM"          = "https://purview.microsoft.com/dspm"
                "Insider Risk Management analytics"        = "https://learn.microsoft.com/purview/insider-risk-management-settings-analytics"
            }
        }
    }

    GetResults($Config) {
        try {
            $InsightsConfigs = @(Get-InsiderRiskInsightsConfig -ErrorAction:Stop)
        }
        catch {
            $this.EmitAwarenessRecommendation(
                "<B>Insider Risk Management analytics (manual review)</B>",
                "Cannot verify via PowerShell in this tenant",
                "Get-InsiderRiskInsightsConfig was not available. Error: $($_.Exception.Message)",
                "Confirm Insider Risk Management analytics are enabled in Microsoft Purview > Insider Risk Management > Settings > Analytics. Requires the Insider Risk Management Admin role and Microsoft 365 E5 Compliance."
            )
            return
        }

        if ($InsightsConfigs.Count -eq 0) {
            $this.EmitAwarenessRecommendation(
                "<B>Insider Risk Management analytics (manual review)</B>",
                "Get-InsiderRiskInsightsConfig returned no configuration",
                "Cmdlet ran but no analytics configuration was returned.",
                "Confirm Insider Risk Management analytics are enabled in Microsoft Purview > Insider Risk Management > Settings > Analytics."
            )
            return
        }

        foreach ($InsightsConfig in $InsightsConfigs) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "Insider Risk Management analytics"
            $ConfigObject.ConfigItem = "Get-InsiderRiskInsightsConfig"

            $EnabledProperty = $null
            foreach ($PropertyName in @("Enabled", "IsEnabled", "AnalyticsEnabled", "InsightsEnabled", "IsInsightsEnabled")) {
                if ($null -ne $InsightsConfig.PSObject.Properties[$PropertyName]) {
                    $EnabledProperty = $InsightsConfig.PSObject.Properties[$PropertyName]
                    break
                }
            }

            if ($null -eq $EnabledProperty) {
                $this.EmitAwarenessRecommendation(
                    "<B>Insider Risk Management analytics (manual review)</B>",
                    "Cannot identify enabled-state property",
                    "Get-InsiderRiskInsightsConfig returned data, but CAMP could not identify an enabled-state property.",
                    "Review the cmdlet output with Format-List * and confirm Insider Risk Management analytics manually in Microsoft Purview > Insider Risk Management > Settings > Analytics."
                )
                return
            }

            $EnabledValue = $EnabledProperty.Value
            $EnabledText = "$EnabledValue"
            $AnalyticsEnabled = (($EnabledValue -eq $true) -or ($EnabledText -match "^(Enabled|True|On)$"))
            $ConfigObject.ConfigData = "$($EnabledProperty.Name): $EnabledText"

            if ($AnalyticsEnabled) {
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $ConfigObject.InfoText = "Enable Insider Risk Management analytics in Microsoft Purview settings. DSPM Step 2 needs Insider Risk analytics to identify risky user activity involving sensitive data."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            }

            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}
