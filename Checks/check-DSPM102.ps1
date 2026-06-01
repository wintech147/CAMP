using module "..\CAMP.psm1"

class DSPM102 : CAMPCheck {
    <#
        Enable Data Loss Prevention analytics for DSPM
        Based on Microsoft Purview Deployment Models: Deploy and use Data Security Posture Management
    #>

    DSPM102() {
        $this.Control            = "DSPM-102"
        $this.ParentArea         = "Data Security Posture Management"
        $this.Area               = "DSPM"
        $this.Name               = "Enable Data Loss Prevention Analytics"
        $this.PassText           = "Your organization has Data Loss Prevention analytics enabled"
        $this.FailRecommendation = "Your organization should enable Data Loss Prevention analytics"
        $this.Importance         = "DSPM Step 2 requires Data Loss Prevention analytics so DSPM can correlate data activity, surface risk trends, and recommend DLP policy improvements. DLP analytics generally requires Microsoft Purview E5 Compliance capabilities or equivalent licensing. DSPM is largely commercial-only in GCCH/DoD at the time of writing, so this check is marked CommercialOnly. If public PowerShell cmdlets are not available in the tenant, CAMP provides an awareness recommendation instead of failing the control."
        $this.ExpandResults      = $True
        $this.ItemName           = "DLP Analytics Component"
        $this.DataType           = "Enabled State"

        # Microsoft Purview Deployment Model alignment - REQUIRED for new checks
        $this.Blueprint        = [CAMPBlueprint]::DSPM -bor [CAMPBlueprint]::LightweightDLP
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "DSPM" = 2; "LightweightDLP" = 2 }

        # Optional but recommended metadata - powers future docs and runtime gating
        $this.RequiredCollections = @()
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $true

        # Three-way link block - follow this exact pattern (mirrors check-IP106.ps1)
        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "DSPM deployment model"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 2: Configure analytics"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step2"
                "Microsoft Purview portal - DLP analytics" = "https://purview.microsoft.com/dlpanalytics"
                "Get started with DLP analytics"        = "https://learn.microsoft.com/purview/dlp-analytics-get-started"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "DSPM deployment model"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 2: Configure analytics"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step2"
                "Microsoft Purview portal - DLP analytics" = "https://purview.microsoft.com/dlpanalytics"
                "Get started with DLP analytics"        = "https://learn.microsoft.com/purview/dlp-analytics-get-started"
            }
        }
        else {
            $this.Links = @{
                "DSPM deployment model"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 2: Configure analytics"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step2"
                "Microsoft Purview portal - DLP analytics" = "https://purview.microsoft.com/dlpanalytics"
                "Get started with DLP analytics"        = "https://learn.microsoft.com/purview/dlp-analytics-get-started"
            }
        }
    }

    GetResults($Config) {
        $AnalyticsCmdlets = @(
            @{
                Name  = "Get-DlpAnalyticsConfig"
                Label = "DLP analytics"
            }
            @{
                Name  = "Get-DlpAdvancedAnalyticsConfig"
                Label = "DLP advanced analytics"
            }
        )

        $AvailableCmdlets = @()
        foreach ($CommandInfo in $AnalyticsCmdlets) {
            $CommandName = $CommandInfo["Name"]
            if ($null -ne (Get-Command -Name $CommandName -ErrorAction SilentlyContinue)) {
                $AvailableCmdlets += $CommandInfo
            }
        }

        if ($AvailableCmdlets.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "DLP analytics"
            $ConfigObject.ConfigItem = "Public PowerShell cmdlet availability"
            $ConfigObject.ConfigData = "Get-DlpAnalyticsConfig and Get-DlpAdvancedAnalyticsConfig are not available in this session"
            $ConfigObject.InfoText   = "Public cmdlet availability for DLP analytics varies by tenant and service release. Review and enable DLP analytics in Microsoft Purview at https://purview.microsoft.com/dlpanalytics so DSPM Step 2 can use DLP signals for recommendations and reports."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
            $this.AddConfig($ConfigObject)
            $this.Completed = $true
            return
        }

        foreach ($CommandInfo in $AvailableCmdlets) {
            $CommandName = $CommandInfo["Name"]
            $CommandLabel = $CommandInfo["Label"]

            try {
                $AnalyticsConfigs = @(& $CommandName -ErrorAction:Stop)
            }
            catch {
                $this.EmitAwarenessRecommendation(
                    "<B>DLP analytics (manual review)</B>",
                    "$CommandName not available in this tenant",
                    "DLP analytics cmdlet was not found in this Security & Compliance PowerShell session. Error: $($_.Exception.Message)",
                    "Review DLP analytics manually in Microsoft Purview > Data Loss Prevention > Analytics at https://purview.microsoft.com/dlpanalytics. Requires Microsoft 365 E5 Compliance."
                )
                return
            }

            if ($AnalyticsConfigs.Count -eq 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object     = $CommandLabel
                $ConfigObject.ConfigItem = $CommandName
                $ConfigObject.ConfigData = "No configuration returned"
                $ConfigObject.InfoText   = "Review DLP analytics in Microsoft Purview at https://purview.microsoft.com/dlpanalytics and confirm analytics are enabled for DSPM Step 2."
                $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
                $this.AddConfig($ConfigObject)
                continue
            }

            foreach ($AnalyticsConfig in $AnalyticsConfigs) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object     = $CommandLabel
                $ConfigObject.ConfigItem = $CommandName

                $EnabledProperty = $null
                foreach ($PropertyName in @("Enabled", "IsEnabled", "AnalyticsEnabled", "AdvancedAnalyticsEnabled", "ActivateAnalytics")) {
                    if ($null -ne $AnalyticsConfig.PSObject.Properties[$PropertyName]) {
                        $EnabledProperty = $AnalyticsConfig.PSObject.Properties[$PropertyName]
                        break
                    }
                }

                if ($null -eq $EnabledProperty) {
                    $ConfigObject.ConfigData = "Returned configuration, but no enabled-state property was exposed"
                    $ConfigObject.InfoText   = "Review DLP analytics in Microsoft Purview at https://purview.microsoft.com/dlpanalytics. CAMP could not identify an Enabled property in $CommandName output, which can vary by service release."
                    $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
                    $this.AddConfig($ConfigObject)
                    continue
                }

                $EnabledValue = $EnabledProperty.Value
                $EnabledText = "$EnabledValue"
                $AnalyticsEnabled = (($EnabledValue -eq $true) -or ($EnabledText -match "^(Enabled|True|On)$"))
                $ConfigObject.ConfigData = "$($EnabledProperty.Name): $EnabledText"

                if ($AnalyticsEnabled) {
                    $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                }
                else {
                    $ConfigObject.InfoText = "Enable DLP analytics at https://purview.microsoft.com/dlpanalytics. DSPM Step 2 needs DLP analytics to produce risk detection and policy refinement recommendations."
                    $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                }

                $this.AddConfig($ConfigObject)
            }
        }

        $this.Completed = $true
    }
}
