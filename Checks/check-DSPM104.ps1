using module "..\CAMP.psm1"

class DSPM104 : CAMPCheck {
    <#
        Review DSPM recommendations and reports regularly
        Based on Microsoft Purview Deployment Models: Deploy and use Data Security Posture Management
    #>

    DSPM104() {
        $this.Control            = "DSPM-104"
        $this.ParentArea         = "Data Security Posture Management"
        $this.Area               = "DSPM"
        $this.Name               = "Review DSPM Recommendations and Reports Regularly"
        $this.PassText           = "Your organization reviews DSPM recommendations and reports regularly"
        $this.FailRecommendation = "Your organization should review DSPM recommendations and reports regularly"
        $this.Importance         = "DSPM Step 3 directs administrators to review DSPM reports, trends, and recommendations to understand unprotected sensitive assets and risky user activity. Step 4 turns that review into action by creating or updating DLP and Insider Risk Management policies from recommendations. DSPM generally requires Microsoft Purview E5 Compliance capabilities or equivalent licensing. DSPM is largely commercial-only in GCCH/DoD at the time of writing, so this check is marked CommercialOnly."
        $this.ExpandResults      = $True
        $this.ItemName           = "DSPM Review Area"
        $this.DataType           = "Review Guidance"

        # Microsoft Purview Deployment Model alignment - REQUIRED for new checks
        $this.Blueprint        = [CAMPBlueprint]::DSPM
        $this.MaturityLevel    = [CAMPMaturityLevel]::Best
        $this.BlueprintStages  = @{ "DSPM" = 3 }

        # Optional but recommended metadata - powers future docs and runtime gating
        $this.RequiredCollections = @()
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $true

        # Three-way link block - follow this exact pattern (mirrors check-IP106.ps1)
        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "DSPM deployment model"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 3: Understand risks"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step3"
                "DSPM Step 4: Take action"               = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step4"
                "Microsoft Purview portal - DSPM"        = "https://purview.microsoft.com/dspm"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "DSPM deployment model"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 3: Understand risks"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step3"
                "DSPM Step 4: Take action"               = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step4"
                "Microsoft Purview portal - DSPM"        = "https://purview.microsoft.com/dspm"
            }
        }
        else {
            $this.Links = @{
                "DSPM deployment model"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 3: Understand risks"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step3"
                "DSPM Step 4: Take action"               = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step4"
                "Microsoft Purview portal - DSPM"        = "https://purview.microsoft.com/dspm"
            }
        }
    }

    GetResults($Config) {
        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object     = "DSPM recommendations and reports"
        $ConfigObject.ConfigItem = "Manual review cadence"
        $ConfigObject.ConfigData = "Review DSPM recommendations, reports, and trends at least every 30 days"
        $ConfigObject.InfoText   = "CAMP cannot programmatically verify that a human reviewed DSPM recommendations. Review the DSPM dashboard at https://purview.microsoft.com/dspm, use Step 3 guidance to understand reports and recommendations, and use Step 4 guidance to create or update DLP and Insider Risk Management policies from those recommendations."
        $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
        $this.AddConfig($ConfigObject)

        $this.Completed = $true
    }
}
