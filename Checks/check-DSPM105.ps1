using module "..\CAMP.psm1"

class DSPM105 : CAMPCheck {
    <#
        Integrate Microsoft Security Copilot with DSPM investigation
        Based on Microsoft Purview Deployment Models: Deploy and use Data Security Posture Management
    #>

    DSPM105() {
        $this.Control            = "DSPM-105"
        $this.ParentArea         = "Data Security Posture Management"
        $this.Area               = "DSPM"
        $this.Name               = "Integrate Microsoft Security Copilot with DSPM Investigation"
        $this.PassText           = "Your organization uses Microsoft Security Copilot with DSPM investigation"
        $this.FailRecommendation = "Your organization should integrate Microsoft Security Copilot with DSPM investigation"
        $this.Importance         = "DSPM Step 4 recommends using Microsoft Security Copilot to investigate users, activities, and sensitive data risks surfaced by DSPM recommendations. This capability requires Microsoft Security Copilot licensing and appropriate Purview access. DSPM is largely commercial-only in GCCH/DoD at the time of writing, so this check is marked CommercialOnly. Security Copilot helps administrators move from posture findings to guided investigations and policy actions."
        $this.ExpandResults      = $True
        $this.ItemName           = "DSPM Investigation Capability"
        $this.DataType           = "Integration Guidance"

        # Microsoft Purview Deployment Model alignment - REQUIRED for new checks
        $this.Blueprint        = [CAMPBlueprint]::DSPM
        $this.MaturityLevel    = [CAMPMaturityLevel]::Best
        $this.BlueprintStages  = @{ "DSPM" = 4 }

        # Optional but recommended metadata - powers future docs and runtime gating
        $this.RequiredCollections = @()
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft Security Copilot")
        $this.CommercialOnly      = $true

        # Three-way link block - follow this exact pattern (mirrors check-IP106.ps1)
        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "DSPM deployment model"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 4: Investigate with Copilot"  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step4"
                "Microsoft Security Copilot"             = "https://learn.microsoft.com/security-copilot/microsoft-security-copilot"
                "Microsoft Purview portal - DSPM"        = "https://purview.microsoft.com/dspm"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "DSPM deployment model"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 4: Investigate with Copilot"  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step4"
                "Microsoft Security Copilot"             = "https://learn.microsoft.com/security-copilot/microsoft-security-copilot"
                "Microsoft Purview portal - DSPM"        = "https://purview.microsoft.com/dspm"
            }
        }
        else {
            $this.Links = @{
                "DSPM deployment model"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 4: Investigate with Copilot"  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step4"
                "Microsoft Security Copilot"             = "https://learn.microsoft.com/security-copilot/microsoft-security-copilot"
                "Microsoft Purview portal - DSPM"        = "https://purview.microsoft.com/dspm"
            }
        }
    }

    GetResults($Config) {
        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object     = "Microsoft Security Copilot for DSPM"
        $ConfigObject.ConfigItem = "Guided investigation"
        $ConfigObject.ConfigData = "Use Security Copilot prompts and promptbooks during DSPM Step 4 investigations"
        $ConfigObject.InfoText   = "CAMP cannot programmatically verify Security Copilot usage from DSPM. Review Microsoft Security Copilot guidance at https://learn.microsoft.com/security-copilot/microsoft-security-copilot and use the DSPM Step 4 guidance to investigate recommendations, risky users, and sensitive data activity with Copilot."
        $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
        $this.AddConfig($ConfigObject)

        $this.Completed = $true
    }
}
