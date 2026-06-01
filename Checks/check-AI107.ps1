using module "..\CAMP.psm1"

class AI107 : CAMPCheck {
    <#
        Use Intune app protection policies to limit managed data flow to AI apps
        Based on Microsoft Purview Deployment Models: Prevent data leak to shadow AI
    #>

    AI107() {
        $this.Control            = "AI-107"
        $this.ParentArea         = "Microsoft Purview AI"
        $this.Area               = "AI & Shadow IT"
        $this.Name               = "Use Intune App Protection Policies to Limit Managed Data Flow to AI Apps"
        $this.PassText           = "Your organization has an Intune app protection policy review item for limiting managed data flow to AI apps"
        $this.FailRecommendation = "Your organization should configure Intune app protection policies to limit managed data flow to unsanctioned AI apps"
        $this.Importance         = "The Prevent data leak to shadow AI deployment model Step 2 recommends restricting data movement to unsanctioned generative AI apps after discovery. Intune app protection policies require Microsoft Intune licensing and managed app coverage for the apps and platforms in scope. CAMP cannot verify this control from Exchange Online or Security & Compliance PowerShell yet, so this awareness check directs admins to the Intune policy experience."
        $this.ExpandResults      = $True
        $this.ItemName           = "Intune Control"
        $this.DataType           = "Review Status"

        $this.Blueprint        = [CAMPBlueprint]::ShadowAI
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "ShadowAI" = 2 }
        $this.RequiredCollections = @()
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft Intune")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 2"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step2"
                "Microsoft Intune"              = "https://intune.microsoft.com"
                "App protection policies"       = "https://learn.microsoft.com/mem/intune/apps/app-protection-policy"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 2"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step2"
                "Microsoft Intune"              = "https://intune.microsoft.com"
                "App protection policies"       = "https://learn.microsoft.com/mem/intune/apps/app-protection-policy"
            }
        }
        else {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 2"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step2"
                "Microsoft Intune"              = "https://intune.microsoft.com"
                "App protection policies"       = "https://learn.microsoft.com/mem/intune/apps/app-protection-policy"
            }
        }
    }

    GetResults($Config) {
        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object     = "Intune app protection policies"
        $ConfigObject.ConfigItem = "Manual review required"
        $ConfigObject.ConfigData = "CAMP cannot verify Intune app protection policy data from EXO/IPPS collections"
        $ConfigObject.InfoText   = "Review or create Intune app protection policies at https://intune.microsoft.com/#view/Microsoft_Intune_Apps/AppsMenu/~/configurationPolicies to limit managed data transfer to unsanctioned AI apps. Use the Shadow AI Step 2 deployment guidance to align these controls with Defender for Cloud Apps, Entra Internet Access, and Endpoint DLP restrictions."
        $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
        $this.AddConfig($ConfigObject)

        $this.Completed = $true
    }
}

