using module "..\CAMP.psm1"

class AI106 : CAMPCheck {
    <#
        Discover shadow AI app usage with Defender for Cloud Apps and Entra Internet Access
        Based on Microsoft Purview Deployment Models: Prevent data leak to shadow AI
    #>

    AI106() {
        $this.Control            = "AI-106"
        $this.ParentArea         = "Microsoft Purview AI"
        $this.Area               = "AI & Shadow IT"
        $this.Name               = "Discover Shadow AI App Usage with Defender for Cloud Apps and Entra Internet Access"
        $this.PassText           = "Your organization has a Shadow AI discovery review item for Defender for Cloud Apps and Entra Internet Access"
        $this.FailRecommendation = "Your organization should use Defender for Cloud Apps and Entra Internet Access to discover and review Shadow AI usage"
        $this.Importance         = "The Prevent data leak to shadow AI deployment model Steps 1 and 2 recommend discovering generative AI app usage before restricting risky traffic. Defender for Cloud Apps and Microsoft Entra Internet Access require their respective licensing, and Graph app registration review requires Application.Read.All consent. Availability of AI discovery signals can vary by cloud, so GCCH and DoD tenants should confirm feature availability in their admin portals."
        $this.ExpandResults      = $True
        $this.ItemName           = "Discovery Signal"
        $this.DataType           = "Potential AI App Registrations"

        $this.Blueprint        = [CAMPBlueprint]::ShadowAI
        $this.MaturityLevel    = [CAMPMaturityLevel]::Good
        $this.BlueprintStages  = @{ "ShadowAI" = "1,2" }
        $this.RequiredCollections = @("GetEntraApps")
        $this.RequiredGraphScopes = @("Application.Read.All")
        $this.RequiredLicenses    = @("Microsoft Defender for Cloud Apps", "Microsoft Entra Internet Access")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Prevent data leak to shadow AI"     = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 1"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step1"
                "Shadow AI Step 2"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step2"
                "Microsoft Defender for Cloud Apps" = "https://learn.microsoft.com/defender-cloud-apps/what-is-defender-for-cloud-apps"
                "Entra Internet Access"             = "https://learn.microsoft.com/entra/global-secure-access/concept-internet-access"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Prevent data leak to shadow AI"     = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 1"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step1"
                "Shadow AI Step 2"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step2"
                "Microsoft Defender for Cloud Apps" = "https://learn.microsoft.com/defender-cloud-apps/what-is-defender-for-cloud-apps"
                "Entra Internet Access"             = "https://learn.microsoft.com/entra/global-secure-access/concept-internet-access"
            }
        }
        else {
            $this.Links = @{
                "Prevent data leak to shadow AI"     = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 1"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step1"
                "Shadow AI Step 2"                  = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step2"
                "Microsoft Defender for Cloud Apps" = "https://learn.microsoft.com/defender-cloud-apps/what-is-defender-for-cloud-apps"
                "Entra Internet Access"             = "https://learn.microsoft.com/entra/global-secure-access/concept-internet-access"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.EmitAwarenessRecommendation(
                    "<B>Shadow AI app discovery (manual review)</B>",
                    "Microsoft Graph data not collected",
                    "GetEntraApps was not available — install Microsoft.Graph and grant Application.Read.All to enumerate Entra app registrations.",
                    "Review Shadow AI app discovery in Microsoft Defender for Cloud Apps (https://security.microsoft.com/cloudapps) and Microsoft Entra Internet Access (https://entra.microsoft.com). Look for sanctioned vs unsanctioned generative AI services."
                )
                return
            }
        }

        $VendorPattern = "(?i)ChatGPT|Claude|Gemini|Perplexity|Copilot|OpenAI|Anthropic|Mistral"
        $MatchingApps = @()

        ForEach ($App in $Config["GetEntraApps"]) {
            $DisplayName = [string]$App.DisplayName
            if ([string]::IsNullOrWhiteSpace($DisplayName)) { continue }
            if ($DisplayName -match $VendorPattern) {
                $AppId = [string]$App.AppId
                if ([string]::IsNullOrWhiteSpace($AppId)) {
                    $MatchingApps += $DisplayName
                }
                else {
                    $MatchingApps += "$DisplayName ($AppId)"
                }
            }
        }

        $DisplayList = "No app registrations matched common generative AI vendor names"
        if ($MatchingApps.Count -gt 0) {
            $DisplayList = $MatchingApps[0..([Math]::Min(24, $MatchingApps.Count - 1))] -join "; "
            if ($MatchingApps.Count -gt 25) {
                $DisplayList += "; and $($MatchingApps.Count - 25) more"
            }
        }

        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object     = "Defender for Cloud Apps / Entra Internet Access review"
        $ConfigObject.ConfigItem = "$($MatchingApps.Count) potential AI app registration(s) found"
        $ConfigObject.ConfigData = $DisplayList
        $ConfigObject.InfoText   = "This awareness check does not prove Shadow AI traffic is controlled. Use Defender for Cloud Apps and Entra Internet Access to discover app usage, classify generative AI apps, and decide which apps should be sanctioned or restricted."
        $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
        $this.AddConfig($ConfigObject)

        $this.Completed = $true
    }
}

