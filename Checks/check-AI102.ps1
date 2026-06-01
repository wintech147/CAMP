using module "..\CAMP.psm1"

class AI102 : CAMPCheck {
    <#
        Restrict browser access to unsanctioned generative AI sites via Endpoint DLP
        Based on Microsoft Purview Deployment Models: Prevent data leak to shadow AI
    #>

    AI102() {
        $this.Control            = "AI-102"
        $this.ParentArea         = "Microsoft Purview AI"
        $this.Area               = "AI & Shadow IT"
        $this.Name               = "Restrict Browser Access to Unsanctioned Generative AI Sites via Endpoint DLP"
        $this.PassText           = "Your organization has Endpoint DLP rules that restrict browser flows to unsanctioned generative AI sites"
        $this.FailRecommendation = "Your organization should configure Endpoint DLP browser restrictions for unsanctioned generative AI sites"
        $this.Importance         = "The Prevent data leak to shadow AI deployment model Step 2 recommends restricting unmanaged browser access to unsanctioned generative AI sites after discovery. Endpoint DLP browser restrictions require Microsoft 365 E5 Compliance or equivalent Endpoint DLP licensing and onboarded devices. This control helps prevent sensitive content from being pasted or uploaded into unmanaged AI services."
        $this.ExpandResults      = $True
        $this.ItemName           = "DLP Rule"
        $this.DataType           = "AI Browser Restriction"

        $this.Blueprint        = [CAMPBlueprint]::ShadowAI
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "ShadowAI" = 2 }
        $this.RequiredCollections = @("GetDlpComplianceRule")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 2"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step2"
                "Microsoft Purview DLP"         = "https://purview.microsoft.com/datalossprevention"
                "Endpoint DLP"                  = "https://learn.microsoft.com/purview/endpoint-dlp-learn-about"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 2"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step2"
                "Microsoft Purview DLP"         = "https://purview.microsoft.com/datalossprevention"
                "Endpoint DLP"                  = "https://learn.microsoft.com/purview/endpoint-dlp-learn-about"
            }
        }
        else {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 2"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step2"
                "Microsoft Purview DLP"         = "https://purview.microsoft.com/datalossprevention"
                "Endpoint DLP"                  = "https://learn.microsoft.com/purview/endpoint-dlp-learn-about"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs DLP compliance rules from Security & Compliance PowerShell.")
                return
            }
        }

        $MatchingRules = @()

        ForEach ($Rule in $Config["GetDlpComplianceRule"]) {
            $RuleName = $Rule.Name
            if ([string]::IsNullOrWhiteSpace([string]$RuleName)) { $RuleName = $Rule.Identity }

            $Reason = @()
            $BrowserRestrictionsProperty = $Rule.PSObject.Properties["EndpointDlpBrowserRestrictions"]
            if ($null -ne $BrowserRestrictionsProperty) {
                $BrowserRestrictionsText = ($BrowserRestrictionsProperty.Value | Out-String).Trim()
                if (-not [string]::IsNullOrWhiteSpace($BrowserRestrictionsText)) {
                    $Reason += "EndpointDlpBrowserRestrictions configured"
                }
            }

            $EndpointRestrictionsProperty = $Rule.PSObject.Properties["EndpointDlpRestrictions"]
            if ($null -ne $EndpointRestrictionsProperty) {
                $EndpointRestrictionsText = ($EndpointRestrictionsProperty.Value | Out-String).Trim()
                if ($EndpointRestrictionsText -match "(?i)UnsanctionedAiApps|GenerativeAI|Generative AI") {
                    $Reason += "EndpointDlpRestrictions includes unsanctioned/generative AI category"
                }
            }

            if ($Reason.Count -gt 0) {
                $MatchingRules += $RuleName
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object     = $RuleName
                $ConfigObject.ConfigItem = "Endpoint DLP browser restriction"
                $ConfigObject.ConfigData = $Reason -join "; "
                $ConfigObject.InfoText   = "Validate that this rule blocks or audits sensitive data movement to unsanctioned generative AI sites, as recommended in Shadow AI Step 2."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)
            }
        }

        if ($MatchingRules.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "No AI browser restriction rules"
            $ConfigObject.ConfigItem = "EndpointDlpBrowserRestrictions / EndpointDlpRestrictions"
            $ConfigObject.ConfigData = "No DLP rule restricted unsanctioned or generative AI browser flows"
            $ConfigObject.InfoText   = "Create or update Endpoint DLP rules to restrict browser uploads, paste, and other data flows to unsanctioned generative AI apps. Use the Shadow AI Step 2 guidance and the Microsoft Purview DLP portal at https://purview.microsoft.com/datalossprevention."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}

