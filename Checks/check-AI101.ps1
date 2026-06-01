using module "..\CAMP.psm1"

class AI101 : CAMPCheck {
    <#
        Enable Data Security Posture Management for AI
        Based on Microsoft Purview Deployment Models: Prevent data leak to shadow AI, Secure and govern Microsoft 365 Copilot agents, Data Security Posture Management
    #>

    AI101() {
        $this.Control            = "AI-101"
        $this.ParentArea         = "Microsoft Purview AI"
        $this.Area               = "AI & Shadow IT"
        $this.Name               = "Enable Data Security Posture Management for AI"
        $this.PassText           = "Your organization has DSPM for AI signals available for review"
        $this.FailRecommendation = "Your organization should enable and review Data Security Posture Management for AI in the Microsoft Purview AI Hub"
        $this.Importance         = "The Prevent data leak to shadow AI deployment model Step 1 and the Secure and govern Microsoft 365 Copilot agents deployment model Step 1 recommend discovering AI usage and data exposure before enforcing controls. DSPM for AI requires Microsoft Purview DSPM capabilities, Microsoft 365 E5 Compliance or equivalent licensing, and InformationProtectionPolicy.Read Graph consent. DSPM for AI is commercial-only at the time of writing, so this check is marked CommercialOnly and may be unavailable in GCCH or DoD."
        $this.ExpandResults      = $True
        $this.ItemName           = "DSPM for AI Signal"
        $this.DataType           = "Availability"

        $this.Blueprint        = [CAMPBlueprint]::ShadowAI -bor [CAMPBlueprint]::CopilotAgents -bor [CAMPBlueprint]::DSPM
        $this.MaturityLevel    = [CAMPMaturityLevel]::Good
        $this.BlueprintStages  = @{ "ShadowAI" = 1; "CopilotAgents" = 1; "DSPM" = 1 }
        $this.RequiredCollections = @()
        $this.RequiredGraphScopes = @("InformationProtectionPolicy.Read")
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $true

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 1"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step1"
                "DSPM for AI"                   = "https://learn.microsoft.com/purview/dspm-for-ai"
                "Microsoft Purview AI Hub"      = "https://purview.microsoft.com/aiHub"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 1"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step1"
                "DSPM for AI"                   = "https://learn.microsoft.com/purview/dspm-for-ai"
                "Microsoft Purview AI Hub"      = "https://purview.microsoft.com/aiHub"
            }
        }
        else {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 1"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step1"
                "DSPM for AI"                   = "https://learn.microsoft.com/purview/dspm-for-ai"
                "Microsoft Purview AI Hub"      = "https://purview.microsoft.com/aiHub"
            }
        }
    }

    GetResults($Config) {
        $SucceededSources = @()
        $SignalDetails = @()
        $Errors = @()

        try {
            $DspmInsights = Get-DspmAiInsights -ErrorAction:Stop
            $SucceededSources += "Get-DspmAiInsights"
            $SignalDetails += "Get-DspmAiInsights returned $(@($DspmInsights).Count) item(s)"
        }
        catch {
            $Errors += "Get-DspmAiInsights: $($_.Exception.Message)"
        }

        try {
            $DataClassificationForAI = Get-DataClassification -ForAI -ErrorAction:Stop
            $SucceededSources += "Get-DataClassification -ForAI"
            $SignalDetails += "Get-DataClassification -ForAI returned $(@($DataClassificationForAI).Count) item(s)"
        }
        catch {
            $Errors += "Get-DataClassification -ForAI: $($_.Exception.Message)"
        }

        if ($SucceededSources.Count -gt 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "Microsoft Purview AI Hub"
            $ConfigObject.ConfigItem = "DSPM for AI query surface available"
            $ConfigObject.ConfigData = "$($SucceededSources -join ', '): $($SignalDetails -join '; ')"
            $ConfigObject.InfoText   = "Review DSPM for AI in the Microsoft Purview AI Hub at https://purview.microsoft.com/aiHub to identify AI interactions, sensitive data exposure, and recommended controls before enforcing Shadow AI restrictions."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
            $this.AddConfig($ConfigObject)
            $this.Completed = $true
            return
        }

        $this.EmitAwarenessRecommendation(
            "<B>DSPM for AI (manual review)</B>",
            "DSPM for AI is portal-only in this tenant",
            "No PowerShell cmdlet was available to verify DSPM for AI enablement. Errors: $($Errors -join ' | ')",
            "DSPM for AI is configured and reviewed in the Microsoft Purview portal at https://purview.microsoft.com/aiHub. Confirm DSPM for AI is enabled, review the Apps and Agents report for risky activities, and revisit this check after Microsoft ships PowerShell support."
        )
    }
}

