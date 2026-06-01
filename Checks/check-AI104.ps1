using module "..\CAMP.psm1"

class AI104 : CAMPCheck {
    <#
        Use sensitivity labels to scope Microsoft 365 Copilot processing
        Based on Microsoft Purview Deployment Models: Prevent data leak to shadow AI, Secure and govern Microsoft 365 Copilot agents
    #>

    AI104() {
        $this.Control            = "AI-104"
        $this.ParentArea         = "Microsoft Purview AI"
        $this.Area               = "AI & Shadow IT"
        $this.Name               = "Use Sensitivity Labels to Scope Microsoft 365 Copilot Processing"
        $this.PassText           = "Your organization has sensitivity labels configured to limit Copilot processing of labeled content"
        $this.FailRecommendation = "Your organization should configure sensitivity label advanced settings that prevent Copilot processing of the most sensitive content"
        $this.Importance         = "The Prevent data leak to shadow AI deployment model Step 3 and the Secure and govern Microsoft 365 Copilot agents deployment model Step 2 recommend using labels to scope what Microsoft 365 Copilot can process. This requires Microsoft 365 E5 Compliance or equivalent sensitivity labeling rights and Microsoft 365 Copilot licensing for the users being governed. Several Copilot label-scoping features are commercial-only at the time of writing, so this check is marked CommercialOnly and may be unavailable in GCCH or DoD."
        $this.ExpandResults      = $True
        $this.ItemName           = "Sensitivity Label"
        $this.DataType           = "Copilot Processing Setting"

        $this.Blueprint        = [CAMPBlueprint]::ShadowAI -bor [CAMPBlueprint]::CopilotAgents
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "ShadowAI" = 3; "CopilotAgents" = 2 }
        $this.RequiredCollections = @("GetLabel")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance", "Microsoft 365 Copilot")
        $this.CommercialOnly      = $true

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 3"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step3"
                "Sensitivity labels"            = "https://learn.microsoft.com/purview/sensitivity-labels"
                "Microsoft Purview AI Hub"      = "https://purview.microsoft.com/aiHub"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 3"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step3"
                "Sensitivity labels"            = "https://learn.microsoft.com/purview/sensitivity-labels"
                "Microsoft Purview AI Hub"      = "https://purview.microsoft.com/aiHub"
            }
        }
        else {
            $this.Links = @{
                "Prevent data leak to shadow AI" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro"
                "Shadow AI Step 3"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-step3"
                "Sensitivity labels"            = "https://learn.microsoft.com/purview/sensitivity-labels"
                "Microsoft Purview AI Hub"      = "https://purview.microsoft.com/aiHub"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs sensitivity labels from Security & Compliance PowerShell.")
                return
            }
        }

        $SettingNames = @("BlockGenerativeAI", "CopilotProtection", "aiProtection", "EnableCopilotProtection")
        $LabelsWithCopilotProtection = @()

        ForEach ($Label in $Config["GetLabel"]) {
            $LabelName = $Label.DisplayName
            if ([string]::IsNullOrWhiteSpace([string]$LabelName)) { $LabelName = $Label.Name }
            $MatchedSetting = $null

            if ($null -ne $Label.Settings) {
                foreach ($Setting in @($Label.Settings)) {
                    $SettingText = [string]$Setting
                    if ([string]::IsNullOrWhiteSpace($SettingText)) { continue }

                    $HasCopilotSetting = $false
                    foreach ($SettingName in $SettingNames) {
                        if ($SettingText -match [regex]::Escape($SettingName)) {
                            $HasCopilotSetting = $true
                            break
                        }
                    }

                    $ExplicitlyOff = $SettingText -match "(?i)(false|disabled|off|no)"
                    if ($HasCopilotSetting -and -not $ExplicitlyOff) {
                        $MatchedSetting = $SettingText
                        break
                    }
                }
            }

            if ($null -ne $MatchedSetting) {
                if ($MatchedSetting.Length -gt 180) { $MatchedSetting = $MatchedSetting.Substring(0, 180) + "..." }
                $LabelsWithCopilotProtection += $LabelName
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object     = $LabelName
                $ConfigObject.ConfigItem = "Copilot processing advanced setting"
                $ConfigObject.ConfigData = $MatchedSetting
                $ConfigObject.InfoText   = "Validate that this label is published to the intended users and applied to content that should be excluded or protected from Microsoft 365 Copilot processing."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)
            }
        }

        if ($LabelsWithCopilotProtection.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "No Copilot-scoped sensitivity labels"
            $ConfigObject.ConfigItem = "Settings checked: $($SettingNames -join ', ')"
            $ConfigObject.ConfigData = "No sensitivity label Settings entry enabled a Copilot or generative AI processing control"
            $ConfigObject.InfoText   = "Use sensitivity label advanced settings to protect the most sensitive content from Microsoft 365 Copilot processing where appropriate. Preview tenants have exposed this with names such as BlockGenerativeAI, CopilotProtection, aiProtection, or EnableCopilotProtection."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}

