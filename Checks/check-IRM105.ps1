using module "..\CAMP.psm1"

class IRM105 : CAMPCheck {
    <#
        CAMP Check: IRM-105
        Informational check recommending Adaptive Protection configuration
        Blueprint: Copilot - Protect Against Data Loss and Insider Risk
        Blueprint: Identify and Remediate Credentials with Purview

        Note: Adaptive Protection settings cannot be verified via PowerShell as there
        are no cmdlets available. This check provides guidance and recommendations.
    #>

    IRM105() {
        $this.Control = "IRM-105"
        $this.ParentArea = "Insider Risk"
        $this.Area = "Insider Risk Management"
        $this.Name = "Enable Adaptive Protection for Dynamic DLP Enforcement"
        $this.PassText = "Review Adaptive Protection configuration in the Microsoft Purview portal"
        $this.FailRecommendation = "Your organization should enable Adaptive Protection to dynamically adjust DLP enforcement based on insider risk levels"
        $this.Importance = "Adaptive Protection integrates Insider Risk Management with DLP and Conditional Access to dynamically adjust security controls based on user risk levels. When enabled, users with elevated risk levels face stricter DLP policies, while low-risk users maintain productivity. This is critical for protecting against data leakage to Copilot/AI applications and credential exposure. Configuration must be done in the Microsoft Purview portal as PowerShell cmdlets are not available."
        $this.ExpandResults = $True
        $this.ItemName = "Configuration"
        $this.DataType = "Status"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Adaptive Protection Overview" = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection"
                "Configure Adaptive Protection" = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection#configure-adaptive-protection"
                "Microsoft Purview portal - Adaptive Protection" = "https://aka.ms/mcca-gcch-irm-compliance-center"
                "Copilot Data Protection Blueprint" = "https://github.com/microsoft/purview/tree/main/purview-blueprints"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Adaptive Protection Overview" = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection"
                "Configure Adaptive Protection" = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection#configure-adaptive-protection"
                "Microsoft Purview portal - Adaptive Protection" = "https://aka.ms/mcca-dod-irm-compliance-center"
                "Copilot Data Protection Blueprint" = "https://github.com/microsoft/purview/tree/main/purview-blueprints"
            }
        }else
        {
            $this.Links = @{
                "Adaptive Protection Overview" = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection"
                "Configure Adaptive Protection" = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection#configure-adaptive-protection"
                "Microsoft Purview portal - Adaptive Protection" = "https://aka.ms/mcca-irm-compliance-center"
                "Copilot Data Protection Blueprint" = "https://github.com/microsoft/purview/tree/main/purview-blueprints"
            }
        }
    }

    <#
        RESULTS
    #>

    GetResults($Config) {
        if ($Config["GetInsiderRiskPolicy"] -eq "Error") {
            $this.Completed = $false
        }
        else {
            # Check if Data Leaks policy exists (prerequisite for Adaptive Protection)
            $Templates = @("DataLeaks", "DataLeaksForAdaptiveProtection")
            $HasDataLeaksPolicy = $false

            foreach($Template in $Templates) {
                $Policy = $Config["GetInsiderRiskPolicy"] | Where-Object {
                    $_.InsiderRiskScenario -eq $Template -and $_.Mode -eq "Enable"
                }
                if ($Policy) {
                    $HasDataLeaksPolicy = $true
                    break
                }
            }

            # Informational check - always provide guidance
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "Adaptive Protection"

            if ($HasDataLeaksPolicy) {
                $ConfigObject.ConfigItem = "Data Leaks policy detected - Adaptive Protection may be available"
                $ConfigObject.ConfigData = "Verify Adaptive Protection is enabled in Microsoft Purview portal > Insider Risk Management > Adaptive Protection"
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Info")
            }
            else {
                $ConfigObject.ConfigItem = "No Data Leaks policy detected"
                $ConfigObject.ConfigData = "Configure a Data Leaks policy first, then enable Adaptive Protection in the portal"
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Info")
            }

            $this.AddConfig($ConfigObject)

            # Add checklist items for Adaptive Protection configuration
            $ChecklistItems = @(
                @{Item = "Quick Setup or Custom Setup"; Data = "Use Quick Setup for fastest deployment, or Custom Setup for granular control"},
                @{Item = "Insider Risk Levels"; Data = "Configure Elevated, Moderate, and Minor risk level thresholds"},
                @{Item = "DLP Policy Integration"; Data = "Create DLP policies with 'User insider risk level for Adaptive Protection' condition"},
                @{Item = "Conditional Access Integration"; Data = "Configure Conditional Access policies in Microsoft Entra with insider risk conditions"}
            )

            foreach ($Item in $ChecklistItems) {
                $ChecklistConfig = [CAMPCheckConfig]::new()
                $ChecklistConfig.Object = "Checklist"
                $ChecklistConfig.ConfigItem = $Item.Item
                $ChecklistConfig.ConfigData = $Item.Data
                $ChecklistConfig.SetResult([CAMPConfigLevel]::Informational, "Info")
                $this.AddConfig($ChecklistConfig)
            }

            $this.Completed = $True
        }
    }
}
