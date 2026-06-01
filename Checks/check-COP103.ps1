using module "..\CAMP.psm1"

class COP103 : CAMPCheck {
    <#

        Run Microsoft Purview Data Risk Assessments for Copilot Oversharing
        Based on Microsoft Purview Deployment Models: Secure & govern Microsoft 365 Copilot agents.

    #>

    COP103() {
        $this.Control = "COP-103"
        $this.ParentArea = "Microsoft Purview AI"
        $this.Area = "Copilot & Agents"
        $this.Name = "Run Microsoft Purview Data Risk Assessments for Copilot Oversharing"
        $this.Blueprint = [CAMPBlueprint]::CopilotAgents -bor [CAMPBlueprint]::DSPM
        $this.MaturityLevel = [CAMPMaturityLevel]::Good
        $this.BlueprintStages = @{
            "CopilotAgents" = 1
            "DSPM" = 1
        }
        $this.Foundational = $false
        $this.RequiredLicenses = @("Microsoft 365 Copilot", "Microsoft 365 E5 Compliance")
        $this.CommercialOnly = $true
        $this.PassText = "Review Microsoft Purview Data Risk Assessments for Copilot oversharing insights"
        $this.FailRecommendation = "Run Microsoft Purview Data Risk Assessments to prioritize Copilot oversharing remediation"
        $this.Importance = "Step 1 of the Secure & govern Microsoft 365 Copilot agents deployment model recommends data risk assessments to identify overshared, sensitive, stale, and unlabeled content before Microsoft 365 Copilot and agents can ground on it. Data risk assessments are part of DSPM for AI, require the relevant Microsoft Purview and Copilot licensing, and are CommercialOnly at the time of writing for GCCH/DoD tenants."
        $this.ExpandResults = $True
        $this.ItemName = "Assessment"
        $this.DataType = "Recommendation"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 1" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step1"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.us/aiHub"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 1" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step1"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.us/aiHub"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }else
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 1" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step1"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.com/aiHub"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config) {
        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object = "Microsoft Purview AI Hub"
        $ConfigObject.ConfigItem = "Data risk assessments"
        $ConfigObject.ConfigData = "Review and run data risk assessments for Copilot oversharing"
        $ConfigObject.InfoText = "Open https://purview.microsoft.com/aiHub/dataRiskAssessments and run the recommended data risk assessments from the Secure & govern Microsoft 365 Copilot agents deployment model: https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step1. Use the results to prioritize sensitivity labels, permission cleanup, and DSPM for AI remediation."
        $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
        $this.AddConfig($ConfigObject)
        $this.Completed = $True
    }
}
