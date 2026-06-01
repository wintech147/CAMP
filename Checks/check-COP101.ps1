using module "..\CAMP.psm1"

class COP101 : CAMPCheck {
    <#

        Confirm Microsoft Purview Audit is Capturing Copilot Interactions
        Based on Microsoft Purview Deployment Models: Secure & govern Microsoft 365 Copilot agents.

    #>

    COP101() {
        $this.Control = "COP-101"
        $this.ParentArea = "Microsoft Purview AI"
        $this.Area = "Copilot & Agents"
        $this.Name = "Confirm Microsoft Purview Audit is Capturing Copilot Interactions"
        $this.Blueprint = [CAMPBlueprint]::CopilotAgents -bor [CAMPBlueprint]::ShadowAI -bor [CAMPBlueprint]::DSPM
        $this.MaturityLevel = [CAMPMaturityLevel]::Good
        $this.BlueprintStages = @{
            "CopilotAgents" = 1
            "ShadowAI" = 1
            "DSPM" = 1
        }
        $this.Foundational = $false
        $this.RequiredCollections = @("GetAdminAuditLogConfig")
        $this.RequiredLicenses = @("Microsoft 365 E3 or higher for Audit (Standard)", "Microsoft 365 Copilot")
        $this.PassText = "Your organization has unified audit log ingestion enabled so Microsoft 365 Copilot interactions can be captured"
        $this.FailRecommendation = "Your organization should enable Microsoft Purview Audit so Copilot interactions are captured"
        $this.Importance = "Step 1 of the Secure & govern Microsoft 365 Copilot agents deployment model starts with audit readiness before applying oversharing, DLP, retention, and eDiscovery controls. Microsoft Purview Audit is the foundation for investigating Copilot prompts, responses, agent actions, and related administrative activity. Audit (Standard) is included with many Microsoft 365 enterprise plans; Audit (Premium) and Microsoft 365 Copilot licensing can extend retention and Copilot-specific coverage."
        $this.ExpandResults = $True
        $this.ItemName = "Configuration"
        $this.DataType = "Setting"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 1" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step1"
                "Microsoft Purview portal - Audit Log search" = "https://aka.ms/mcca-gcch-aa-compliance-center"
                "Microsoft 365 Copilot data security" = "https://learn.microsoft.com/microsoft-365-copilot/microsoft-365-copilot-overview"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 1" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step1"
                "Microsoft Purview portal - Audit Log search" = "https://aka.ms/mcca-dod-aa-compliance-center"
                "Microsoft 365 Copilot data security" = "https://learn.microsoft.com/microsoft-365-copilot/microsoft-365-copilot-overview"
            }
        }else
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 1" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step1"
                "Microsoft Purview portal - Audit Log search" = "https://aka.ms/mcca-aa-compliance-center"
                "Microsoft 365 Copilot data security" = "https://learn.microsoft.com/microsoft-365-copilot/microsoft-365-copilot-overview"
            }
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config) {
        if (-not $this.HasCollection($Config, "GetAdminAuditLogConfig")) {
            $this.SetUnavailable("Required collection GetAdminAuditLogConfig is missing or returned an error.")
            return
        }

        $Auditconfiguration = $Config["GetAdminAuditLogConfig"]
        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object = "Configuration"
        $ConfigObject.ConfigItem = "Unified audit log ingestion"

        If ($Auditconfiguration.UnifiedAuditLogIngestionEnabled -eq $true) {
            $ConfigObject.ConfigData = "Enabled"
            $ConfigObject.InfoText = "Unified audit log ingestion is enabled. Use Audit search to validate Copilot interaction events as Microsoft 365 Copilot and agents are rolled out."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
        }
        Else {
            $ConfigObject.ConfigData = "Disabled"
            $ConfigObject.InfoText = "Enable unified audit log ingestion before broad Copilot and agent deployment so prompts, responses, agent activity, and administrative actions can be investigated."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
        }

        $this.AddConfig($ConfigObject)
        $this.Completed = $True
    }
}
