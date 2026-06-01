using module "..\CAMP.psm1"

class COP107 : CAMPCheck {
    <#

        Ensure eDiscovery Readiness for Microsoft 365 Copilot Interactions
        Based on Microsoft Purview Deployment Models: Secure & govern Microsoft 365 Copilot agents.

    #>

    COP107() {
        $this.Control = "COP-107"
        $this.ParentArea = "Microsoft Purview AI"
        $this.Area = "Copilot & Agents"
        $this.Name = "Ensure eDiscovery Readiness for Microsoft 365 Copilot Interactions"
        $this.Blueprint = [CAMPBlueprint]::CopilotAgents
        $this.MaturityLevel = [CAMPMaturityLevel]::Better
        $this.BlueprintStages = @{
            "CopilotAgents" = 4
        }
        $this.Foundational = $false
        $this.RequiredCollections = @("GetComplianceCaseCore")
        $this.RequiredLicenses = @("Microsoft 365 E5 Compliance", "Microsoft 365 Copilot")
        $this.CommercialOnly = $true
        $this.PassText = "Your organization has eDiscovery cases available for Copilot interaction readiness validation"
        $this.FailRecommendation = "Create an eDiscovery case and validate searches across Microsoft 365 Copilot interactions"
        $this.Importance = "Step 4 of the Secure & govern Microsoft 365 Copilot agents deployment model validates that retained Microsoft 365 Copilot and agent interactions can be found during investigations and legal response. Copilot-specific interaction locations require Microsoft Purview eDiscovery capabilities and Copilot licensing, and are CommercialOnly at the time of writing for GCCH/DoD tenants."
        $this.ExpandResults = $True
        $this.ItemName = "eDiscovery Readiness"
        $this.DataType = "Status"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 4" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step4"
                "Microsoft Purview portal - eDiscovery" = "https://aka.ms/mcca-gcch-ediscovery-compliance-center"
                "Microsoft 365 Copilot data security" = "https://learn.microsoft.com/microsoft-365-copilot/microsoft-365-copilot-overview"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 4" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step4"
                "Microsoft Purview portal - eDiscovery" = "https://aka.ms/mcca-dod-ediscovery-compliance-center"
                "Microsoft 365 Copilot data security" = "https://learn.microsoft.com/microsoft-365-copilot/microsoft-365-copilot-overview"
            }
        }else
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 4" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step4"
                "Microsoft Purview portal - eDiscovery" = "https://aka.ms/mcca-ediscovery-compliance-center"
                "Microsoft 365 Copilot data security" = "https://learn.microsoft.com/microsoft-365-copilot/microsoft-365-copilot-overview"
            }
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config) {
        if (-not $this.HasCollection($Config, "GetComplianceCaseCore")) {
            $this.SetUnavailable("Required collection GetComplianceCaseCore is missing or returned an error.")
            return
        }

        $CaseCount = @($Config["GetComplianceCaseCore"]).Count

        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object = "eDiscovery"
        $ConfigObject.ConfigItem = "Compliance cases"
        if ($CaseCount -gt 0) {
            $ConfigObject.ConfigData = "$CaseCount compliance case(s) found"
            $ConfigObject.InfoText = "At least one compliance case exists. Use a case to validate Copilot interaction retention and search readiness."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
        }
        else {
            $ConfigObject.ConfigData = "No compliance cases found"
            $ConfigObject.InfoText = "Create a compliance case so administrators can validate eDiscovery search and export workflows for Microsoft 365 Copilot interactions."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
        }
        $this.AddConfig($ConfigObject)

        $ValidationObject = [CAMPCheckConfig]::new()
        $ValidationObject.Object = "<B>Copilot eDiscovery readiness validation</B>"
        $ValidationObject.ConfigItem = "Sample search"
        $ValidationObject.ConfigData = "Run a sample search across the Copilot interactions location"
        $ValidationObject.InfoText = "After retention is configured, run a sample eDiscovery search across the Copilot interactions location to confirm retained prompts, responses, and agent interactions are discoverable. This check does not run searches automatically."
        $ValidationObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
        $this.AddConfig($ValidationObject)

        $this.Completed = $True
    }
}
