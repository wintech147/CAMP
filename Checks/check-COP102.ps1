using module "..\CAMP.psm1"

class COP102 : CAMPCheck {
    <#

        Enable Restricted SharePoint Search to Reduce Copilot Oversharing
        Based on Microsoft Purview Deployment Models: Secure & govern Microsoft 365 Copilot agents.

    #>

    COP102() {
        $this.Control = "COP-102"
        $this.ParentArea = "Microsoft Purview AI"
        $this.Area = "Copilot & Agents"
        $this.Name = "Enable Restricted SharePoint Search to Reduce Copilot Oversharing"
        $this.Blueprint = [CAMPBlueprint]::CopilotAgents
        $this.MaturityLevel = [CAMPMaturityLevel]::Better
        $this.BlueprintStages = @{
            "CopilotAgents" = 2
        }
        $this.Foundational = $false
        $this.RequiredGraphScopes = @("Sites.Read.All")
        $this.RequiredLicenses = @("Microsoft 365 Copilot", "SharePoint Advanced Management")
        $this.CommercialOnly = $true
        $this.PassText = "Your organization has enabled Restricted SharePoint Search to reduce Copilot oversharing risk"
        $this.FailRecommendation = "Your organization should enable Restricted SharePoint Search while remediating SharePoint oversharing risk"
        $this.Importance = "Step 2 of the Secure & govern Microsoft 365 Copilot agents deployment model uses containment controls such as Restricted SharePoint Search while administrators identify, classify, and remediate overshared sites. This control depends on SharePoint Advanced Management and Copilot deployment prerequisites, and is CommercialOnly at the time of writing for GCCH/DoD tenants."
        $this.ExpandResults = $True
        $this.ItemName = "Configuration"
        $this.DataType = "Restricted Search Mode"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 2" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step2"
                "Restricted SharePoint Search" = "https://learn.microsoft.com/sharepoint/restricted-sharepoint-search"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.us/aiHub"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 2" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step2"
                "Restricted SharePoint Search" = "https://learn.microsoft.com/sharepoint/restricted-sharepoint-search"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.us/aiHub"
            }
        }else
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 2" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step2"
                "Restricted SharePoint Search" = "https://learn.microsoft.com/sharepoint/restricted-sharepoint-search"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.com/aiHub"
            }
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config) {
        try {
            $RestrictedSearchMode = Get-SPOTenantRestrictedSearchMode -ErrorAction Stop
        }
        catch {
            $this.EmitAwarenessRecommendation(
                "<B>Restricted SharePoint Search (manual review)</B>",
                "Get-SPOTenantRestrictedSearchMode not available",
                "SharePoint Online PowerShell cmdlet was not available in this session.",
                "Install Microsoft.Online.SharePoint.PowerShell and connect via Connect-SPOService -Url https://&lt;tenant&gt;-admin.sharepoint.com to verify Restricted SharePoint Search is enabled. Alternatively configure it manually in the SharePoint admin center: https://admin.microsoft.com/sharepoint?page=settings"
            )
            return
        }

        $Mode = $null
        if ($RestrictedSearchMode -is [string]) {
            $Mode = $RestrictedSearchMode
        }
        elseif ($null -ne $RestrictedSearchMode) {
            foreach ($PropertyName in @("Mode", "SearchMode", "RestrictedSearchMode", "Value")) {
                if ($null -eq $Mode -and $null -ne $RestrictedSearchMode.PSObject.Properties[$PropertyName]) {
                    $Mode = $RestrictedSearchMode.PSObject.Properties[$PropertyName].Value
                }
            }
            if ($null -eq $Mode) {
                $Mode = $RestrictedSearchMode.ToString()
            }
        }

        $ModeText = "Unknown"
        if ($null -ne $Mode -and -not [string]::IsNullOrWhiteSpace([string]$Mode)) {
            $ModeText = [string]$Mode
        }

        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object = "SharePoint Online"
        $ConfigObject.ConfigItem = "Restricted SharePoint Search mode"
        $ConfigObject.ConfigData = $ModeText

        if ($ModeText -ieq "Enabled" -or $ModeText -imatch "\bEnabled\b") {
            $ConfigObject.InfoText = "Restricted SharePoint Search is enabled. Continue remediating overshared sites before broadening Copilot grounding scope."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
        }
        else {
            $ConfigObject.InfoText = "Enable Restricted SharePoint Search as a temporary containment measure while reviewing site permissions, sensitivity labels, and data risk assessment findings for Copilot readiness."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
        }

        $this.AddConfig($ConfigObject)
        $this.Completed = $True
    }
}
