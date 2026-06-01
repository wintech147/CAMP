using module "..\CAMP.psm1"

class DLP203 : CAMPCheck {
    <#

        Dedicated DLP Policy for Exchange Email
        Based on Microsoft Purview Deployment Models: Lightweight DLP Blueprint

    #>

    DLP203() {
        $this.Control = "DLP-203"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Data Loss Prevention"
        $this.Name = "Maintain a Dedicated DLP Policy for Exchange Email"
        $this.PassText = "Your organization has a dedicated enabled DLP policy for Exchange email"
        $this.FailRecommendation = "Your organization should maintain a dedicated DLP policy scoped only to Exchange email"
        $this.Importance = "The Lightweight DLP deployment model Step 1 recommends a separate policy for Exchange email so email-specific user notifications, exceptions, and tuning can be managed independently from SharePoint, OneDrive, Teams, and endpoint DLP. Core Exchange DLP is available with Microsoft 365 Business Premium and E3+IPG licensing; advanced DLP capabilities may require Microsoft 365 E5 Compliance."
        $this.ExpandResults = $True
        $this.CheckType = [CheckType]::ObjectPropertyValue
        $this.ObjectType = "DLP Policy"
        $this.ItemName = "Policy Scope"
        $this.DataType = "Configuration Status"
        $this.Blueprint = [CAMPBlueprint]::LightweightDLP
        $this.MaturityLevel = [CAMPMaturityLevel]::Good
        $this.BlueprintStages = @{ "LightweightDLP" = 1 }
        $this.RequiredCollections = @("GetDlpCompliancePolicy")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses = @()
        $this.CommercialOnly = $false
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Lightweight DLP Step 1"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step1"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-gcch-dlp-compliance-center"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Lightweight DLP overview"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Lightweight DLP Step 1"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step1"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dod-dlp-compliance-center"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Lightweight DLP overview"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
            }
        }else
        {
            $this.Links = @{
                "Lightweight DLP Step 1"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step1"
                "Microsoft Purview portal - Data Loss Prevention" = "https://purview.microsoft.com"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Lightweight DLP overview"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs Get-DlpCompliancePolicy from Security & Compliance PowerShell.")
                return
            }
        }

        $HasLocation = {
            param($Value)

            $Items = @($Value) | Where-Object { $null -ne $_ -and "$_".Trim() -ne "" -and "$_" -ine "None" }
            return ($Items.Count -gt 0)
        }

        $GetLocationText = {
            param($Value)

            $Items = @($Value) | Where-Object { $null -ne $_ -and "$_".Trim() -ne "" -and "$_" -ine "None" }
            if ($Items.Count -eq 0) {
                return "Not configured"
            }

            return ($Items -join ", ")
        }

        $EmailOnlyPolicies = @()

        ForEach ($CompliancePolicy in $Config["GetDlpCompliancePolicy"]) {
            if ($CompliancePolicy.Mode -ieq "Enable") {
                $HasExchangeLocation = & $HasLocation $CompliancePolicy.ExchangeLocation
                $HasSharePointLocation = & $HasLocation $CompliancePolicy.SharePointLocation
                $HasOneDriveLocation = & $HasLocation $CompliancePolicy.OneDriveLocation
                $HasTeamsLocation = & $HasLocation $CompliancePolicy.TeamsLocation
                $HasEndpointLocation = & $HasLocation $CompliancePolicy.EndpointDlpLocation

                if ($HasExchangeLocation -and -not $HasSharePointLocation -and -not $HasOneDriveLocation -and -not $HasTeamsLocation -and -not $HasEndpointLocation) {
                    $ConfigObject = [CAMPCheckConfig]::new()
                    $ConfigObject.Object = $CompliancePolicy.Name
                    $ConfigObject.ConfigItem = "Exchange: $(& $GetLocationText $CompliancePolicy.ExchangeLocation)"
                    $ConfigObject.ConfigData = "Enabled policy is scoped only to Exchange email"
                    $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                    $this.AddConfig($ConfigObject)

                    $EmailOnlyPolicies += $CompliancePolicy.Name
                }
            }
        }

        if ($EmailOnlyPolicies.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Dedicated Exchange DLP Policy"
            $ConfigObject.ConfigItem = "No enabled email-only DLP policy found"
            $ConfigObject.ConfigData = "No enabled DLP policy has Exchange populated while SharePoint, OneDrive, Teams, and Endpoint DLP locations are empty"
            $ConfigObject.InfoText = "The Lightweight DLP Step 1 blueprint recommends keeping Exchange email in a separate DLP policy. Create or enable an Exchange-only policy in the Microsoft Purview portal so email tuning does not affect other workloads."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}

