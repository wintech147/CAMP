using module "..\CAMP.psm1"

class IP110 : CAMPCheck {
    <#
        Configure service-side auto-labeling policies
        Based on Microsoft Purview Deployment Models: Secure by Default and Lightweight DLP Blueprints
    #>

    IP110() {
        $this.Control            = "IP-110"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Information Protection"
        $this.Name               = "Configure Service-Side Auto-Labeling Policies"
        $this.PassText           = "Your organization has at least one enabled service-side auto-labeling policy scoped to Microsoft 365 locations"
        $this.FailRecommendation = "Your organization should enable service-side auto-labeling policies for SharePoint, OneDrive, or Exchange locations"
        $this.Importance         = "Secure by Default Steps 2 and 3 use service-side auto-labeling to find sensitive data at rest and apply protection at scale. Enabling policies for SharePoint, OneDrive, or Exchange helps protect content even when users do not label it manually. Service-side auto-labeling typically requires Microsoft 365 E5 Compliance or equivalent Information Protection advanced licensing."
        $this.ExpandResults      = $True
        $this.ItemName           = "Auto-Labeling Policy"
        $this.DataType           = "Mode and Locations"

        $this.Blueprint        = [CAMPBlueprint]::SecureByDefault -bor [CAMPBlueprint]::LightweightDLP
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "SecureByDefault" = 3; "LightweightDLP" = 3 }
        $this.RequiredCollections = @("GetAutoSensitivityLabelPolicy")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.microsoft.us"
                "Automatically apply a sensitivity label"          = "https://learn.microsoft.com/purview/apply-sensitivity-label-automatically"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.apps.mil"
                "Automatically apply a sensitivity label"          = "https://learn.microsoft.com/purview/apply-sensitivity-label-automatically"
            }
        }
        else {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://purview.microsoft.com"
                "Automatically apply a sensitivity label"          = "https://learn.microsoft.com/purview/apply-sensitivity-label-automatically"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs Get-AutoSensitivityLabelPolicy results.")
                return
            }
        }

        $EnabledPolicies = @()
        $TestModePolicies = @()
        $PoliciesWithLocations = 0

        ForEach ($Policy in $Config["GetAutoSensitivityLabelPolicy"]) {
            $PolicyName = $Policy.Name
            if ([string]::IsNullOrWhiteSpace($PolicyName)) {
                $PolicyName = $Policy.Identity
            }

            $Mode = "$($Policy.Mode)"
            if ([string]::IsNullOrWhiteSpace($Mode)) {
                $Mode = "Unknown"
            }

            $SharePointLocations = @($Policy.SharePointLocation) | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }
            $OneDriveLocations = @($Policy.OneDriveLocation) | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }
            $ExchangeLocations = @($Policy.ExchangeLocation) | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }
            $LocationParts = @()
            if ($SharePointLocations.Count -gt 0) { $LocationParts += "SharePoint: $($SharePointLocations -join ', ')" }
            if ($OneDriveLocations.Count -gt 0) { $LocationParts += "OneDrive: $($OneDriveLocations -join ', ')" }
            if ($ExchangeLocations.Count -gt 0) { $LocationParts += "Exchange: $($ExchangeLocations -join ', ')" }
            if ($LocationParts.Count -eq 0) { $LocationParts += "No SharePoint, OneDrive, or Exchange locations" }

            $HasLocation = ($SharePointLocations.Count -gt 0 -or $OneDriveLocations.Count -gt 0 -or $ExchangeLocations.Count -gt 0)
            if ($HasLocation) { $PoliciesWithLocations++ }
            $IsEnabled = ($Mode -ieq "Enable")
            $IsTestMode = ($Mode -ieq "TestWithNotifications" -or $Mode -ieq "TestWithoutNotifications")

            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = $PolicyName
            $ConfigObject.ConfigItem = "Mode: $Mode"
            $ConfigObject.ConfigData = $LocationParts -join " | "

            if ($IsEnabled -and $HasLocation) {
                $EnabledPolicies += $PolicyName
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            elseif ($IsTestMode) {
                $TestModePolicies += $PolicyName
                $ConfigObject.InfoText = "This policy is in test mode. Review results and enable the policy when ready to apply labels automatically."
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            }
            else {
                $ConfigObject.InfoText = "Enable this service-side auto-labeling policy and scope it to SharePoint, OneDrive, or Exchange."
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            }
            $this.AddConfig($ConfigObject)
        }

        if (@($Config["GetAutoSensitivityLabelPolicy"]).Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Auto-Labeling Policies"
            $ConfigObject.ConfigItem = "No service-side auto-labeling policies found"
            $ConfigObject.ConfigData = "Get-AutoSensitivityLabelPolicy returned no policies"
            $ConfigObject.InfoText = "Create service-side auto-labeling policies in Microsoft Purview and scope them to SharePoint, OneDrive, or Exchange."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }
        elseif ($EnabledPolicies.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "<B>Enable Service-Side Auto-Labeling</B>"
            if ($TestModePolicies.Count -gt 0) {
                $ConfigObject.ConfigItem = "All service-side auto-labeling policies are in test mode or disabled"
                $ConfigObject.ConfigData = "Test mode policies: $($TestModePolicies -join ', ')"
            }
            elseif ($PoliciesWithLocations -eq 0) {
                $ConfigObject.ConfigItem = "No policies are scoped to Microsoft 365 locations"
                $ConfigObject.ConfigData = "Policies exist but none include SharePoint, OneDrive, or Exchange locations"
            }
            else {
                $ConfigObject.ConfigItem = "No enabled service-side auto-labeling policy found"
                $ConfigObject.ConfigData = "Policies exist but none are in Enable mode with a Microsoft 365 location"
            }
            $ConfigObject.InfoText = "Secure by Default Steps 2 and 3 recommend moving validated auto-labeling policies from test mode to enabled enforcement."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}
