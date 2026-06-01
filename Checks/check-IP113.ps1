using module "..\CAMP.psm1"

class IP113 : CAMPCheck {
    <#
        Configure default sharing links by sensitivity label
        Based on Microsoft Purview Deployment Models: Secure by Default Blueprint
    #>

    IP113() {
        $this.Control            = "IP-113"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Information Protection"
        $this.Name               = "Configure Default Sharing Link by Sensitivity Label"
        $this.PassText           = "Your organization has default sharing link settings configured on at least one SharePoint site sensitivity label"
        $this.FailRecommendation = "Your organization should configure default sharing link type and scope on SharePoint site sensitivity labels"
        $this.Importance         = "Secure by Default Step 1 recommends using container labels to make safer sharing the default for collaboration spaces. Default sharing link settings on site labels reduce accidental broad sharing by aligning SharePoint link behavior with the sensitivity of the site. This capability generally requires Microsoft 365 E3 with Information Protection and Governance or equivalent licensing."
        $this.ExpandResults      = $True
        $this.ItemName           = "Site Sensitivity Label"
        $this.DataType           = "Default Sharing Link"

        $this.Blueprint        = [CAMPBlueprint]::SecureByDefault
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "SecureByDefault" = 1 }
        $this.RequiredCollections = @("GetLabel")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E3 + Information Protection and Governance")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.microsoft.us"
                "Use sensitivity labels with Microsoft Teams, Microsoft 365 groups, and SharePoint sites" = "https://learn.microsoft.com/purview/sensitivity-labels-teams-groups-sites"
                "Manage sensitivity labels in Office apps"         = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.apps.mil"
                "Use sensitivity labels with Microsoft Teams, Microsoft 365 groups, and SharePoint sites" = "https://learn.microsoft.com/purview/sensitivity-labels-teams-groups-sites"
                "Manage sensitivity labels in Office apps"         = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
        else {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://purview.microsoft.com"
                "Use sensitivity labels with Microsoft Teams, Microsoft 365 groups, and SharePoint sites" = "https://learn.microsoft.com/purview/sensitivity-labels-teams-groups-sites"
                "Manage sensitivity labels in Office apps"         = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs site label settings from Get-Label.")
                return
            }
        }

        $SiteLabelCount = 0
        $LabelsWithSharingDefaults = @()

        ForEach ($Label in $Config["GetLabel"]) {
            $LabelName = $Label.DisplayName
            if ([string]::IsNullOrWhiteSpace($LabelName)) { $LabelName = $Label.Name }
            $ContentTypeText = (@($Label.ContentType) -join ",")
            if ($ContentTypeText -notmatch "(?i)(^|[,;\s])Site($|[,;\s])") {
                continue
            }

            $SiteLabelCount++
            $SettingsFound = @()
            foreach ($Setting in @($Label.Settings)) {
                if ($Setting -match "(?i)DefaultShareLink(Type|Scope)\s*[:=]\s*[^\s;]+") {
                    $SettingsFound += $Setting
                }
            }

            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = $LabelName
            if ($SettingsFound.Count -gt 0) {
                $LabelsWithSharingDefaults += $LabelName
                $ConfigObject.ConfigItem = "Default sharing link configured"
                $ConfigObject.ConfigData = ($SettingsFound | Select-Object -Unique) -join "; "
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $ConfigObject.ConfigItem = "Default sharing link not configured"
                $ConfigObject.ConfigData = "DefaultShareLinkType and DefaultShareLinkScope were not found in advanced settings"
                $ConfigObject.InfoText = "Configure default sharing link type and scope on site labels to align sharing defaults with label sensitivity."
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            }
            $this.AddConfig($ConfigObject)
        }

        if ($SiteLabelCount -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Site Labels"
            $ConfigObject.ConfigItem = "No sensitivity labels with Site content type found"
            $ConfigObject.ConfigData = "Container labels are required before label-based sharing defaults can be configured"
            $ConfigObject.InfoText = "Enable sensitivity labels for SharePoint site containers, then configure DefaultShareLinkType and DefaultShareLinkScope."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }
        elseif ($LabelsWithSharingDefaults.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "<B>Secure by Default Recommendation</B>"
            $ConfigObject.ConfigItem = "No site labels define sharing link defaults"
            $ConfigObject.ConfigData = "Site labels reviewed: $SiteLabelCount"
            $ConfigObject.InfoText = "Secure by Default Step 1 recommends using site labels to control collaboration defaults, including default sharing link type and scope."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}
