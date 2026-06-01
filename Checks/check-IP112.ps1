using module "..\CAMP.psm1"

class IP112 : CAMPCheck {
    <#
        Enable container labels for SharePoint sites and Microsoft Teams
        Based on Microsoft Purview Deployment Models: Secure by Default, Lightweight DLP, and Copilot Agents Blueprints
    #>

    IP112() {
        $this.Control            = "IP-112"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Information Protection"
        $this.Name               = "Enable Container Labels for SharePoint Sites and Microsoft Teams"
        $this.PassText           = "Your organization has sensitivity labels configured for both SharePoint sites and Microsoft Teams containers"
        $this.FailRecommendation = "Your organization should enable container labels for SharePoint sites and Microsoft Teams"
        $this.Importance         = "Secure by Default Step 1 recommends extending sensitivity labeling to containers so SharePoint sites and Teams inherit privacy, external sharing, and access controls. Container labels help protect collaboration spaces before sensitive data is added, which is important for both Lightweight DLP and Copilot agent grounding scenarios. This capability generally requires Microsoft 365 E3 with Information Protection and Governance or equivalent licensing."
        $this.ExpandResults      = $True
        $this.ItemName           = "Container Label Coverage"
        $this.DataType           = "Label Counts"

        $this.Blueprint        = [CAMPBlueprint]::SecureByDefault -bor [CAMPBlueprint]::LightweightDLP -bor [CAMPBlueprint]::CopilotAgents
        $this.MaturityLevel    = [CAMPMaturityLevel]::Good
        $this.BlueprintStages  = @{ "SecureByDefault" = 1; "LightweightDLP" = 3 }
        $this.RequiredCollections = @("GetLabel")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E3 + Information Protection and Governance")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.microsoft.us"
                "Use sensitivity labels with Microsoft Teams, Microsoft 365 groups, and SharePoint sites" = "https://learn.microsoft.com/purview/sensitivity-labels-teams-groups-sites"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.apps.mil"
                "Use sensitivity labels with Microsoft Teams, Microsoft 365 groups, and SharePoint sites" = "https://learn.microsoft.com/purview/sensitivity-labels-teams-groups-sites"
            }
        }
        else {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Lightweight Guide to Mitigate Data Leakage"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
                "Microsoft Purview portal - Information Protection" = "https://purview.microsoft.com"
                "Use sensitivity labels with Microsoft Teams, Microsoft 365 groups, and SharePoint sites" = "https://learn.microsoft.com/purview/sensitivity-labels-teams-groups-sites"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs sensitivity label content types from Get-Label.")
                return
            }
        }

        $SiteLabels = @()
        $TeamsLabels = @()

        ForEach ($Label in $Config["GetLabel"]) {
            $LabelName = $Label.DisplayName
            if ([string]::IsNullOrWhiteSpace($LabelName)) { $LabelName = $Label.Name }
            $ContentTypeText = (@($Label.ContentType) -join ",")

            if ($ContentTypeText -match "(?i)(^|[,;\s])Site($|[,;\s])") {
                $SiteLabels += $LabelName
            }
            if ($ContentTypeText -match "(?i)(^|[,;\s])UnifiedGroup($|[,;\s])") {
                $TeamsLabels += $LabelName
            }
        }

        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object = "Container Label Coverage"
        $ConfigObject.ConfigItem = "SharePoint site labels: $($SiteLabels.Count); Teams labels: $($TeamsLabels.Count)"
        $ConfigObject.ConfigData = "Site labels: $($SiteLabels -join ', ') | Teams labels: $($TeamsLabels -join ', ')"

        if ($SiteLabels.Count -gt 0 -and $TeamsLabels.Count -gt 0) {
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
        }
        else {
            $Missing = @()
            if ($SiteLabels.Count -eq 0) { $Missing += "SharePoint site labels" }
            if ($TeamsLabels.Count -eq 0) { $Missing += "Microsoft Teams labels" }
            $ConfigObject.ConfigData = "Missing: $($Missing -join ', ')"
            $ConfigObject.InfoText = "Enable container label support and publish labels for both Site and UnifiedGroup content types so SharePoint sites and Teams can be protected consistently."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
        }
        $this.AddConfig($ConfigObject)

        if ($this.HasCollection($Config, "GetSpoSites")) {
            $LabeledSiteCount = 0
            $TotalSiteCount = @($Config["GetSpoSites"]).Count
            ForEach ($Site in $Config["GetSpoSites"]) {
                $HasSensitivityLabel = $false
                foreach ($Property in $Site.PSObject.Properties) {
                    if ($Property.Name -match "(?i)sensitivity.*label" -and -not [string]::IsNullOrWhiteSpace("$($Property.Value)")) {
                        $HasSensitivityLabel = $true
                    }
                }
                if ($null -ne $Site.AdditionalProperties) {
                    if ($Site.AdditionalProperties -is [System.Collections.IDictionary] -and $Site.AdditionalProperties.ContainsKey("sensitivityLabel")) {
                        if (-not [string]::IsNullOrWhiteSpace("$($Site.AdditionalProperties["sensitivityLabel"])") ) {
                            $HasSensitivityLabel = $true
                        }
                    }
                    elseif ($null -ne $Site.AdditionalProperties.PSObject.Properties["sensitivityLabel"]) {
                        if (-not [string]::IsNullOrWhiteSpace("$($Site.AdditionalProperties.PSObject.Properties["sensitivityLabel"].Value)") ) {
                            $HasSensitivityLabel = $true
                        }
                    }
                }
                if ($HasSensitivityLabel) { $LabeledSiteCount++ }
            }

            $SiteConfigObject = [CAMPCheckConfig]::new()
            $SiteConfigObject.Object = "SharePoint Site Label Assignments"
            $SiteConfigObject.ConfigItem = "Graph enrichment"
            $SiteConfigObject.ConfigData = "$LabeledSiteCount of $TotalSiteCount sampled sites have a sensitivity label value"
            $SiteConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            $this.AddConfig($SiteConfigObject)
        }

        $this.Completed = $true
    }
}
