using module "..\CAMP.psm1"

class IP107 : CAMPCheck {
    <#

        SharePoint/OneDrive Sensitivity Labels Integration
        Based on Microsoft Purview Deployment Models: Secure by Default Blueprint

    #>

    IP107() {
        $this.Control = "IP-107"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Information Protection"
        $this.Name = "Enable Sensitivity Labels for SharePoint and OneDrive"
        $this.PassText = "Your organization has enabled sensitivity labels for SharePoint and OneDrive files"
        $this.FailRecommendation = "Your organization should enable sensitivity labels for SharePoint and OneDrive to support container-based labeling"
        $this.Importance = "Enabling sensitivity labels for SharePoint and OneDrive allows files to inherit labels from their container (site/library), achieving rapid protection scale with minimal user interaction. This is a foundational component of the Secure by Default approach, enabling default library labeling where all new documents automatically receive the library's sensitivity label."
        $this.ExpandResults = $True
        $this.ItemName = "Configuration"
        $this.DataType = "Status"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://aka.ms/PurviewDeploymentModels/SecureByDefault"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-gcch-ip-compliance-center"
                "Enable sensitivity labels for files in SharePoint and OneDrive" = "https://learn.microsoft.com/en-us/purview/sensitivity-labels-sharepoint-onedrive-files"
                "Default sensitivity labels for SharePoint libraries" = "https://learn.microsoft.com/en-us/purview/sensitivity-labels-sharepoint-default-label"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://aka.ms/PurviewDeploymentModels/SecureByDefault"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-dod-ip-compliance-center"
                "Enable sensitivity labels for files in SharePoint and OneDrive" = "https://learn.microsoft.com/en-us/purview/sensitivity-labels-sharepoint-onedrive-files"
                "Default sensitivity labels for SharePoint libraries" = "https://learn.microsoft.com/en-us/purview/sensitivity-labels-sharepoint-default-label"
            }
        }else
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://aka.ms/PurviewDeploymentModels/SecureByDefault"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-ip-compliance-center"
                "Enable sensitivity labels for files in SharePoint and OneDrive" = "https://learn.microsoft.com/en-us/purview/sensitivity-labels-sharepoint-onedrive-files"
                "Default sensitivity labels for SharePoint libraries" = "https://learn.microsoft.com/en-us/purview/sensitivity-labels-sharepoint-default-label"
            }
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config) {
        if ($Config["GetLabel"] -eq "Error") {
            $this.Completed = $false
        }
        else {
            # Check if any labels have the Files scope enabled (indicates SPO/ODB integration)
            $LabelsWithFilesScope = @()
            $LabelsWithContainerScope = @()

            ForEach ($Label in $Config["GetLabel"]) {
                # Check ContentType/Scope for Files capability
                $HasFilesScope = $false
                $HasContainerScope = $false

                if ($null -ne $Label.ContentType) {
                    # ContentType can include File, Email, Site, UnifiedGroup, etc.
                    $ContentTypes = $Label.ContentType -split ","
                    foreach ($ct in $ContentTypes) {
                        $ct = $ct.Trim()
                        if ($ct -eq "File" -or $ct -match "File") {
                            $HasFilesScope = $true
                        }
                        if ($ct -eq "Site" -or $ct -eq "UnifiedGroup" -or $ct -match "Site" -or $ct -match "UnifiedGroup") {
                            $HasContainerScope = $true
                        }
                    }
                }

                if ($HasFilesScope) {
                    $LabelsWithFilesScope += $Label.DisplayName
                }
                if ($HasContainerScope) {
                    $LabelsWithContainerScope += $Label.DisplayName
                }
            }

            # Report on Files scope (SPO/ODB file labeling)
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "Sensitivity Labels for Files"

            if ($LabelsWithFilesScope.Count -gt 0) {
                $ConfigObject.ConfigItem = "$($LabelsWithFilesScope.Count) labels configured for files"
                $ConfigObject.ConfigData = "Labels: $($LabelsWithFilesScope[0..([Math]::Min(4, $LabelsWithFilesScope.Count-1))] -join ', ')$(if($LabelsWithFilesScope.Count -gt 5){' and more...'})"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $ConfigObject.ConfigItem = "No labels configured for files"
                $ConfigObject.ConfigData = "Sensitivity labels are not configured with the Files scope"
                $ConfigObject.InfoText = "Create sensitivity labels with the 'Files & other data assets' scope to enable labeling in SharePoint and OneDrive."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            }
            $this.AddConfig($ConfigObject)

            # Report on Container scope (Sites and Groups labeling)
            $ConfigObject2 = [CAMPCheckConfig]::new()
            $ConfigObject2.Object = "Sensitivity Labels for Containers (Sites/Teams)"

            if ($LabelsWithContainerScope.Count -gt 0) {
                $ConfigObject2.ConfigItem = "$($LabelsWithContainerScope.Count) labels configured for containers"
                $ConfigObject2.ConfigData = "Labels: $($LabelsWithContainerScope[0..([Math]::Min(4, $LabelsWithContainerScope.Count-1))] -join ', ')$(if($LabelsWithContainerScope.Count -gt 5){' and more...'})"
                $ConfigObject2.InfoText = "Container labels can automatically apply a default sensitivity label to all files in a SharePoint site or document library."
                $ConfigObject2.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $ConfigObject2.ConfigItem = "No labels configured for containers"
                $ConfigObject2.ConfigData = "Sensitivity labels are not configured with the Sites/Groups scope"
                $ConfigObject2.InfoText = "Create sensitivity labels with the 'Groups & sites' scope to enable container-based labeling. This allows files to inherit labels from their SharePoint site."
                $ConfigObject2.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            }
            $this.AddConfig($ConfigObject2)

            # Overall recommendation if neither is configured
            if ($LabelsWithFilesScope.Count -eq 0 -and $LabelsWithContainerScope.Count -eq 0) {
                $ConfigObject3 = [CAMPCheckConfig]::new()
                $ConfigObject3.Object = "<B>Secure by Default Recommendation</B>"
                $ConfigObject3.ConfigItem = "SharePoint/OneDrive labeling not fully enabled"
                $ConfigObject3.ConfigData = "No sensitivity labels are configured for files or containers"
                $ConfigObject3.InfoText = "Microsoft's Secure by Default blueprint recommends enabling sensitivity labels for SharePoint and OneDrive. Run '(Get-SPOTenant).EnableAIPIntegration' in SharePoint Online PowerShell to verify tenant-level enablement, then create labels with appropriate scopes."
                $ConfigObject3.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
                $this.AddConfig($ConfigObject3)
            }

            $this.Completed = $True
        }
    }

}
