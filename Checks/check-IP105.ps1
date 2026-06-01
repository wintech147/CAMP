using module "..\CAMP.psm1"

class IP105 : CAMPCheck {
    <#

        Secure by Default - Default Sensitivity Label Policy
        Based on Microsoft Purview Deployment Models: Secure by Default Blueprint

    #>

    IP105() {
        $this.Control = "IP-105"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Information Protection"
        $this.Name = "Configure Default Sensitivity Label for All Content"
        $this.Blueprint = [CAMPBlueprint]::SecureByDefault -bor [CAMPBlueprint]::LightweightDLP
        $this.MaturityLevel = [CAMPMaturityLevel]::Good
        $this.PassText = "Your organization has configured a default sensitivity label policy"
        $this.FailRecommendation = "Your organization should configure a default sensitivity label to protect all content by default"
        $this.Importance = "The Secure by Default approach recommends applying a default sensitivity label to all content automatically. This shifts user training from 'when to apply protection' to 'when to remove protection', ensuring baseline protection across your Microsoft 365 environment. Microsoft recommends using labels like 'Confidential\All Employees' or 'General\All Employees' as the default."
        $this.ExpandResults = $True
        $this.ItemName = "Label Policy"
        $this.DataType = "Default Label Status"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-gcch-ip-compliance-center"
                "Default labels for sensitivity"              = "https://learn.microsoft.com/en-us/purview/mip-easy-trials"
                "Compliance Manager - IP Actions"             = "https://aka.ms/mcca-gcch-ip-compliance-manager"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-dod-ip-compliance-center"
                "Default labels for sensitivity"              = "https://learn.microsoft.com/en-us/purview/mip-easy-trials"
                "Compliance Manager - IP Actions"             = "https://aka.ms/mcca-dod-ip-compliance-manager"
            }
        }else
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-ip-compliance-center"
                "Default labels for sensitivity"              = "https://learn.microsoft.com/en-us/purview/mip-easy-trials"
                "Compliance Manager - IP Actions"             = "https://aka.ms/mcca-ip-compliance-manager"
            }
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config) {
        if (($Config["GetLabel"] -eq "Error") -or ($Config["GetLabelPolicy"] -eq "Error")) {
            $this.Completed = $false
        }
        else {
            $HasDefaultLabel = $false
            $DefaultLabelPolicies = @()

            ForEach ($Policy in $Config["GetLabelPolicy"]) {
                if ($Policy.Enabled -eq $true) {
                    $ConfigObject = [CAMPCheckConfig]::new()
                    $ConfigObject.Object = $Policy.Name

                    # Check for default label settings in the policy
                    # The Settings property contains advanced settings including DefaultLabelId
                    $PolicySettings = $Policy.Settings
                    $DefaultLabelId = $null

                    # Parse settings to find DefaultLabelId
                    if ($null -ne $PolicySettings) {
                        foreach ($setting in $PolicySettings) {
                            if ($setting -match "DefaultLabelId") {
                                $DefaultLabelId = $setting -replace ".*DefaultLabelId[:\s]*", "" -replace "[}\]].*", ""
                                $DefaultLabelId = $DefaultLabelId.Trim()
                            }
                        }
                    }

                    # Also check DefaultLabel property directly if available
                    if ($null -eq $DefaultLabelId -or $DefaultLabelId -eq "") {
                        if ($null -ne $Policy.DefaultLabel -and $Policy.DefaultLabel -ne "") {
                            $DefaultLabelId = $Policy.DefaultLabel
                        }
                    }

                    if ($null -ne $DefaultLabelId -and $DefaultLabelId -ne "" -and $DefaultLabelId -ne "None") {
                        # Find the label name
                        $DefaultLabelName = "Unknown"
                        foreach ($Label in $Config["GetLabel"]) {
                            if ($Label.Guid -eq $DefaultLabelId -or $Label.ImmutableId -eq $DefaultLabelId) {
                                $DefaultLabelName = $Label.DisplayName
                                break
                            }
                        }

                        $ConfigObject.ConfigItem = "Default Label: $DefaultLabelName"
                        $ConfigObject.ConfigData = "Default sensitivity label is configured for this policy"
                        $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                        $HasDefaultLabel = $true
                        $DefaultLabelPolicies += $Policy.Name
                    }
                    else {
                        $ConfigObject.ConfigItem = "No default label configured"
                        $ConfigObject.ConfigData = "This policy does not have a default sensitivity label"
                        $ConfigObject.InfoText = "Configure a default sensitivity label (e.g., 'General\All Employees' or 'Confidential\All Employees') to ensure all content is protected by default."
                        $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                    }

                    $this.AddConfig($ConfigObject)
                }
            }

            # If no policies exist at all
            if ($Config["GetLabelPolicy"].Count -eq 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = "No Label Policies"
                $ConfigObject.ConfigItem = "No sensitivity label policies found"
                $ConfigObject.ConfigData = "Your organization has not configured any sensitivity label policies"
                $ConfigObject.InfoText = "Create sensitivity label policies with default labels to implement Secure by Default protection."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                $this.AddConfig($ConfigObject)
            }

            # Summary recommendation if no default labels found
            if (-not $HasDefaultLabel -and $Config["GetLabelPolicy"].Count -gt 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = "<B>Secure by Default Recommendation</B>"
                $ConfigObject.ConfigItem = "No default sensitivity labels configured"
                $ConfigObject.ConfigData = "None of your label policies have a default label configured"
                $ConfigObject.InfoText = "Microsoft's Secure by Default blueprint recommends configuring a default label such as 'Confidential\All Employees' to protect all new content automatically."
                $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
                $this.AddConfig($ConfigObject)
            }

            $this.Completed = $True
        }
    }

}
