using module "..\CAMP.psm1"

class IP106 : CAMPCheck {
    <#

        Justification Required for Label Downgrade
        Based on Microsoft Purview Deployment Models: Secure by Default Blueprint

    #>

    IP106() {
        $this.Control = "IP-106"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Information Protection"
        $this.Name = "Require Justification for Sensitivity Label Downgrade or Removal"
        $this.Blueprint = [CAMPBlueprint]::SecureByDefault
        $this.MaturityLevel = [CAMPMaturityLevel]::Good
        $this.PassText = "Your organization requires justification when users downgrade or remove sensitivity labels"
        $this.FailRecommendation = "Your organization should require justification when users downgrade or remove sensitivity labels"
        $this.Importance = "Requiring justification when users remove or lower the classification of a sensitivity label helps prevent accidental or intentional removal of protection without an audit trail. This is a key control in the Secure by Default approach, ensuring accountability and enabling investigation of potential data handling issues."
        $this.ExpandResults = $True
        $this.ItemName = "Label Policy"
        $this.DataType = "Justification Requirement"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-gcch-ip-compliance-center"
                "Sensitivity label policy settings"           = "https://learn.microsoft.com/en-us/purview/sensitivity-labels-office-apps#what-label-policies-can-do"
                "Compliance Manager - IP Actions"             = "https://aka.ms/mcca-gcch-ip-compliance-manager"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-dod-ip-compliance-center"
                "Sensitivity label policy settings"           = "https://learn.microsoft.com/en-us/purview/sensitivity-labels-office-apps#what-label-policies-can-do"
                "Compliance Manager - IP Actions"             = "https://aka.ms/mcca-dod-ip-compliance-manager"
            }
        }else
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-ip-compliance-center"
                "Sensitivity label policy settings"           = "https://learn.microsoft.com/en-us/purview/sensitivity-labels-office-apps#what-label-policies-can-do"
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
            $HasJustificationRequirement = $false
            $PoliciesWithoutJustification = @()

            ForEach ($Policy in $Config["GetLabelPolicy"]) {
                if ($Policy.Enabled -eq $true) {
                    $ConfigObject = [CAMPCheckConfig]::new()
                    $ConfigObject.Object = $Policy.Name

                    # Check for RequireDowngradeJustification setting
                    $RequiresJustification = $false
                    $PolicySettings = $Policy.Settings

                    # Check the Settings property for RequireDowngradeJustification
                    if ($null -ne $PolicySettings) {
                        foreach ($setting in $PolicySettings) {
                            if ($setting -match "RequireDowngradeJustification.*True" -or
                                $setting -match "requiredowngradejustification.*true") {
                                $RequiresJustification = $true
                                break
                            }
                        }
                    }

                    # Also check direct property if available
                    if ($null -ne $Policy.RequireDowngradeJustification) {
                        $RequiresJustification = $Policy.RequireDowngradeJustification
                    }

                    $ExchangeLocation = $Policy.ExchangeLocation
                    $IsGlobalPolicy = (@($ExchangeLocation) -like 'All').Count -gt 0

                    if ($RequiresJustification -eq $true) {
                        $ConfigObject.ConfigItem = "Justification required: Yes"
                        if ($IsGlobalPolicy) {
                            $ConfigObject.ConfigData = "Global policy requires justification for label downgrade or removal"
                        } else {
                            $ConfigObject.ConfigData = "Scoped policy requires justification for label downgrade or removal"
                        }
                        $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                        $HasJustificationRequirement = $true
                    }
                    else {
                        $ConfigObject.ConfigItem = "Justification required: No"
                        if ($IsGlobalPolicy) {
                            $ConfigObject.ConfigData = "Global policy does not require justification"
                            $ConfigObject.InfoText = "Enable 'Require users to provide justification to remove a label or lower its classification' in this global policy to maintain audit trail and accountability."
                        } else {
                            $ConfigObject.ConfigData = "Scoped policy does not require justification"
                            $ConfigObject.InfoText = "Consider enabling justification requirement for this scoped policy."
                        }
                        $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                        $PoliciesWithoutJustification += $Policy.Name
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
                $ConfigObject.InfoText = "Create sensitivity label policies with justification requirements enabled."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                $this.AddConfig($ConfigObject)
            }

            # Summary recommendation if no justification requirements found
            if (-not $HasJustificationRequirement -and $Config["GetLabelPolicy"].Count -gt 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = "<B>Secure by Default Recommendation</B>"
                $ConfigObject.ConfigItem = "No policies require downgrade justification"
                $ConfigObject.ConfigData = "Policies without justification: $($PoliciesWithoutJustification -join ', ')"
                $ConfigObject.InfoText = "Microsoft's Secure by Default blueprint recommends requiring users to provide justification when removing or lowering a sensitivity label classification. This creates an audit trail and deters inappropriate label changes."
                $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
                $this.AddConfig($ConfigObject)
            }

            $this.Completed = $True
        }
    }

}
