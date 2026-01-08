using module "..\CAMP.psm1"

class DLP201 : CAMPCheck {
    <#

        DLP Policy for External Sharing of Labeled Content
        Based on Microsoft Purview Deployment Models: Secure by Default & Oversharing Prevention Blueprints

    #>

    DLP201() {
        $this.Control = "DLP-201"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Data Loss Prevention"
        $this.Name = "Restrict External Sharing of Sensitivity Labeled Content"
        $this.PassText = "Your organization has DLP policies restricting external sharing of labeled content"
        $this.FailRecommendation = "Your organization should create DLP policies that restrict external sharing of Confidential and Highly Confidential labeled content"
        $this.Importance = "The Secure by Default blueprint recommends using DLP policies to restrict external sharing of sensitivity labeled content. This prevents oversharing by blocking or warning when users attempt to share Confidential or Highly Confidential content with external recipients. This is a foundational control for preventing data leakage."
        $this.ExpandResults = $True
        $this.CheckType = [CheckType]::ObjectPropertyValue
        $this.ObjectType = "DLP Policy"
        $this.ItemName = "Sensitivity Labels"
        $this.DataType = "Protection Status"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://aka.ms/PurviewDeploymentModels/SecureByDefault"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-gcch-dlp-compliance-center"
                "DLP policy conditions and exceptions"        = "https://learn.microsoft.com/en-us/purview/dlp-policy-reference"
                "Oversharing Prevention Blueprint"            = "https://aka.ms/purviewdeploymentmodels"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://aka.ms/PurviewDeploymentModels/SecureByDefault"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dod-dlp-compliance-center"
                "DLP policy conditions and exceptions"        = "https://learn.microsoft.com/en-us/purview/dlp-policy-reference"
                "Oversharing Prevention Blueprint"            = "https://aka.ms/purviewdeploymentmodels"
            }
        }else
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://aka.ms/PurviewDeploymentModels/SecureByDefault"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dlp-compliance-center"
                "DLP policy conditions and exceptions"        = "https://learn.microsoft.com/en-us/purview/dlp-policy-reference"
                "Oversharing Prevention Blueprint"            = "https://aka.ms/purviewdeploymentmodels"
            }
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config) {
        if (($Config["GetDlpComplianceRule"] -eq "Error") -or ($Config["GetDlpCompliancePolicy"] -eq "Error")) {
            $this.Completed = $false
        }
        else {
            $PoliciesWithLabelProtection = @()
            $PoliciesWithExternalScope = @()
            $ProtectedLabels = @()

            ForEach ($CompliancePolicy in $Config["GetDlpCompliancePolicy"]) {
                if ($CompliancePolicy.Mode -ieq "Enable" -or $CompliancePolicy.Mode -ieq "TestWithNotifications") {
                    $PolicyName = $CompliancePolicy.Name
                    $HasLabelCondition = $false
                    $HasExternalScope = $false
                    $LabelsInPolicy = @()

                    # Check the rules for this policy
                    ForEach ($Rule in $Config["GetDlpComplianceRule"]) {
                        if ($Rule.ParentPolicyName -eq $PolicyName) {
                            # Check if rule uses sensitivity labels as condition
                            if ($null -ne $Rule.ContentContainsSensitivityLabels -and $Rule.ContentContainsSensitivityLabels.Count -gt 0) {
                                $HasLabelCondition = $true
                                foreach ($labelId in $Rule.ContentContainsSensitivityLabels) {
                                    if ($LabelsInPolicy -notcontains $labelId) {
                                        $LabelsInPolicy += $labelId
                                    }
                                }
                            }

                            # Check for external/NotInOrganization access scope
                            if ($Rule.AccessScope -eq "NotInOrganization") {
                                $HasExternalScope = $true
                            }
                        }
                    }

                    if ($HasLabelCondition) {
                        $ConfigObject = [CAMPCheckConfig]::new()
                        $ConfigObject.Object = $PolicyName

                        # Map label IDs to names if possible
                        $LabelNames = @()
                        if ($null -ne $Config["GetLabel"]) {
                            foreach ($labelId in $LabelsInPolicy) {
                                $labelMatch = $Config["GetLabel"] | Where-Object { $_.Guid -eq $labelId -or $_.ImmutableId -eq $labelId }
                                if ($null -ne $labelMatch) {
                                    $LabelNames += $labelMatch.DisplayName
                                } else {
                                    $LabelNames += $labelId
                                }
                            }
                        } else {
                            $LabelNames = $LabelsInPolicy
                        }

                        $ConfigObject.ConfigItem = "Labels: $($LabelNames -join ', ')"

                        $PoliciesWithLabelProtection += $PolicyName
                        $ProtectedLabels += $LabelNames

                        if ($HasExternalScope) {
                            $ConfigObject.ConfigData = "Policy restricts external sharing of labeled content"
                            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                            $PoliciesWithExternalScope += $PolicyName
                        } else {
                            $ConfigObject.ConfigData = "Policy uses labels but may not restrict external sharing"
                            $ConfigObject.InfoText = "Consider adding 'Content is shared from Microsoft 365 - with people outside my organization' condition to strengthen external sharing protection."
                            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
                        }

                        $this.AddConfig($ConfigObject)
                    }
                }
            }

            # If no policies protect labeled content
            if ($PoliciesWithLabelProtection.Count -eq 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = "No Label-Based DLP Policies"
                $ConfigObject.ConfigItem = "No DLP policies found using sensitivity labels"
                $ConfigObject.ConfigData = "Your organization has not configured DLP policies that use sensitivity labels as conditions"
                $ConfigObject.InfoText = "Create DLP policies that detect Confidential and Highly Confidential labeled content and restrict external sharing. This is a key recommendation in the Secure by Default and Oversharing Prevention blueprints."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                $this.AddConfig($ConfigObject)
            }

            # Summary recommendation
            if ($PoliciesWithLabelProtection.Count -gt 0 -and $PoliciesWithExternalScope.Count -eq 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = "<B>Oversharing Prevention Recommendation</B>"
                $ConfigObject.ConfigItem = "No policies explicitly target external sharing"
                $ConfigObject.ConfigData = "$($PoliciesWithLabelProtection.Count) policy(ies) use labels but none explicitly restrict external sharing"
                $ConfigObject.InfoText = "Microsoft's Secure by Default blueprint recommends DLP policies that specifically block or warn when labeled content is shared with people outside your organization."
                $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
                $this.AddConfig($ConfigObject)
            }

            $hasRemediation = $this.Config | Where-Object { $_.RemediationAction -ne '' }
            if ($($hasRemediation.count) -gt 0) {
                $this.CAMPRemediationInfo = New-Object -TypeName CAMPRemediationInfo -Property @{
                    RemediationAvailable = $True
                    RemediationText      = "You need to connect to Security & Compliance PowerShell to execute the below commands. Please follow steps defined in <a href = 'https://learn.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps'> Connect to Security & Compliance PowerShell</a>."
                }
            }

            $this.Completed = $True
        }
    }

}
