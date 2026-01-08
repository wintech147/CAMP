using module "..\CAMP.psm1"

class IP108 : CAMPCheck {
    <#

        Encryption on Confidential Labels
        Based on Microsoft Purview Deployment Models: Secure by Default Blueprint

    #>

    IP108() {
        $this.Control = "IP-108"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Information Protection"
        $this.Name = "Enable Encryption on Confidential and Highly Confidential Labels"
        $this.PassText = "Your organization has encryption enabled on confidential sensitivity labels"
        $this.FailRecommendation = "Your organization should enable encryption on Confidential and Highly Confidential sensitivity labels"
        $this.Importance = "Encryption ensures that protection travels with documents across Microsoft 365, Azure, AWS, and third-party applications. According to the Secure by Default blueprint, encryption should be enabled on Confidential and Highly Confidential labels to prevent unauthorized access even if files are shared externally or exfiltrated. This is a key milestone in mature data protection implementation."
        $this.ExpandResults = $True
        $this.ItemName = "Sensitivity Label"
        $this.DataType = "Encryption Status"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://aka.ms/PurviewDeploymentModels/SecureByDefault"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-gcch-ip-compliance-center"
                "Apply encryption using sensitivity labels"   = "https://learn.microsoft.com/en-us/purview/encryption-sensitivity-labels"
                "Compliance Manager - IP Actions"             = "https://aka.ms/mcca-gcch-ip-compliance-manager"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://aka.ms/PurviewDeploymentModels/SecureByDefault"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-dod-ip-compliance-center"
                "Apply encryption using sensitivity labels"   = "https://learn.microsoft.com/en-us/purview/encryption-sensitivity-labels"
                "Compliance Manager - IP Actions"             = "https://aka.ms/mcca-dod-ip-compliance-manager"
            }
        }else
        {
            $this.Links = @{
                "Secure by Default Deployment Model"          = "https://aka.ms/PurviewDeploymentModels/SecureByDefault"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-ip-compliance-center"
                "Apply encryption using sensitivity labels"   = "https://learn.microsoft.com/en-us/purview/encryption-sensitivity-labels"
                "Compliance Manager - IP Actions"             = "https://aka.ms/mcca-ip-compliance-manager"
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
            $ConfidentialLabelsWithEncryption = @()
            $ConfidentialLabelsWithoutEncryption = @()
            $HighlyConfidentialLabelsWithEncryption = @()
            $HighlyConfidentialLabelsWithoutEncryption = @()
            $OtherLabelsChecked = @()

            ForEach ($Label in $Config["GetLabel"]) {
                $LabelName = $Label.DisplayName
                $LabelNameLower = $LabelName.ToLower()

                # Check if this is a Confidential or Highly Confidential label
                $IsConfidential = $LabelNameLower -match "confidential" -and $LabelNameLower -notmatch "highly"
                $IsHighlyConfidential = $LabelNameLower -match "highly.*confidential" -or $LabelNameLower -match "top.*secret" -or $LabelNameLower -match "restricted"

                # Check encryption settings
                $HasEncryption = $false

                # Check EncryptionEnabled property
                if ($null -ne $Label.EncryptionEnabled -and $Label.EncryptionEnabled -eq $true) {
                    $HasEncryption = $true
                }

                # Also check Settings for encryption configuration
                if ($null -ne $Label.Settings) {
                    foreach ($setting in $Label.Settings) {
                        if ($setting -match "EncryptionEnabled.*true" -or
                            $setting -match "encryptionenabled.*true" -or
                            $setting -match "EncryptionProtectionType") {
                            $HasEncryption = $true
                            break
                        }
                    }
                }

                # Check EncryptionProtectionType if available
                if ($null -ne $Label.EncryptionProtectionType -and $Label.EncryptionProtectionType -ne "None") {
                    $HasEncryption = $true
                }

                if ($IsHighlyConfidential) {
                    if ($HasEncryption) {
                        $HighlyConfidentialLabelsWithEncryption += $LabelName
                    } else {
                        $HighlyConfidentialLabelsWithoutEncryption += $LabelName
                    }
                }
                elseif ($IsConfidential) {
                    if ($HasEncryption) {
                        $ConfidentialLabelsWithEncryption += $LabelName
                    } else {
                        $ConfidentialLabelsWithoutEncryption += $LabelName
                    }
                }
            }

            # Report on Highly Confidential labels
            if ($HighlyConfidentialLabelsWithEncryption.Count -gt 0 -or $HighlyConfidentialLabelsWithoutEncryption.Count -gt 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = "Highly Confidential Labels"

                if ($HighlyConfidentialLabelsWithoutEncryption.Count -eq 0 -and $HighlyConfidentialLabelsWithEncryption.Count -gt 0) {
                    $ConfigObject.ConfigItem = "All Highly Confidential labels have encryption"
                    $ConfigObject.ConfigData = "Encrypted labels: $($HighlyConfidentialLabelsWithEncryption -join ', ')"
                    $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                }
                elseif ($HighlyConfidentialLabelsWithoutEncryption.Count -gt 0) {
                    $ConfigObject.ConfigItem = "Some Highly Confidential labels lack encryption"
                    $ConfigObject.ConfigData = "Labels without encryption: $($HighlyConfidentialLabelsWithoutEncryption -join ', ')"
                    $ConfigObject.InfoText = "Highly Confidential labels should always have encryption enabled to protect the most sensitive data."
                    $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                }
                $this.AddConfig($ConfigObject)
            }

            # Report on Confidential labels
            if ($ConfidentialLabelsWithEncryption.Count -gt 0 -or $ConfidentialLabelsWithoutEncryption.Count -gt 0) {
                $ConfigObject2 = [CAMPCheckConfig]::new()
                $ConfigObject2.Object = "Confidential Labels"

                if ($ConfidentialLabelsWithoutEncryption.Count -eq 0 -and $ConfidentialLabelsWithEncryption.Count -gt 0) {
                    $ConfigObject2.ConfigItem = "All Confidential labels have encryption"
                    $ConfigObject2.ConfigData = "Encrypted labels: $($ConfidentialLabelsWithEncryption -join ', ')"
                    $ConfigObject2.SetResult([CAMPConfigLevel]::Ok, "Pass")
                }
                elseif ($ConfidentialLabelsWithoutEncryption.Count -gt 0 -and $ConfidentialLabelsWithEncryption.Count -gt 0) {
                    $ConfigObject2.ConfigItem = "Some Confidential labels have encryption"
                    $ConfigObject2.ConfigData = "Labels without encryption: $($ConfidentialLabelsWithoutEncryption -join ', ')"
                    $ConfigObject2.InfoText = "Consider enabling encryption on all Confidential labels, especially those intended for internal-only content like 'Confidential\All Employees'."
                    $ConfigObject2.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
                }
                else {
                    $ConfigObject2.ConfigItem = "No Confidential labels have encryption"
                    $ConfigObject2.ConfigData = "Labels without encryption: $($ConfidentialLabelsWithoutEncryption -join ', ')"
                    $ConfigObject2.InfoText = "The Secure by Default blueprint recommends adding encryption to Confidential labels as a Milestone 3 enhancement to ensure protection travels with documents."
                    $ConfigObject2.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
                }
                $this.AddConfig($ConfigObject2)
            }

            # If no Confidential or Highly Confidential labels exist
            if ($ConfidentialLabelsWithEncryption.Count -eq 0 -and $ConfidentialLabelsWithoutEncryption.Count -eq 0 -and
                $HighlyConfidentialLabelsWithEncryption.Count -eq 0 -and $HighlyConfidentialLabelsWithoutEncryption.Count -eq 0) {
                $ConfigObject3 = [CAMPCheckConfig]::new()
                $ConfigObject3.Object = "Label Taxonomy Review"
                $ConfigObject3.ConfigItem = "No Confidential or Highly Confidential labels found"
                $ConfigObject3.ConfigData = "Your label taxonomy may not include standard confidential classifications"
                $ConfigObject3.InfoText = "Microsoft recommends a label taxonomy that includes 'Confidential' and 'Highly Confidential' parent labels with encryption. Refer to the Secure by Default blueprint for recommended label structures."
                $ConfigObject3.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
                $this.AddConfig($ConfigObject3)
            }

            $this.Completed = $True
        }
    }

}
