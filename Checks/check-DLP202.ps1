using module "..\CAMP.psm1"

class DLP202 : CAMPCheck {
    <#

        Endpoint DLP for USB and Removable Storage
        Based on Microsoft Purview Deployment Models: Lightweight Guide to Mitigate Data Leakage Blueprint

    #>

    DLP202() {
        $this.Control = "DLP-202"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Data Loss Prevention"
        $this.Name = "Enable Endpoint DLP to Prevent Data Exfiltration"
        $this.PassText = "Your organization has Endpoint DLP policies configured to protect against data exfiltration"
        $this.FailRecommendation = "Your organization should enable Endpoint DLP policies to prevent sensitive data exfiltration via USB, printing, and other egress points"
        $this.Importance = "Endpoint DLP extends data loss prevention to Windows and macOS devices, enabling organizations to detect and block sensitive data from being copied to USB drives, printed, uploaded to cloud services, or accessed by unauthorized applications. This is a critical control for preventing data leakage and is recommended in the Lightweight Guide to Mitigate Data Leakage blueprint."
        $this.ExpandResults = $True
        $this.CheckType = [CheckType]::ObjectPropertyValue
        $this.ObjectType = "DLP Policy"
        $this.ItemName = "Endpoint Coverage"
        $this.DataType = "Configuration Status"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Data Leakage Prevention Blueprint"           = "https://aka.ms/purviewdeploymentmodels"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-gcch-dlp-compliance-center"
                "Learn about Endpoint DLP"                    = "https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about"
                "Get started with Endpoint DLP"               = "https://learn.microsoft.com/en-us/purview/endpoint-dlp-getting-started"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Data Leakage Prevention Blueprint"           = "https://aka.ms/purviewdeploymentmodels"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dod-dlp-compliance-center"
                "Learn about Endpoint DLP"                    = "https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about"
                "Get started with Endpoint DLP"               = "https://learn.microsoft.com/en-us/purview/endpoint-dlp-getting-started"
            }
        }else
        {
            $this.Links = @{
                "Data Leakage Prevention Blueprint"           = "https://aka.ms/purviewdeploymentmodels"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dlp-compliance-center"
                "Learn about Endpoint DLP"                    = "https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about"
                "Get started with Endpoint DLP"               = "https://learn.microsoft.com/en-us/purview/endpoint-dlp-getting-started"
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
            $EndpointDLPPolicies = @()
            $PoliciesWithDevices = @()
            $PoliciesInTestMode = @()

            ForEach ($CompliancePolicy in $Config["GetDlpCompliancePolicy"]) {
                $PolicyName = $CompliancePolicy.Name

                # Check if policy includes Endpoint/Devices location
                $EndpointLocation = $CompliancePolicy.EndpointDlpLocation
                $HasEndpointLocation = $false

                if ($null -ne $EndpointLocation) {
                    if ((@($EndpointLocation) -like 'All').Count -gt 0 -or @($EndpointLocation).Count -gt 0) {
                        $HasEndpointLocation = $true
                    }
                }

                if ($HasEndpointLocation) {
                    $ConfigObject = [CAMPCheckConfig]::new()
                    $ConfigObject.Object = $PolicyName

                    $EndpointDLPPolicies += $PolicyName

                    # Check policy mode
                    $PolicyMode = $CompliancePolicy.Mode
                    $IsEnabled = $PolicyMode -ieq "Enable"
                    $IsTestMode = $PolicyMode -ieq "TestWithNotifications" -or $PolicyMode -ieq "TestWithoutNotifications"

                    # Check endpoint location scope
                    $EndpointScope = "Unknown"
                    if ((@($EndpointLocation) -like 'All').Count -gt 0) {
                        $EndpointScope = "All devices"
                    } else {
                        $EndpointScope = "Specific users/groups: $($EndpointLocation -join ', ')"
                    }

                    # Check for endpoint-specific actions in rules
                    $EndpointActions = @()
                    ForEach ($Rule in $Config["GetDlpComplianceRule"]) {
                        if ($Rule.ParentPolicyName -eq $PolicyName) {
                            # Check for endpoint-specific actions
                            if ($null -ne $Rule.EndpointDlpBrowserRestrictions) {
                                $EndpointActions += "Browser restrictions"
                            }
                            if ($null -ne $Rule.EndpointDlpRestrictionAction) {
                                $EndpointActions += "Restriction actions configured"
                            }
                            # Check for removable storage/USB blocking
                            if ($null -ne $Rule.BlockAccessScope -or $null -ne $Rule.NotifyUser) {
                                $EndpointActions += "Access blocking/notifications"
                            }
                        }
                    }

                    $ConfigObject.ConfigItem = "Endpoint scope: $EndpointScope"

                    if ($IsEnabled) {
                        $PoliciesWithDevices += $PolicyName
                        $ConfigObject.ConfigData = "Policy is enabled for endpoint protection"
                        if ($EndpointActions.Count -gt 0) {
                            $ConfigObject.ConfigData += " | Actions: $($EndpointActions -join ', ')"
                        }
                        $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                    }
                    elseif ($IsTestMode) {
                        $PoliciesInTestMode += $PolicyName
                        $ConfigObject.ConfigData = "Policy is in test mode ($PolicyMode)"
                        $ConfigObject.InfoText = "Consider enabling this policy after validating test results to enforce endpoint protection."
                        $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Pass")
                    }
                    else {
                        $ConfigObject.ConfigData = "Policy is disabled ($PolicyMode)"
                        $ConfigObject.InfoText = "Enable this policy to enforce endpoint DLP protection."
                        $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                    }

                    $this.AddConfig($ConfigObject)
                }
            }

            # If no Endpoint DLP policies exist
            if ($EndpointDLPPolicies.Count -eq 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = "No Endpoint DLP Policies"
                $ConfigObject.ConfigItem = "No DLP policies configured for endpoints"
                $ConfigObject.ConfigData = "Your organization has not configured any DLP policies that include endpoint devices"
                $ConfigObject.InfoText = "Create DLP policies that include the 'Devices' location to protect against data exfiltration via USB drives, printing, clipboard, and other egress points. This is recommended in the Lightweight Guide to Mitigate Data Leakage blueprint."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                $this.AddConfig($ConfigObject)

                # Add a recommendation for getting started
                $ConfigObject2 = [CAMPCheckConfig]::new()
                $ConfigObject2.Object = "<B>Endpoint DLP Recommendation</B>"
                $ConfigObject2.ConfigItem = "Enable Endpoint DLP for comprehensive data protection"
                $ConfigObject2.ConfigData = "Endpoint DLP can prevent: USB/removable storage exfiltration, unauthorized printing, uploads to non-approved cloud services, and clipboard sharing to unauthorized apps"
                $ConfigObject2.InfoText = "To get started: 1) Ensure devices are onboarded to Microsoft Purview, 2) Create a DLP policy with 'Devices' location, 3) Configure rules for sensitive content detection and blocking actions."
                $ConfigObject2.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
                $this.AddConfig($ConfigObject2)
            }

            # Summary if only test mode policies
            if ($EndpointDLPPolicies.Count -gt 0 -and $PoliciesWithDevices.Count -eq 0 -and $PoliciesInTestMode.Count -gt 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = "<B>Enable Endpoint DLP Policies</B>"
                $ConfigObject.ConfigItem = "All endpoint policies are in test mode"
                $ConfigObject.ConfigData = "Policies in test mode: $($PoliciesInTestMode -join ', ')"
                $ConfigObject.InfoText = "Review test results and enable these policies to enforce endpoint protection against data exfiltration."
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
