using module "..\CAMP.psm1"

class DLP203 : CAMPCheck {
    <#
        CAMP Check: DLP-203
        Checks for DLP policies protecting credentials and secrets
        Blueprint: Identify and Remediate Credentials with Purview
    #>

    DLP203() {
        $this.Control = "DLP-203"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Data Loss Prevention"
        $this.Name = "Configure DLP Policies for Credential Protection"
        $this.PassText = "Your organization has DLP policies protecting credentials and secrets"
        $this.FailRecommendation = "Your organization should configure DLP policies to detect and protect credentials, API keys, and connection strings"
        $this.Importance = "Exposed credentials such as API keys, connection strings, passwords, and access tokens pose significant security risks. Microsoft recommends configuring DLP policies using credential-related sensitive information types to detect and prevent credential exposure in emails, documents, and collaboration tools. This aligns with the Microsoft Purview blueprint for identifying and remediating credentials."
        $this.ExpandResults = $True
        $this.ItemName = "Policy"
        $this.DataType = "Credential SITs Protected"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Credential SITs Documentation" = "https://learn.microsoft.com/purview/sit-defn-all-creds"
                "Microsoft Purview portal - DLP" = "https://aka.ms/mcca-gcch-dlp-compliance-center"
                "Credentials Blueprint" = "https://github.com/microsoft/purview/tree/main/purview-blueprints"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Credential SITs Documentation" = "https://learn.microsoft.com/purview/sit-defn-all-creds"
                "Microsoft Purview portal - DLP" = "https://aka.ms/mcca-dod-dlp-compliance-center"
                "Credentials Blueprint" = "https://github.com/microsoft/purview/tree/main/purview-blueprints"
            }
        }else
        {
            $this.Links = @{
                "Credential SITs Documentation" = "https://learn.microsoft.com/purview/sit-defn-all-creds"
                "Microsoft Purview portal - DLP" = "https://aka.ms/mcca-dlp-compliance-center"
                "Credentials Blueprint" = "https://github.com/microsoft/purview/tree/main/purview-blueprints"
            }
        }
    }

    <#
        RESULTS
    #>

    GetResults($Config) {
        if ($Config["GetDlpCompliancePolicy"] -eq "Error" -or $Config["GetDlpComplianceRule"] -eq "Error") {
            $this.Completed = $false
        }
        else {
            # Credential-related SIT patterns to look for in DLP rules
            # These are common credential SITs from the "All credentials" bundle
            $CredentialSITPatterns = @(
                "Azure Storage Account",
                "Azure SQL Connection",
                "Azure Cosmos",
                "Azure Redis",
                "Azure Service Bus",
                "Azure IoT",
                "Azure Function",
                "Azure DevOps",
                "Azure Databricks",
                "Azure Container Registry",
                "Azure Cognitive",
                "Azure Bot",
                "Azure Batch",
                "Azure App Service",
                "Azure SignalR",
                "Azure Maps",
                "Azure Machine Learning",
                "Azure Logic App",
                "Azure EventGrid",
                "Microsoft Entra",
                "Amazon S3",
                "GitHub Personal Access Token",
                "Google API",
                "Slack Access Token",
                "Client Secret",
                "API Key",
                "General Password",
                "General Symmetric Key",
                "X.509 Certificate",
                "Connection String",
                "Access Key",
                "Access Token",
                "Shared Access Signature",
                "SAS",
                "Credential"
            )

            $AnyCredentialPolicyFound = $false
            $ProtectedSITs = @()

            # Get all enabled DLP policies
            $EnabledPolicies = $Config["GetDlpCompliancePolicy"] | Where-Object { $_.Mode -eq "Enable" }

            foreach ($Policy in $EnabledPolicies) {
                # Get rules for this policy
                $Rules = $Config["GetDlpComplianceRule"] | Where-Object { $_.ParentPolicyName -eq $Policy.Name }

                foreach ($Rule in $Rules) {
                    if ($Rule.Disabled -eq $false) {
                        # Check ContentContainsSensitiveInformation for credential SITs
                        $RuleContent = $Rule | Out-String

                        foreach ($Pattern in $CredentialSITPatterns) {
                            if ($RuleContent -match $Pattern) {
                                $AnyCredentialPolicyFound = $true

                                # Add to protected SITs list if not already there
                                if ($ProtectedSITs -notcontains $Pattern) {
                                    $ProtectedSITs += $Pattern
                                }
                            }
                        }

                        # Also check for the bundled "All credentials" SIT
                        if ($RuleContent -match "All credentials" -or $RuleContent -match "All Credentials") {
                            $AnyCredentialPolicyFound = $true
                            if ($ProtectedSITs -notcontains "All Credentials (Bundled)") {
                                $ProtectedSITs += "All Credentials (Bundled)"
                            }
                        }
                    }
                }
            }

            if ($AnyCredentialPolicyFound) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = "DLP Policy"
                $ConfigObject.ConfigItem = "Credential protection configured"
                $ConfigObject.ConfigData = "Protected: $($ProtectedSITs -join ', ')"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)
            }
            else {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = "DLP Policy"
                $ConfigObject.ConfigItem = "No credential protection policies found"
                $ConfigObject.ConfigData = "Configure DLP with credential SITs (Azure keys, API keys, passwords, tokens)"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                $this.AddConfig($ConfigObject)

                # Add recommended SITs
                $RecommendedConfig = [CAMPCheckConfig]::new()
                $RecommendedConfig.Object = "Recommendation"
                $RecommendedConfig.ConfigItem = "Use 'All credentials' bundled SIT"
                $RecommendedConfig.ConfigData = "Includes 40+ credential types: Azure keys, tokens, passwords, connection strings"
                $RecommendedConfig.SetResult([CAMPConfigLevel]::Informational, "Info")
                $this.AddConfig($RecommendedConfig)
            }

            $this.Completed = $True
        }
    }
}
