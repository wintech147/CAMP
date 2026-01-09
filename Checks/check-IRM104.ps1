using module "..\CAMP.psm1"

class IRM104 : CAMPCheck {
    <#
        CAMP Check: IRM-104
        Checks for Data Leaks IRM policy which is required for Adaptive Protection
        Blueprint: Copilot - Protect Against Data Loss and Insider Risk
        Blueprint: Identify and Remediate Credentials with Purview
    #>

    IRM104() {
        $this.Control = "IRM-104"
        $this.ParentArea = "Insider Risk"
        $this.Area = "Insider Risk Management"
        $this.Name = "Configure Data Leaks Policy for Adaptive Protection"
        $this.PassText = "Your organization has an active Data Leaks insider risk policy configured"
        $this.FailRecommendation = "Your organization should configure a Data Leaks insider risk policy to enable Adaptive Protection"
        $this.Importance = "A Data Leaks insider risk management policy is required for Adaptive Protection. Adaptive Protection dynamically adjusts DLP policy enforcement based on user risk levels, providing stronger protection for risky users while maintaining productivity for others. This is essential for protecting against data exfiltration to Copilot and AI applications, as well as credential exposure scenarios."
        $this.ExpandResults = $True
        $this.ItemName = "Policy"
        $this.DataType = "Status"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Adaptive Protection in Insider Risk Management" = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection"
                "Microsoft Purview portal - Insider Risk Management" = "https://aka.ms/mcca-gcch-irm-compliance-center"
                "Copilot Data Protection Blueprint" = "https://github.com/microsoft/purview/tree/main/purview-blueprints"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Adaptive Protection in Insider Risk Management" = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection"
                "Microsoft Purview portal - Insider Risk Management" = "https://aka.ms/mcca-dod-irm-compliance-center"
                "Copilot Data Protection Blueprint" = "https://github.com/microsoft/purview/tree/main/purview-blueprints"
            }
        }else
        {
            $this.Links = @{
                "Adaptive Protection in Insider Risk Management" = "https://learn.microsoft.com/purview/insider-risk-management-adaptive-protection"
                "Microsoft Purview portal - Insider Risk Management" = "https://aka.ms/mcca-irm-compliance-center"
                "Copilot Data Protection Blueprint" = "https://github.com/microsoft/purview/tree/main/purview-blueprints"
            }
        }
    }

    <#
        RESULTS
    #>

    GetResults($Config) {
        if ($Config["GetInsiderRiskPolicy"] -eq "Error") {
            $this.Completed = $false
        }
        else {
            $UtilityFiles = Get-ChildItem "$PSScriptRoot\..\Utilities"

            ForEach ($UtilityFile in $UtilityFiles) {
                . $UtilityFile.FullName
            }

            # DataLeaks is the template used by Adaptive Protection Quick Setup
            # Also check for DataLeaksForAdaptiveProtection which may be used in some configurations
            $Templates = @("DataLeaks", "DataLeaksForAdaptiveProtection")
            $LogFile = $this.LogFile

            $AnyPolicyEnabled = $false
            $IRMPolicy = @()

            foreach($Template in $Templates) {
                $IRMPolicy += $Config["GetInsiderRiskPolicy"] | Where-Object { $_.InsiderRiskScenario -eq $Template }
            }

            foreach ($Policy in $IRMPolicy) {
                if ($($Policy.Mode) -eq "Enable") {
                    $AnyPolicyEnabled = $true

                    $ConfigObject = [CAMPCheckConfig]::new()
                    $ConfigObject.Object = "Policy"
                    $ConfigObject.ConfigItem = "$($Policy.Name)"
                    $ConfigObject.ConfigData = "Enabled - Scenario: $($Policy.InsiderRiskScenario)"
                    $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                    $this.AddConfig($ConfigObject)
                }
            }

            if ($AnyPolicyEnabled -eq $false) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = "Policy"
                $ConfigObject.ConfigItem = "No Data Leaks policy configured"
                $ConfigObject.ConfigData = "Required for Adaptive Protection"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                $this.AddConfig($ConfigObject)
            }

            $this.Completed = $True
        }
    }
}
