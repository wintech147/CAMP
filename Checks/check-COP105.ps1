using module "..\CAMP.psm1"

class COP105 : CAMPCheck {
    <#

        Enforce Label Inheritance for Copilot Interactions
        Based on Microsoft Purview Deployment Models: Secure & govern Microsoft 365 Copilot agents.

    #>

    COP105() {
        $this.Control = "COP-105"
        $this.ParentArea = "Microsoft Purview AI"
        $this.Area = "Copilot & Agents"
        $this.Name = "Enforce Label Inheritance for Copilot Interactions"
        $this.Blueprint = [CAMPBlueprint]::CopilotAgents
        $this.MaturityLevel = [CAMPMaturityLevel]::Better
        $this.BlueprintStages = @{
            "CopilotAgents" = 3
        }
        $this.Foundational = $false
        $this.RequiredCollections = @("GetLabelPolicy")
        $this.RequiredLicenses = @("Microsoft 365 E5 Compliance", "Microsoft 365 Copilot")
        $this.CommercialOnly = $true
        $this.PassText = "Your organization has a label policy with Copilot-relevant label inheritance enabled"
        $this.FailRecommendation = "Enable label inheritance for Copilot interactions in an enabled label policy"
        $this.Importance = "Step 3 of the Secure & govern Microsoft 365 Copilot agents deployment model relies on label inheritance so Microsoft 365 Copilot chats and generated content retain the sensitivity context of source material. Copilot-specific inheritance settings overlap with existing information protection controls, require Microsoft Purview Information Protection licensing and Copilot licensing, and are CommercialOnly at the time of writing for GCCH/DoD tenants."
        $this.ExpandResults = $True
        $this.ItemName = "Label Policy"
        $this.DataType = "Inheritance Setting"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 3" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step3"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.us/aiHub"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 3" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step3"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.us/aiHub"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }else
        {
            $this.Links = @{
                "Secure & govern Microsoft 365 Copilot agents" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment"
                "Deployment model Step 3" = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-step3"
                "Microsoft Purview AI Hub" = "https://purview.microsoft.com/aiHub"
                "AI data security" = "https://learn.microsoft.com/purview/ai-microsoft-purview"
            }
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config) {
        if (-not $this.HasCollection($Config, "GetLabelPolicy")) {
            $this.SetUnavailable("Required collection GetLabelPolicy is missing or returned an error.")
            return
        }

        $InheritanceSettingNames = @("EnableLabelInheritance", "EnableCopilotLabelInheritance", "EnableMipLabelsInChat")
        $MatchingPolicyCount = 0

        foreach ($Policy in @($Config["GetLabelPolicy"])) {
            $PolicyName = "Unnamed label policy"
            foreach ($PropertyName in @("Name", "Identity", "Guid")) {
                if ($PolicyName -eq "Unnamed label policy") {
                    if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains($PropertyName)) {
                        $PolicyName = [string]$Policy[$PropertyName]
                    }
                    elseif ($null -ne $Policy.PSObject.Properties[$PropertyName]) {
                        $PolicyName = [string]$Policy.PSObject.Properties[$PropertyName].Value
                    }
                }
            }

            $IsEnabled = $true
            $EnabledValue = $null
            if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains("Enabled")) {
                $EnabledValue = $Policy["Enabled"]
            }
            elseif ($null -ne $Policy.PSObject.Properties["Enabled"]) {
                $EnabledValue = $Policy.PSObject.Properties["Enabled"].Value
            }
            if ($null -ne $EnabledValue) {
                if ($EnabledValue -is [bool]) {
                    $IsEnabled = $EnabledValue
                }
                elseif ([string]$EnabledValue -imatch "^(false|disabled|off|0|no)$") {
                    $IsEnabled = $false
                }
            }
            if (-not $IsEnabled) {
                continue
            }

            $MatchedSettings = @()
            foreach ($SettingName in $InheritanceSettingNames) {
                $Value = $null
                if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains($SettingName)) {
                    $Value = $Policy[$SettingName]
                }
                elseif ($null -ne $Policy.PSObject.Properties[$SettingName]) {
                    $Value = $Policy.PSObject.Properties[$SettingName].Value
                }
                if ($null -ne $Value) {
                    if ($Value -is [bool]) {
                        if ($Value) { $MatchedSettings += $SettingName }
                    }
                    elseif ([string]$Value -imatch "^(true|enabled|on|1|yes)$") {
                        $MatchedSettings += $SettingName
                    }
                }
            }

            $SettingsValue = $null
            if ($Policy -is [System.Collections.IDictionary] -and $Policy.Contains("Settings")) {
                $SettingsValue = $Policy["Settings"]
            }
            elseif ($null -ne $Policy.PSObject.Properties["Settings"]) {
                $SettingsValue = $Policy.PSObject.Properties["Settings"].Value
            }

            foreach ($Setting in @($SettingsValue)) {
                if ($null -eq $Setting) { continue }
                if ($Setting -is [System.Collections.IDictionary]) {
                    foreach ($Key in $Setting.Keys) {
                        if ($InheritanceSettingNames -contains [string]$Key) {
                            $Value = $Setting[$Key]
                            if ($Value -is [bool]) {
                                if ($Value) { $MatchedSettings += [string]$Key }
                            }
                            elseif ([string]$Value -imatch "^(true|enabled|on|1|yes)$") {
                                $MatchedSettings += [string]$Key
                            }
                        }
                    }
                }
                else {
                    $SettingText = [string]$Setting
                    foreach ($SettingName in $InheritanceSettingNames) {
                        if ($SettingText -imatch "$SettingName\s*[:=]\s*(true|enabled|on|1|yes)") {
                            $MatchedSettings += $SettingName
                        }
                    }
                }
            }

            $MatchedSettings = @($MatchedSettings | Select-Object -Unique)
            if ($MatchedSettings.Count -gt 0) {
                $MatchingPolicyCount++
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = $PolicyName
                $ConfigObject.ConfigItem = "Copilot label inheritance"
                $ConfigObject.ConfigData = $MatchedSettings -join ", "
                $ConfigObject.InfoText = "This enabled label policy has Copilot-relevant inheritance settings turned on."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)
            }
        }

        if ($MatchingPolicyCount -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "Sensitivity label policies"
            $ConfigObject.ConfigItem = "Copilot label inheritance"
            $ConfigObject.ConfigData = "No enabled label policy with Copilot label inheritance found"
            $ConfigObject.InfoText = "Enable EnableLabelInheritance, EnableCopilotLabelInheritance, or EnableMipLabelsInChat in an enabled label policy so Copilot interactions inherit sensitivity context."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $True
    }
}
