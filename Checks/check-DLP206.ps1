using module "..\CAMP.psm1"

class DLP206 : CAMPCheck {
    <#

        Custom Sensitive Information Types for Organization-Specific Data
        Based on Microsoft Purview Deployment Models: Lightweight DLP and Reduce False Positives Blueprints

    #>

    DLP206() {
        $this.Control = "DLP-206"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Data Loss Prevention"
        $this.Name = "Define Custom Sensitive Information Types for Organization-Specific Data"
        $this.PassText = "Your organization has custom sensitive information types referenced by DLP rules"
        $this.FailRecommendation = "Your organization should define custom sensitive information types and reference them in DLP rules"
        $this.Importance = "The Lightweight DLP Step 2 and Reduce False Positives Step 1 blueprints recommend custom sensitive information types for organization-specific identifiers and regulated data patterns. Custom SITs help reduce false positives and align detections to your data estate; core SIT use is available with Microsoft 365 Business Premium and E3+IPG licensing, while advanced DLP scenarios may require Microsoft 365 E5 Compliance."
        $this.ExpandResults = $True
        $this.CheckType = [CheckType]::ObjectPropertyValue
        $this.ObjectType = "Sensitive Information Type"
        $this.ItemName = "DLP Rule Reference"
        $this.DataType = "Usage Status"
        $this.Blueprint = [CAMPBlueprint]::LightweightDLP -bor [CAMPBlueprint]::ReduceFalsePositives
        $this.MaturityLevel = [CAMPMaturityLevel]::Better
        $this.BlueprintStages = @{ "LightweightDLP" = 2; "ReduceFalsePositives" = 1 }
        $this.RequiredCollections = @("GetDLPCustomSIT", "GetDlpComplianceRule")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses = @()
        $this.CommercialOnly = $false
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Lightweight DLP Step 2"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2"
                "Reduce false positives Step 1"            = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives-step1"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-gcch-dlp-compliance-center"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Lightweight DLP overview"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Lightweight DLP Step 2"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2"
                "Reduce false positives Step 1"            = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives-step1"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dod-dlp-compliance-center"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Lightweight DLP overview"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
            }
        }else
        {
            $this.Links = @{
                "Lightweight DLP Step 2"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2"
                "Reduce false positives Step 1"            = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives-step1"
                "Microsoft Purview portal - Data Loss Prevention" = "https://purview.microsoft.com"
                "DLP policy reference"                     = "https://learn.microsoft.com/purview/dlp-policy-reference"
                "Lightweight DLP overview"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs custom sensitive information types and DLP rules from Security & Compliance PowerShell.")
                return
            }
        }

        $HasNonEmptyValue = {
            param($Value)

            if ($null -eq $Value) {
                return $false
            }

            if ($Value -is [string]) {
                return ($Value.Trim() -ne "" -and $Value -ine "None")
            }

            if ($Value -is [System.Collections.IDictionary]) {
                return ($Value.Count -gt 0)
            }

            if ($Value -is [System.Collections.IEnumerable]) {
                $Items = @($Value) | Where-Object { $null -ne $_ -and "$_".Trim() -ne "" -and "$_" -ine "None" }
                return ($Items.Count -gt 0)
            }

            return $true
        }

        $GetStringValues = {
            param($Value)

            $Strings = @()
            if ($null -eq $Value) {
                return $Strings
            }

            if ($Value -is [string]) {
                if ($Value.Trim() -ne "") {
                    $Strings += $Value.Trim()
                }
                return $Strings
            }

            if ($Value -is [System.Collections.IDictionary]) {
                foreach ($Key in $Value.Keys) {
                    $Strings += & $GetStringValues $Value[$Key]
                }
                return $Strings
            }

            if ($Value -is [System.Collections.IEnumerable]) {
                foreach ($Item in $Value) {
                    $Strings += & $GetStringValues $Item
                }
                return $Strings
            }

            foreach ($Property in $Value.PSObject.Properties) {
                if ($null -ne $Property.Value -and $Property.Name -notin @("PSComputerName", "RunspaceId")) {
                    $Strings += & $GetStringValues $Property.Value
                }
            }

            if ($Strings.Count -eq 0) {
                $StringValue = "$Value"
                if ($StringValue.Trim() -ne "") {
                    $Strings += $StringValue.Trim()
                }
            }

            return $Strings
        }

        $CustomSITRecords = @()
        ForEach ($CustomSIT in $Config["GetDLPCustomSIT"]) {
            $Identifiers = @()
            foreach ($PropertyName in @("Name", "Identity", "Id", "Guid", "ImmutableId")) {
                $Property = $CustomSIT.PSObject.Properties[$PropertyName]
                if ($null -ne $Property -and (& $HasNonEmptyValue $Property.Value)) {
                    foreach ($Identifier in @($Property.Value)) {
                        if ($null -ne $Identifier -and "$Identifier".Trim() -ne "") {
                            $Identifiers += "$Identifier".Trim()
                        }
                    }
                }
            }

            $Identifiers = @($Identifiers | Select-Object -Unique)
            if ($Identifiers.Count -gt 0) {
                $DisplayName = $Identifiers[0]
                if ($null -ne $CustomSIT.PSObject.Properties["Name"] -and "$($CustomSIT.Name)".Trim() -ne "") {
                    $DisplayName = "$($CustomSIT.Name)".Trim()
                }

                $CustomSITRecords += [pscustomobject]@{
                    Name = $DisplayName
                    Identifiers = $Identifiers
                }
            }
        }

        if ($CustomSITRecords.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Custom Sensitive Information Types"
            $ConfigObject.ConfigItem = "No non-Microsoft publisher SITs found"
            $ConfigObject.ConfigData = "Your organization has not defined custom sensitive information types"
            $ConfigObject.InfoText = "Create custom sensitive information types for organization-specific identifiers and use them in DLP rules to improve precision."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
            $this.Completed = $true
            return
        }

        $UsedCustomSITs = @{}
        foreach ($Record in $CustomSITRecords) {
            $UsedCustomSITs[$Record.Name] = @()
        }

        ForEach ($Rule in $Config["GetDlpComplianceRule"]) {
            if (& $HasNonEmptyValue $Rule.ContentContainsSensitiveInformation) {
                $RuleStrings = & $GetStringValues $Rule.ContentContainsSensitiveInformation
                $RuleText = $RuleStrings -join " "
                if ($RuleText.Trim() -eq "") {
                    $RuleText = "$($Rule.ContentContainsSensitiveInformation | Out-String)"
                }

                foreach ($Record in $CustomSITRecords) {
                    $Referenced = $false
                    foreach ($Identifier in $Record.Identifiers) {
                        if (($RuleStrings -contains $Identifier) -or ($RuleText -match [regex]::Escape($Identifier))) {
                            $Referenced = $true
                        }
                    }

                    if ($Referenced) {
                        $RuleName = $Rule.Name
                        if ($null -eq $RuleName -or "$RuleName".Trim() -eq "") {
                            $RuleName = "$($Rule.ParentPolicyName)"
                        }

                        if ($UsedCustomSITs[$Record.Name] -notcontains $RuleName) {
                            $UsedCustomSITs[$Record.Name] += $RuleName
                        }
                    }
                }
            }
        }

        $UsedNames = @()
        $UnusedNames = @()
        foreach ($Record in $CustomSITRecords) {
            if ($UsedCustomSITs[$Record.Name].Count -gt 0) {
                $UsedNames += $Record.Name
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = $Record.Name
                $ConfigObject.ConfigItem = "Referenced by DLP rule"
                $ConfigObject.ConfigData = "Rules: $($UsedCustomSITs[$Record.Name] -join ', ')"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)
            }
            else {
                $UnusedNames += $Record.Name
            }
        }

        if ($UsedNames.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "Custom SITs Not Used by DLP"
            $ConfigObject.ConfigItem = "Unused custom SITs: $($UnusedNames -join ', ')"
            $ConfigObject.ConfigData = "Custom sensitive information types exist but no DLP rule references them"
            $ConfigObject.InfoText = "Reference custom sensitive information types in DLP rules so organization-specific data patterns are protected and false positives are reduced."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            $this.AddConfig($ConfigObject)
        }
        elseif ($UnusedNames.Count -gt 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "<B>Custom SIT Usage Note</B>"
            $ConfigObject.ConfigItem = "Unused custom SITs"
            $ConfigObject.ConfigData = $UnusedNames -join ", "
            $ConfigObject.InfoText = "Review unused custom sensitive information types and either reference them in DLP rules or retire them to reduce configuration drift."
            $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}
