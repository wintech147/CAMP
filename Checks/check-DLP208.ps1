using module "..\CAMP.psm1"

class DLP208 : CAMPCheck {
    <#

        Adaptive Protection Signal in Conditional Access Policies
        Based on Microsoft Purview Deployment Models: Lightweight DLP Blueprint

    #>

    DLP208() {
        $this.Control = "DLP-208"
        $this.ParentArea = "Microsoft Information Protection"
        $this.Area = "Data Loss Prevention"
        $this.Name = "Add Adaptive Protection Signal to Conditional Access Policies"
        $this.PassText = "Your organization has Conditional Access policies that include an insider-risk signal"
        $this.FailRecommendation = "Your organization should add Adaptive Protection or insider-risk signals to Conditional Access policies"
        $this.Importance = "The Lightweight DLP Step 3 blueprint recommends extending Adaptive Protection signals into Conditional Access so elevated insider risk can trigger stronger access controls. Conditional Access requires appropriate Microsoft Entra ID licensing, and Adaptive Protection signals are typically enabled through Microsoft 365 E5 Compliance."
        $this.ExpandResults = $True
        $this.CheckType = [CheckType]::ObjectPropertyValue
        $this.ObjectType = "Conditional Access Policy"
        $this.ItemName = "Insider Risk Signal"
        $this.DataType = "Policy Conditions"
        $this.Blueprint = [CAMPBlueprint]::LightweightDLP
        $this.MaturityLevel = [CAMPMaturityLevel]::Best
        $this.BlueprintStages = @{ "LightweightDLP" = 3 }
        $this.RequiredCollections = @("GetEntraConditionalAccessPolicies")
        $this.RequiredGraphScopes = @("Policy.Read.All")
        $this.RequiredLicenses = @()
        $this.CommercialOnly = $false
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Lightweight DLP Step 3"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step3"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-gcch-dlp-compliance-center"
                "Adaptive Protection"                      = "https://learn.microsoft.com/purview/dlp-adaptive-protection-learn"
                "Conditional Access overview"              = "https://learn.microsoft.com/entra/identity/conditional-access/overview"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Lightweight DLP Step 3"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step3"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dod-dlp-compliance-center"
                "Adaptive Protection"                      = "https://learn.microsoft.com/purview/dlp-adaptive-protection-learn"
                "Conditional Access overview"              = "https://learn.microsoft.com/entra/identity/conditional-access/overview"
            }
        }else
        {
            $this.Links = @{
                "Lightweight DLP Step 3"                    = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step3"
                "Microsoft Purview portal - Data Loss Prevention" = "https://purview.microsoft.com"
                "Adaptive Protection"                      = "https://learn.microsoft.com/purview/dlp-adaptive-protection-learn"
                "Conditional Access overview"              = "https://learn.microsoft.com/entra/identity/conditional-access/overview"
            }
        }
    }

    GetResults($Config) {
        if (-not $this.HasCollection($Config, "GetEntraConditionalAccessPolicies")) {
            $this.EmitAwarenessRecommendation(
                "<B>Conditional Access for Adaptive Protection (manual review)</B>",
                "Microsoft Graph data not collected",
                "GetEntraConditionalAccessPolicies was not available — install Microsoft.Graph and grant Policy.Read.All to enumerate Conditional Access policies.",
                "Review Conditional Access policies manually in Microsoft Entra > Protection > Conditional Access (https://entra.microsoft.com). Confirm at least one policy uses the Insider Risk signal to block or restrict elevated-risk users."
            )
            return
        }

        $GetPropertyValue = {
            param($Object, [string]$Name)

            if ($null -eq $Object) {
                return $null
            }

            if ($Object -is [System.Collections.IDictionary]) {
                if ($Object.Contains($Name)) {
                    return $Object[$Name]
                }

                foreach ($Key in $Object.Keys) {
                    if ("$Key" -ieq $Name) {
                        return $Object[$Key]
                    }
                }
            }

            $Property = $Object.PSObject.Properties[$Name]
            if ($null -ne $Property) {
                return $Property.Value
            }

            $AdditionalProperties = $Object.PSObject.Properties["AdditionalProperties"]
            if ($null -ne $AdditionalProperties -and $null -ne $AdditionalProperties.Value) {
                $AdditionalValues = $AdditionalProperties.Value
                if ($AdditionalValues -is [System.Collections.IDictionary]) {
                    if ($AdditionalValues.Contains($Name)) {
                        return $AdditionalValues[$Name]
                    }

                    foreach ($Key in $AdditionalValues.Keys) {
                        if ("$Key" -ieq $Name) {
                            return $AdditionalValues[$Key]
                        }
                    }
                }
            }

            return $null
        }

        $GetNonEmptyValues = {
            param($Value)

            $Values = @()
            if ($null -eq $Value) {
                return $Values
            }

            if ($Value -is [string]) {
                if ($Value.Trim() -ne "" -and $Value -ine "None") {
                    $Values += $Value.Trim()
                }
                return $Values
            }

            if ($Value -is [System.Collections.IDictionary]) {
                foreach ($Key in $Value.Keys) {
                    $Values += & $GetNonEmptyValues $Value[$Key]
                }
                return $Values
            }

            if ($Value -is [System.Collections.IEnumerable]) {
                foreach ($Item in $Value) {
                    $Values += & $GetNonEmptyValues $Item
                }
                return $Values
            }

            $StringValue = "$Value"
            if ($StringValue.Trim() -ne "") {
                $Values += $StringValue.Trim()
            }

            return $Values
        }

        $PoliciesWithSignal = @()

        ForEach ($Policy in $Config["GetEntraConditionalAccessPolicies"]) {
            $PolicyName = & $GetPropertyValue $Policy "DisplayName"
            if ($null -eq $PolicyName -or "$PolicyName".Trim() -eq "") {
                $PolicyName = & $GetPropertyValue $Policy "Name"
            }
            if ($null -eq $PolicyName -or "$PolicyName".Trim() -eq "") {
                $PolicyName = & $GetPropertyValue $Policy "Id"
            }

            $PolicyState = & $GetPropertyValue $Policy "State"
            $Conditions = & $GetPropertyValue $Policy "Conditions"
            $Users = & $GetPropertyValue $Conditions "Users"
            $IncludeUsers = & $GetNonEmptyValues (& $GetPropertyValue $Users "IncludeUsers")
            $SignInRiskLevels = & $GetNonEmptyValues (& $GetPropertyValue $Conditions "SignInRiskLevels")
            $InsiderRiskLevels = & $GetNonEmptyValues (& $GetPropertyValue $Conditions "InsiderRiskLevels")

            $FallbackSignals = @()
            foreach ($Value in ($IncludeUsers + $SignInRiskLevels)) {
                if ("$Value" -match "(?i)insider|adaptive") {
                    $FallbackSignals += $Value
                }
            }

            $InsiderRiskSignals = @($InsiderRiskLevels + $FallbackSignals) | Where-Object { $null -ne $_ -and "$_".Trim() -ne "" }

            if ($InsiderRiskSignals.Count -gt 0) {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object = $PolicyName
                $ConfigObject.ConfigItem = "Insider risk signal: $($InsiderRiskSignals -join ', ')"
                $ConfigObject.ConfigData = "State: $PolicyState | IncludeUsers: $($IncludeUsers -join ', ') | SignInRiskLevels: $($SignInRiskLevels -join ', ')"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)

                $PoliciesWithSignal += $PolicyName
            }
        }

        if ($PoliciesWithSignal.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Conditional Access Insider-Risk Signal"
            $ConfigObject.ConfigItem = "Conditions.InsiderRiskLevels not found"
            $ConfigObject.ConfigData = "No Conditional Access policy includes an insider-risk or Adaptive Protection signal"
            $ConfigObject.InfoText = "Install Microsoft.Graph if this collection is unavailable, connect with Policy.Read.All, and configure Conditional Access to use the Insider risk / Adaptive Protection condition where supported."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}

