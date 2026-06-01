using module "..\CAMP.psm1"

class FP102 : CAMPCheck {
    <#
        Implement Exact Data Match for precise identification of known sensitive data
        Based on Microsoft Purview Deployment Models: Reduce False Positives Blueprint
    #>

    FP102() {
        $this.Control            = "FP-102"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Classifier Tuning"
        $this.Name               = "Implement Exact Data Match (EDM) for Precise Identification of Known Sensitive Data"
        $this.PassText           = "Your organization has at least one Exact Data Match schema configured"
        $this.FailRecommendation = "Your organization should implement Exact Data Match schemas and EDM-based sensitive information types for known sensitive data sets"
        $this.Importance         = "Reduce False Positives Step 2 recommends using Exact Data Match when known sensitive data sets need precise identification. EDM reduces false positives by matching protected data against hashed known values instead of relying only on generic patterns. EDM requires Microsoft 365 E5 Compliance and is commercial-only at the time of writing."
        $this.ExpandResults      = $True
        $this.ItemName           = "EDM Schema"
        $this.DataType           = "Configuration Status"

        $this.Blueprint        = [CAMPBlueprint]::ReduceFalsePositives
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "ReduceFalsePositives" = 2 }

        $this.RequiredLicenses = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly   = $true

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-gcch-ip-compliance-center"
                "Exact Data Match sensitive information types"      = "https://learn.microsoft.com/purview/sit-learn-about-exact-data-match-based-sits"
                "Reduce False Positives Deployment Model"           = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-dod-ip-compliance-center"
                "Exact Data Match sensitive information types"      = "https://learn.microsoft.com/purview/sit-learn-about-exact-data-match-based-sits"
                "Reduce False Positives Deployment Model"           = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
            }
        }
        else {
            $this.Links = @{
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-ip-compliance-center"
                "Exact Data Match sensitive information types"      = "https://learn.microsoft.com/purview/sit-learn-about-exact-data-match-based-sits"
                "Reduce False Positives Deployment Model"           = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
            }
        }
    }

    GetResults($Config) {
        $GetPropertyValue = {
            param($Object)
            foreach ($Name in $args) {
                if ($null -eq $Object) { continue }
                if ($Object -is [hashtable] -and $Object.ContainsKey($Name)) { return $Object[$Name] }
                $Property = $Object.PSObject.Properties[$Name]
                if ($null -ne $Property) { return $Property.Value }
            }
            return $null
        }

        $GetObjectName = {
            param($Object)
            if ($Object -is [string]) { return [string]$Object }
            $Name = & $GetPropertyValue $Object "Name" "DisplayName" "Identity" "Id"
            if ([string]::IsNullOrWhiteSpace([string]$Name)) { return "Unnamed EDM object" }
            return [string]$Name
        }

        try {
            $EdmSchemas = @(Get-DlpEdmSchema -ErrorAction:Stop)
        }
        catch {
            $this.EmitAwarenessRecommendation(
                "<B>Exact Data Match (manual review)</B>",
                "Get-DlpEdmSchema not available",
                "EDM cmdlets were not found in this Security & Compliance PowerShell session. Error: $($_.Exception.Message)",
                "Review EDM configuration manually in Microsoft Purview > Data Loss Prevention > Classifiers > Exact Data Match. Requires Microsoft 365 E5 Compliance."
            )
            return
        }

        $EdmSensitiveInformationTypes = @()
        $EdmSitStatus = "EDM-based SIT enumeration was not available"
        try {
            $SensitiveInformationTypes = @(Get-DlpSensitiveInformationType -ErrorAction:Stop)
            $EdmSensitiveInformationTypes = @(
                $SensitiveInformationTypes |
                    Where-Object {
                        $Type = & $GetPropertyValue $_ "Type"
                        $Publisher = & $GetPropertyValue $_ "Publisher"
                        ([string]$Type -eq "EDM") -or ([string]$Publisher -match "Exact Data Match")
                    }
            )
            $EdmSitStatus = "EDM-based SITs detected: $($EdmSensitiveInformationTypes.Count)"
        }
        catch {
            $EdmSitStatus = "Get-DlpSensitiveInformationType could not be queried for EDM-based SITs: $($_.Exception.Message)"
        }

        if ($EdmSchemas.Count -gt 0) {
            $EdmSitNames = @($EdmSensitiveInformationTypes | Select-Object -First 10 | ForEach-Object { & $GetObjectName $_ })
            $EdmSitSummary = if ($EdmSitNames.Count -gt 0) { $EdmSitNames -join ", " } else { "None detected" }

            foreach ($Schema in $EdmSchemas) {
                $SchemaName = & $GetObjectName $Schema
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.Object     = $SchemaName
                $ConfigObject.ConfigItem = "EDM schema configured"
                $ConfigObject.ConfigData = "$EdmSitStatus; EDM SIT examples: $EdmSitSummary"
                $ConfigObject.InfoText   = "This tenant has at least one EDM schema for precise matching of known sensitive data."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                $this.AddConfig($ConfigObject)
            }
        }
        else {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "Exact Data Match"
            $ConfigObject.ConfigItem = "No EDM schemas detected"
            $ConfigObject.ConfigData = $EdmSitStatus
            $ConfigObject.InfoText   = "Create EDM schemas and EDM-based SITs for known data sets that need lower false-positive rates."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $True
    }
}

