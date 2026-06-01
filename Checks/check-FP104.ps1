using module "..\CAMP.psm1"

class FP104 : CAMPCheck {
    <#
        Apply document fingerprinting for standardized templates
        Based on Microsoft Purview Deployment Models: Reduce False Positives Blueprint
    #>

    FP104() {
        $this.Control            = "FP-104"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Classifier Tuning"
        $this.Name               = "Apply Document Fingerprinting for Standardized Templates"
        $this.PassText           = "Your organization has at least one document fingerprint referenced by a DLP rule"
        $this.FailRecommendation = "Your organization should create document fingerprints for standardized templates and reference them in DLP rules"
        $this.Importance         = "Reduce False Positives Step 4 recommends document fingerprinting for standardized forms and templates that are difficult to classify with keywords alone. Document fingerprinting requires Microsoft 365 E5 Compliance and is commercial-only at the time of writing. Referencing fingerprints in DLP rules improves precision for repeatable document formats."
        $this.ExpandResults      = $True
        $this.ItemName           = "Document Fingerprint"
        $this.DataType           = "DLP Rule Usage"

        $this.Blueprint        = [CAMPBlueprint]::ReduceFalsePositives
        $this.MaturityLevel    = [CAMPMaturityLevel]::Best
        $this.BlueprintStages  = @{ "ReduceFalsePositives" = 4 }

        $this.RequiredCollections = @("GetDlpComplianceRule")
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $true

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-gcch-ip-compliance-center"
                "Document fingerprinting"                          = "https://learn.microsoft.com/purview/sit-document-fingerprinting"
                "Reduce False Positives Deployment Model"           = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-dod-ip-compliance-center"
                "Document fingerprinting"                          = "https://learn.microsoft.com/purview/sit-document-fingerprinting"
                "Reduce False Positives Deployment Model"           = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
            }
        }
        else {
            $this.Links = @{
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-ip-compliance-center"
                "Document fingerprinting"                          = "https://learn.microsoft.com/purview/sit-document-fingerprinting"
                "Reduce False Positives Deployment Model"           = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs DLP rules to find document fingerprint references.")
                return
            }
        }

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
            if ([string]::IsNullOrWhiteSpace([string]$Name)) { return "Unnamed object" }
            return [string]$Name
        }

        $GetObjectText = {
            param($Object, [string]$PropertyNamePattern)
            if ($null -eq $Object) { return "" }
            $Parts = @()
            foreach ($Property in $Object.PSObject.Properties) {
                if ($Property.Name -match $PropertyNamePattern) {
                    try {
                        $ValueText = $Property.Value | ConvertTo-Json -Depth 8 -Compress -ErrorAction:Stop
                    }
                    catch {
                        $ValueText = $Property.Value | Out-String
                    }
                    $Parts += "$($Property.Name)=$ValueText"
                }
            }
            return ($Parts -join " ")
        }

        try {
            $Fingerprints = @(Get-DlpFingerprint -ErrorAction:Stop)
        }
        catch {
            $this.EmitAwarenessRecommendation(
                "<B>Document fingerprinting (manual review)</B>",
                "Get-DlpFingerprint not available",
                "Document fingerprint cmdlet was not available in this Security & Compliance PowerShell session. Error: $($_.Exception.Message)",
                "Review document fingerprints manually in Microsoft Purview > Data Loss Prevention > Classifiers > Document fingerprints. Confirm at least one fingerprint exists and is referenced by a DLP rule. Requires Microsoft 365 E5 Compliance."
            )
            return
        }

        if ($Fingerprints.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "Document fingerprinting"
            $ConfigObject.ConfigItem = "No fingerprints detected"
            $ConfigObject.ConfigData = "Get-DlpFingerprint returned zero fingerprint objects"
            $ConfigObject.InfoText   = "Create document fingerprints for standardized templates that need precise DLP matching."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
            $this.Completed = $True
            return
        }

        $DlpRules = @($Config["GetDlpComplianceRule"] | Where-Object { $null -ne $_ })
        $ReferencedFingerprints = @()

        foreach ($Fingerprint in $Fingerprints) {
            $FingerprintName = & $GetObjectName $Fingerprint
            $References = @(
                $FingerprintName,
                (& $GetPropertyValue $Fingerprint "Identity"),
                (& $GetPropertyValue $Fingerprint "Id"),
                (& $GetPropertyValue $Fingerprint "Guid"),
                (& $GetPropertyValue $Fingerprint "FingerprintId")
            ) | Where-Object { (-not [string]::IsNullOrWhiteSpace([string]$_)) -and (([string]$_).Length -gt 3) } | Select-Object -Unique

            $MatchedRules = @()
            foreach ($Rule in $DlpRules) {
                $RuleText = & $GetObjectText $Rule "Fingerprint|ContentContainsSensitiveInformation|SensitiveInformation|AdvancedRule|Condition"
                foreach ($Reference in $References) {
                    if ($RuleText -match ([regex]::Escape([string]$Reference))) {
                        $MatchedRules += (& $GetObjectName $Rule)
                        break
                    }
                }
            }

            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = $FingerprintName

            if ($MatchedRules.Count -gt 0) {
                $ReferencedFingerprints += $FingerprintName
                $ConfigObject.ConfigItem = "Fingerprint referenced by DLP rule"
                $ConfigObject.ConfigData = "DLP rules: $(($MatchedRules | Sort-Object -Unique) -join ', ')"
                $ConfigObject.InfoText   = "This document fingerprint is used in policy evaluation for standardized template matching."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $ConfigObject.ConfigItem = "Fingerprint not referenced by DLP rule"
                $ConfigObject.ConfigData = "No matching DLP rule reference was detected"
                $ConfigObject.InfoText   = "Reference this fingerprint in DLP rules if the template should drive lower-false-positive matching."
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            }

            $this.AddConfig($ConfigObject)
        }

        if ($ReferencedFingerprints.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "<B>Document fingerprinting recommendation</B>"
            $ConfigObject.ConfigItem = "Fingerprints exist but are unused"
            $ConfigObject.ConfigData = "No document fingerprint was referenced by GetDlpComplianceRule"
            $ConfigObject.InfoText   = "Add at least one document fingerprint to a DLP rule for standardized template scenarios."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $True
    }
}

