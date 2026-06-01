using module "..\CAMP.psm1"

class FP103 : CAMPCheck {
    <#
        Use trainable classifiers for complex content
        Based on Microsoft Purview Deployment Models: Reduce False Positives Blueprint
    #>

    FP103() {
        $this.Control            = "FP-103"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Classifier Tuning"
        $this.Name               = "Use Trainable Classifiers for Complex Content"
        $this.PassText           = "Your organization uses at least one trainable classifier in DLP rules or sensitivity label auto-labeling conditions"
        $this.FailRecommendation = "Your organization should use trainable classifiers in DLP rules or sensitivity label auto-labeling conditions for complex content"
        $this.Importance         = "Reduce False Positives Step 3 recommends trainable classifiers for complex content that cannot be matched reliably with keywords or patterns. Trainable classifiers require Microsoft 365 E5 Compliance and are commercial-only at the time of writing. Referencing classifiers in DLP and auto-labeling conditions reduces false positives where business context matters."
        $this.ExpandResults      = $True
        $this.ItemName           = "Classifier"
        $this.DataType           = "Usage Status"

        $this.Blueprint        = [CAMPBlueprint]::ReduceFalsePositives
        $this.MaturityLevel    = [CAMPMaturityLevel]::Better
        $this.BlueprintStages  = @{ "ReduceFalsePositives" = 3 }

        $this.RequiredCollections = @("GetDlpComplianceRule", "GetLabel")
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $true

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-gcch-ip-compliance-center"
                "Trainable classifiers"                            = "https://learn.microsoft.com/purview/trainable-classifiers-learn-about"
                "Reduce False Positives Deployment Model"           = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-dod-ip-compliance-center"
                "Trainable classifiers"                            = "https://learn.microsoft.com/purview/trainable-classifiers-learn-about"
                "Reduce False Positives Deployment Model"           = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
            }
        }
        else {
            $this.Links = @{
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-ip-compliance-center"
                "Trainable classifiers"                            = "https://learn.microsoft.com/purview/trainable-classifiers-learn-about"
                "Reduce False Positives Deployment Model"           = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs DLP rules and sensitivity labels to find classifier references.")
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
            $Classifiers = @(Get-DataClassification -ErrorAction:Stop)
            $ClassifierSource = "Get-DataClassification"
        }
        catch {
            try {
                $Classifiers = @(Get-Classifier -ErrorAction:Stop)
                $ClassifierSource = "Get-Classifier"
            }
            catch {
                $this.EmitAwarenessRecommendation(
                    "<B>Trainable classifiers (manual review)</B>",
                    "Trainable classifier cmdlets not available",
                    "Neither Get-DataClassification nor Get-Classifier was available. Error: $($_.Exception.Message)",
                    "Review trainable classifiers in Microsoft Purview > Data classification > Trainable classifiers. Confirm built-in or custom classifiers are configured and referenced by DLP rules or auto-labeling policies. Requires Microsoft 365 E5 Compliance."
                )
                return
            }
        }

        if ($Classifiers.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "Trainable classifiers"
            $ConfigObject.ConfigItem = "No classifiers returned"
            $ConfigObject.ConfigData = "$ClassifierSource returned zero classifier objects"
            $ConfigObject.InfoText   = "Confirm Microsoft 365 E5 Compliance licensing and enable trainable classifiers for complex content scenarios."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
            $this.Completed = $True
            return
        }

        $DlpRules = @($Config["GetDlpComplianceRule"] | Where-Object { $null -ne $_ })
        $Labels = @($Config["GetLabel"] | Where-Object { $null -ne $_ })
        $UsedClassifiers = @()

        foreach ($Classifier in $Classifiers) {
            $ClassifierName = & $GetObjectName $Classifier
            $Publisher = & $GetPropertyValue $Classifier "Publisher"
            $ClassifierType = if ([string]$Publisher -match "Microsoft") { "Built-in" } else { "Custom" }
            $References = @(
                $ClassifierName,
                (& $GetPropertyValue $Classifier "Identity"),
                (& $GetPropertyValue $Classifier "Id"),
                (& $GetPropertyValue $Classifier "Guid"),
                (& $GetPropertyValue $Classifier "ClassifierId")
            ) | Where-Object { (-not [string]::IsNullOrWhiteSpace([string]$_)) -and (([string]$_).Length -gt 3) } | Select-Object -Unique

            $MatchedDlpRules = @()
            foreach ($Rule in $DlpRules) {
                $RuleText = & $GetObjectText $Rule "Classifier|ContentContains|AdvancedRule|Condition"
                foreach ($Reference in $References) {
                    if ($RuleText -match ([regex]::Escape([string]$Reference))) {
                        $MatchedDlpRules += (& $GetObjectName $Rule)
                        break
                    }
                }
            }

            $MatchedLabels = @()
            foreach ($Label in $Labels) {
                $LabelText = & $GetObjectText $Label "Auto|Condition|Classifier|Settings|Action"
                foreach ($Reference in $References) {
                    if ($LabelText -match ([regex]::Escape([string]$Reference))) {
                        $MatchedLabels += (& $GetObjectName $Label)
                        break
                    }
                }
            }

            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = $ClassifierName
            $ConfigObject.ConfigData = "Publisher: $Publisher; Source: $ClassifierSource"

            if ($MatchedDlpRules.Count -eq 0 -and $MatchedLabels.Count -eq 0) {
                $ConfigObject.ConfigItem = "$ClassifierType classifier available but unused"
                $ConfigObject.InfoText   = "No DLP rule or sensitivity label auto-labeling references were detected for this classifier."
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            }
            else {
                $UsedClassifiers += $ClassifierName
                $ConfigObject.ConfigItem = "$ClassifierType classifier in use"
                $ConfigObject.InfoText   = "DLP rules: $(($MatchedDlpRules | Sort-Object -Unique) -join ', '); Labels: $(($MatchedLabels | Sort-Object -Unique) -join ', ')"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }

            $this.AddConfig($ConfigObject)
        }

        if ($UsedClassifiers.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "<B>Trainable classifier recommendation</B>"
            $ConfigObject.ConfigItem = "Classifiers exist but are not referenced"
            $ConfigObject.ConfigData = "No classifier reference was found in GetDlpComplianceRule or GetLabel auto-labeling-related properties"
            $ConfigObject.InfoText   = "Use at least one trainable classifier in a DLP rule or sensitivity label auto-labeling condition for complex false-positive scenarios."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $True
    }
}

