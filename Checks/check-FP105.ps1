using module "..\CAMP.psm1"

class FP105 : CAMPCheck {
    <#
        Tune confidence level and instance count thresholds in DLP rules
        Based on Microsoft Purview Deployment Models: Reduce False Positives and Lightweight DLP Blueprints
    #>

    FP105() {
        $this.Control            = "FP-105"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Classifier Tuning"
        $this.Name               = "Tune Confidence Level and Instance Count Thresholds in DLP Rules"
        $this.PassText           = "Your organization has at least one DLP rule with tuned sensitive information type confidence or instance-count thresholds"
        $this.FailRecommendation = "Your organization should tune confidence levels and minimum instance counts in high-volume DLP rules"
        $this.Importance         = "The optimization section of Reduce False Positives Step 1 recommends tuning DLP rule thresholds after improving SIT quality. DLP rules that use default thresholds can generate avoidable alerts, especially in broad Exchange, SharePoint, OneDrive, Teams, and endpoint deployments. This lightweight DLP tuning step improves rule precision without requiring commercial-only advanced classifiers."
        $this.ExpandResults      = $True
        $this.ItemName           = "DLP Rule"
        $this.DataType           = "Threshold Status"

        $this.Blueprint        = [CAMPBlueprint]::ReduceFalsePositives -bor [CAMPBlueprint]::LightweightDLP
        $this.MaturityLevel    = [CAMPMaturityLevel]::Best
        $this.BlueprintStages  = @{ "ReduceFalsePositives" = 1; "LightweightDLP" = 1 }

        $this.RequiredCollections = @("GetDlpComplianceRule")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Reduce False Positives Deployment Model"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-gcch-dlp-compliance-center"
                "Sensitive information types"                  = "https://learn.microsoft.com/purview/sit-sensitive-information-type-learn-about"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Reduce False Positives Deployment Model"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dod-dlp-compliance-center"
                "Sensitive information types"                  = "https://learn.microsoft.com/purview/sit-sensitive-information-type-learn-about"
            }
        }
        else {
            $this.Links = @{
                "Reduce False Positives Deployment Model"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
                "Microsoft Purview portal - Data Loss Prevention" = "https://aka.ms/mcca-dlp-compliance-center"
                "Sensitive information types"                  = "https://learn.microsoft.com/purview/sit-sensitive-information-type-learn-about"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs DLP rules to evaluate SIT thresholds.")
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

        $DlpRules = @($Config["GetDlpComplianceRule"] | Where-Object { $null -ne $_ })
        $RuleEvaluations = @()

        foreach ($Rule in $DlpRules) {
            $RuleName = & $GetObjectName $Rule
            $SensitiveInformationValue = & $GetPropertyValue $Rule "ContentContainsSensitiveInformation"
            $SensitiveInformationEntries = @($SensitiveInformationValue | Where-Object { $null -ne $_ })

            if ($SensitiveInformationEntries.Count -eq 0) {
                continue
            }

            $RuleTuned = $false
            $EntrySummaries = @()

            foreach ($Entry in $SensitiveInformationEntries) {
                $SitName = & $GetObjectName $Entry
                $MinCountValue = & $GetPropertyValue $Entry "MinCount" "minCount"
                $MaxCountValue = & $GetPropertyValue $Entry "MaxCount" "maxCount"
                $ConfidenceLevelValue = & $GetPropertyValue $Entry "ConfidenceLevel" "confidenceLevel"

                $MinCountTuned = $false
                if (-not [string]::IsNullOrWhiteSpace([string]$MinCountValue)) {
                    $ParsedMinCount = 0
                    if ([int]::TryParse([string]$MinCountValue, [ref]$ParsedMinCount) -and $ParsedMinCount -gt 1) {
                        $MinCountTuned = $true
                    }
                }

                $ConfidenceTuned = @("High", "Medium", "Low") -contains [string]$ConfidenceLevelValue
                if ($MinCountTuned -or $ConfidenceTuned) {
                    $RuleTuned = $true
                }

                $MinCountSummary = if ([string]::IsNullOrWhiteSpace([string]$MinCountValue)) { "default" } else { [string]$MinCountValue }
                $MaxCountSummary = if ([string]::IsNullOrWhiteSpace([string]$MaxCountValue)) { "default" } else { [string]$MaxCountValue }
                $ConfidenceSummary = if ([string]::IsNullOrWhiteSpace([string]$ConfidenceLevelValue)) { "default" } else { [string]$ConfidenceLevelValue }
                $EntrySummaries += "$SitName (MinCount=$MinCountSummary; MaxCount=$MaxCountSummary; ConfidenceLevel=$ConfidenceSummary)"
            }

            $RuleEvaluations += [pscustomobject]@{
                RuleName = $RuleName
                Tuned    = $RuleTuned
                Summary  = $EntrySummaries -join "; "
            }
        }

        if ($RuleEvaluations.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "DLP rules"
            $ConfigObject.ConfigItem = "No SIT-based rules detected"
            $ConfigObject.ConfigData = "No GetDlpComplianceRule entries had ContentContainsSensitiveInformation conditions"
            $ConfigObject.InfoText   = "Use SIT-based DLP rules before tuning confidence and instance-count thresholds."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
            $this.Completed = $True
            return
        }

        $TunedRules = @($RuleEvaluations | Where-Object { $_.Tuned })

        foreach ($Evaluation in $RuleEvaluations) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = $Evaluation.RuleName
            $ConfigObject.ConfigData = $Evaluation.Summary

            if ($Evaluation.Tuned) {
                $ConfigObject.ConfigItem = "Tuned SIT thresholds detected"
                $ConfigObject.InfoText   = "This rule has at least one SIT entry with MinCount greater than 1 or an explicit ConfidenceLevel."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $ConfigObject.ConfigItem = "Default SIT thresholds detected"
                $ConfigObject.InfoText   = "Review this rule if it is high-volume or produces false positives."
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            }

            $this.AddConfig($ConfigObject)
        }

        if ($TunedRules.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "<B>DLP threshold tuning recommendation</B>"
            $ConfigObject.ConfigItem = "All SIT thresholds are default"
            $ConfigObject.ConfigData = "No DLP rule had MinCount greater than 1 or an explicit High, Medium, or Low ConfidenceLevel"
            $ConfigObject.InfoText   = "Tune at least the highest-volume DLP rules by setting instance-count and confidence thresholds."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $True
    }
}

