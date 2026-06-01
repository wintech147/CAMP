using module "..\CAMP.psm1"

class FP101 : CAMPCheck {
    <#
        Tune custom sensitive information types to reduce false positives
        Based on Microsoft Purview Deployment Models: Reduce False Positives and Lightweight DLP Blueprints
    #>

    FP101() {
        $this.Control            = "FP-101"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Classifier Tuning"
        $this.Name               = "Tune Custom Sensitive Information Types for Lower False Positives"
        $this.PassText           = "Your organization has custom sensitive information types with tuned confidence or instance thresholds"
        $this.FailRecommendation = "Your organization should tune custom sensitive information types so high-volume DLP scenarios do not rely only on default medium-confidence matching"
        $this.Importance         = "Reduce False Positives Step 1 recommends improving the precision of sensitive information types before broadening DLP enforcement. Custom SITs let administrators tune evidence, confidence, and instance thresholds for tenant-specific data patterns. This lightweight DLP tuning step does not require the commercial-only advanced classifiers used in later blueprint steps."
        $this.ExpandResults      = $True
        $this.ItemName           = "Sensitive Information Type"
        $this.DataType           = "Tuning Status"

        $this.Blueprint        = [CAMPBlueprint]::ReduceFalsePositives -bor [CAMPBlueprint]::LightweightDLP
        $this.MaturityLevel    = [CAMPMaturityLevel]::Good
        $this.BlueprintStages  = @{ "ReduceFalsePositives" = 1; "LightweightDLP" = 1 }

        $this.RequiredCollections = @("GetDLPCustomSIT")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Reduce False Positives Deployment Model"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-gcch-ip-compliance-center"
                "Custom sensitive information types"           = "https://learn.microsoft.com/purview/sit-create-a-custom-sensitive-information-type"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Reduce False Positives Deployment Model"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-dod-ip-compliance-center"
                "Custom sensitive information types"           = "https://learn.microsoft.com/purview/sit-create-a-custom-sensitive-information-type"
            }
        }
        else {
            $this.Links = @{
                "Reduce False Positives Deployment Model"      = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives"
                "Microsoft Purview portal - Information Protection" = "https://aka.ms/mcca-ip-compliance-center"
                "Custom sensitive information types"           = "https://learn.microsoft.com/purview/sit-create-a-custom-sensitive-information-type"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs custom sensitive information type definitions.")
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
            if ([string]::IsNullOrWhiteSpace([string]$Name)) { return "Unnamed custom SIT" }
            return [string]$Name
        }

        $CustomSITs = @(
            $Config["GetDLPCustomSIT"] |
                Where-Object {
                    $Publisher = & $GetPropertyValue $_ "Publisher"
                    [string]::IsNullOrWhiteSpace([string]$Publisher) -or ([string]$Publisher -notmatch "Microsoft")
                }
        )

        if ($CustomSITs.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "Sensitive information types"
            $ConfigObject.ConfigItem = "Only Microsoft built-in SITs detected"
            $ConfigObject.ConfigData = "No non-Microsoft custom sensitive information types were returned by GetDLPCustomSIT"
            $ConfigObject.InfoText   = "Create custom SITs for tenant-specific patterns and tune confidence or required evidence counts to reduce false positives."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            $this.AddConfig($ConfigObject)
            $this.Completed = $True
            return
        }

        $TunedSITs = @()

        foreach ($SensitiveInfoType in $CustomSITs) {
            $SensitiveInfoTypeName = & $GetObjectName $SensitiveInfoType
            $PatternValues = & $GetPropertyValue $SensitiveInfoType "Pattern" "Patterns"
            $Patterns = @($PatternValues | Where-Object { $null -ne $_ })
            $ConfidenceLevels = @()
            $RequiredCounts = @()

            foreach ($Pattern in $Patterns) {
                $ConfidenceValue = & $GetPropertyValue $Pattern "ConfidenceLevel"
                if (-not [string]::IsNullOrWhiteSpace([string]$ConfidenceValue)) {
                    $ConfidenceLevels += [string]$ConfidenceValue
                }

                $PatternRequiredCount = & $GetPropertyValue $Pattern "RequiredCount"
                if (-not [string]::IsNullOrWhiteSpace([string]$PatternRequiredCount)) {
                    $ParsedPatternCount = 0
                    if ([int]::TryParse([string]$PatternRequiredCount, [ref]$ParsedPatternCount)) {
                        $RequiredCounts += $ParsedPatternCount
                    }
                }

                $IdMatchValues = & $GetPropertyValue $Pattern "IdMatch" "IdMatches"
                foreach ($IdMatch in @($IdMatchValues | Where-Object { $null -ne $_ })) {
                    $RequiredCountValue = & $GetPropertyValue $IdMatch "RequiredCount"
                    if ([string]::IsNullOrWhiteSpace([string]$RequiredCountValue) -and $IdMatch -is [string] -and $IdMatch -match "RequiredCount\s*[:=]\s*(\d+)") {
                        $RequiredCountValue = $Matches[1]
                    }

                    if (-not [string]::IsNullOrWhiteSpace([string]$RequiredCountValue)) {
                        $ParsedCount = 0
                        if ([int]::TryParse([string]$RequiredCountValue, [ref]$ParsedCount)) {
                            $RequiredCounts += $ParsedCount
                        }
                    }
                }
            }

            $NonDefaultConfidenceLevels = @($ConfidenceLevels | Where-Object { $_ -and $_ -ine "Medium" })
            $RaisedRequiredCounts = @($RequiredCounts | Where-Object { $_ -gt 1 })
            $IsTuned = ($NonDefaultConfidenceLevels.Count -gt 0) -or ($RaisedRequiredCounts.Count -gt 0)
            $ConfidenceSummary = if ($ConfidenceLevels.Count -gt 0) { ($ConfidenceLevels | Sort-Object -Unique) -join ", " } else { "Not configured" }
            $RequiredCountSummary = if ($RequiredCounts.Count -gt 0) { ($RequiredCounts | Sort-Object -Unique) -join ", " } else { "Not configured" }

            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = $SensitiveInfoTypeName
            $ConfigObject.ConfigData = "ConfidenceLevel: $ConfidenceSummary; RequiredCount: $RequiredCountSummary"

            if ($IsTuned) {
                $TunedSITs += $SensitiveInfoTypeName
                $ConfigObject.ConfigItem = "Custom SIT tuning detected"
                $ConfigObject.InfoText   = "This custom SIT uses non-default confidence or requires multiple evidence instances."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $ConfigObject.ConfigItem = "Custom SIT uses default tuning"
                $ConfigObject.InfoText   = "Review whether this custom SIT should require stronger evidence or a non-medium confidence level in high-volume DLP scenarios."
                $ConfigObject.SetResult([CAMPConfigLevel]::Informational, "Pass")
            }

            $this.AddConfig($ConfigObject)
        }

        if ($TunedSITs.Count -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = "<B>Custom SIT tuning recommendation</B>"
            $ConfigObject.ConfigItem = "No tuned custom SITs detected"
            $ConfigObject.ConfigData = "All custom SITs returned by GetDLPCustomSIT use default confidence and single-instance matching"
            $ConfigObject.InfoText   = "Tune at least one custom SIT with non-medium confidence or RequiredCount greater than 1 to reduce false positives."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $True
    }
}

