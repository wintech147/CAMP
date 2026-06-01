using module "..\CAMP.psm1"

class IP117 : CAMPCheck {
    <#
        Follow the recommended 5x5 label taxonomy
        Based on Microsoft Purview Deployment Models: Secure by Default Blueprint
    #>

    IP117() {
        $this.Control            = "IP-117"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Information Protection"
        $this.Name               = "Follow the Recommended 5x5 Label Taxonomy with Specific People and Internal Exception Sublabels"
        $this.PassText           = "Your organization follows the recommended 5x5 sensitivity label taxonomy and includes exception sublabels under Confidential classifications"
        $this.FailRecommendation = "Your organization should align its sensitivity label taxonomy to no more than five parent labels and five sublabels per parent, including Specific People or Internal exception sublabels"
        $this.Importance         = "Secure by Default Step 1 recommends a simple label taxonomy so users can classify data consistently without decision fatigue. Keeping the taxonomy near a 5x5 structure and adding Specific People or Internal exception sublabels under Confidential or Highly Confidential labels supports secure collaboration exceptions. This baseline sensitivity labeling capability generally requires Microsoft 365 E3 with Information Protection and Governance or equivalent licensing."
        $this.ExpandResults      = $True
        $this.ItemName           = "Label Taxonomy"
        $this.DataType           = "5x5 Status"

        $this.Blueprint        = [CAMPBlueprint]::SecureByDefault
        $this.MaturityLevel    = [CAMPMaturityLevel]::Good
        $this.BlueprintStages  = @{ "SecureByDefault" = 1 }
        $this.RequiredCollections = @("GetLabel")
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E3 + Information Protection and Governance")
        $this.CommercialOnly      = $false

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.microsoft.us"
                "Sensitivity labels"                              = "https://learn.microsoft.com/purview/sensitivity-labels"
                "Manage sensitivity labels in Office apps"         = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.apps.mil"
                "Sensitivity labels"                              = "https://learn.microsoft.com/purview/sensitivity-labels"
                "Manage sensitivity labels in Office apps"         = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
        else {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://purview.microsoft.com"
                "Sensitivity labels"                              = "https://learn.microsoft.com/purview/sensitivity-labels"
                "Manage sensitivity labels in Office apps"         = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
    }

    GetResults($Config) {
        foreach ($key in $this.RequiredCollections) {
            if (-not $this.HasCollection($Config, $key)) {
                $this.SetUnavailable("Required collection '$key' is not available. This check needs sensitivity label taxonomy data from Get-Label.")
                return
            }
        }

        $ParentLabels = @()
        $SublabelCounts = @{}
        $HasRecommendedExceptionSublabel = $false
        $RecommendedExceptionSublabels = @()

        ForEach ($Label in $Config["GetLabel"]) {
            $LabelName = $Label.DisplayName
            if ([string]::IsNullOrWhiteSpace($LabelName)) { $LabelName = $Label.Name }
            $ParentName = $Label.ParentLabelDisplayName

            if ([string]::IsNullOrWhiteSpace($ParentName)) {
                $ParentLabels += $LabelName
                if (-not $SublabelCounts.ContainsKey($LabelName)) {
                    $SublabelCounts[$LabelName] = 0
                }
            }
            else {
                if (-not $SublabelCounts.ContainsKey($ParentName)) {
                    $SublabelCounts[$ParentName] = 0
                }
                $SublabelCounts[$ParentName] = $SublabelCounts[$ParentName] + 1

                if ($ParentName -match "(?i)highly.*confidential|confidential" -and
                    $LabelName -match "(?i)specific\s+people|internal\s+exception") {
                    $HasRecommendedExceptionSublabel = $true
                    $RecommendedExceptionSublabels += "$ParentName\$LabelName"
                }
            }
        }

        $ParentCount = $ParentLabels.Count
        $MaxSublabelCount = 0
        $ParentsOverLimit = @()
        foreach ($Parent in $SublabelCounts.Keys) {
            if ($SublabelCounts[$Parent] -gt $MaxSublabelCount) {
                $MaxSublabelCount = $SublabelCounts[$Parent]
            }
            if ($SublabelCounts[$Parent] -gt 5) {
                $ParentsOverLimit += "$Parent ($($SublabelCounts[$Parent]))"
            }
        }

        if ($ParentCount -eq 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "No Sensitivity Labels"
            $ConfigObject.ConfigItem = "No parent labels found"
            $ConfigObject.ConfigData = "Get-Label did not return a usable label taxonomy"
            $ConfigObject.InfoText = "Create a simple sensitivity label taxonomy before adding sublabels and exceptions."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
            $this.Completed = $true
            return
        }

        $SummaryObject = [CAMPCheckConfig]::new()
        $SummaryObject.Object = "5x5 Taxonomy Summary"
        $SummaryObject.ConfigItem = "Parents: $ParentCount; Max sublabels per parent: $MaxSublabelCount"
        if ($RecommendedExceptionSublabels.Count -gt 0) {
            $SummaryObject.ConfigData = "Recommended exception sublabels: $($RecommendedExceptionSublabels -join ', ')"
        }
        else {
            $SummaryObject.ConfigData = "No Specific People or Internal exception sublabels found under Confidential parents"
        }

        if ($ParentCount -le 5 -and $MaxSublabelCount -le 5 -and $HasRecommendedExceptionSublabel) {
            $SummaryObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
        }
        else {
            $SummaryObject.InfoText = "Review the sensitivity label taxonomy against the Secure by Default recommended 5x5 pattern and add Specific People or Internal exception sublabels under Confidential or Highly Confidential parents."
            if ($ParentCount -gt 5 -or $MaxSublabelCount -gt 5) {
                $SummaryObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            }
            else {
                $SummaryObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            }
        }
        $this.AddConfig($SummaryObject)

        if ($ParentCount -gt 5) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "Parent Label Count"
            $ConfigObject.ConfigItem = "More than five parent labels"
            $ConfigObject.ConfigData = "Parent labels: $($ParentLabels -join ', ')"
            $ConfigObject.InfoText = "Secure by Default recommends simplifying the taxonomy to five or fewer parent labels where possible."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            $this.AddConfig($ConfigObject)
        }

        if ($ParentsOverLimit.Count -gt 0) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "Sublabel Count"
            $ConfigObject.ConfigItem = "More than five sublabels under a parent"
            $ConfigObject.ConfigData = "Parents over limit: $($ParentsOverLimit -join ', ')"
            $ConfigObject.InfoText = "Reduce sublabel sprawl so users can quickly choose the right sensitivity label."
            $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
            $this.AddConfig($ConfigObject)
        }

        if (-not $HasRecommendedExceptionSublabel) {
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "Confidential Exception Sublabels"
            $ConfigObject.ConfigItem = "Specific People or Internal exception sublabel missing"
            $ConfigObject.ConfigData = "No matching sublabel found under Confidential or Highly Confidential parent labels"
            $ConfigObject.InfoText = "Add a Specific People or Internal exception sublabel to support controlled exceptions for confidential collaboration."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}
