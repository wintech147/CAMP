using module "..\CAMP.psm1"

class IP114 : CAMPCheck {
    <#
        Enable co-authoring for encrypted documents
        Based on Microsoft Purview Deployment Models: Secure by Default Blueprint
    #>

    IP114() {
        $this.Control            = "IP-114"
        $this.ParentArea         = "Microsoft Information Protection"
        $this.Area               = "Information Protection"
        $this.Name               = "Enable Co-Authoring for Encrypted Documents"
        $this.PassText           = "Your organization has co-authoring for encrypted sensitivity-labeled documents enabled"
        $this.FailRecommendation = "Your organization should enable co-authoring for encrypted documents protected by sensitivity labels"
        $this.Importance         = "Secure by Default Step 1 prerequisites include enabling modern sensitivity label experiences so protected Office documents remain usable. Co-authoring for encrypted documents lets users collaborate while encryption stays applied, reducing pressure to remove protection. This feature has limited sovereign-cloud rollout, so this CAMP check is marked CommercialOnly and generally requires Microsoft 365 E3 with Information Protection and Governance or equivalent licensing."
        $this.ExpandResults      = $True
        $this.ItemName           = "Policy Config"
        $this.DataType           = "Co-Authoring Status"

        $this.Blueprint        = [CAMPBlueprint]::SecureByDefault
        $this.MaturityLevel    = [CAMPMaturityLevel]::Best
        $this.BlueprintStages  = @{ "SecureByDefault" = 1 }
        $this.RequiredCollections = @()
        $this.RequiredGraphScopes = @()
        $this.RequiredLicenses    = @("Microsoft 365 E3 + Information Protection and Governance")
        $this.CommercialOnly      = $true

        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.microsoft.us"
                "Co-authoring with sensitivity labels"             = "https://learn.microsoft.com/purview/sensitivity-labels-coauthoring"
                "Sensitivity labels in Office apps"                = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://compliance.apps.mil"
                "Co-authoring with sensitivity labels"             = "https://learn.microsoft.com/purview/sensitivity-labels-coauthoring"
                "Sensitivity labels in Office apps"                = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
        else {
            $this.Links = @{
                "Secure by Default Deployment Model"              = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro"
                "Microsoft Purview portal - Information Protection" = "https://purview.microsoft.com"
                "Co-authoring with sensitivity labels"             = "https://learn.microsoft.com/purview/sensitivity-labels-coauthoring"
                "Sensitivity labels in Office apps"                = "https://learn.microsoft.com/purview/sensitivity-labels-office-apps"
            }
        }
    }

    GetResults($Config) {
        try {
            $PolicyConfig = Get-PolicyConfig -ErrorAction:Stop
        }
        catch {
            $this.EmitAwarenessRecommendation(
                "<B>Co-authoring for encrypted documents (manual review)</B>",
                "Get-PolicyConfig not available",
                "Co-authoring cmdlet was not available in this Security & Compliance PowerShell session.",
                "Verify co-authoring for encrypted documents in Microsoft Purview > Information Protection > Settings > Co-authoring. Once enabled it cannot be turned off — confirm prerequisites first (https://learn.microsoft.com/purview/sensitivity-labels-coauthoring)."
            )
            return
        }

        $EnableMipLabels = $null
        $EnableLabelCoauth = $null
        foreach ($Property in $PolicyConfig.PSObject.Properties) {
            if ($Property.Name -ieq "EnableMipLabels") { $EnableMipLabels = $Property.Value }
            if ($Property.Name -ieq "EnableLabelCoauth") { $EnableLabelCoauth = $Property.Value }
        }

        if ($null -eq $EnableMipLabels -and $null -eq $EnableLabelCoauth) {
            $this.EmitAwarenessRecommendation(
                "<B>Co-authoring for encrypted documents (manual review)</B>",
                "EnableMipLabels / EnableLabelCoauth not exposed",
                "Get-PolicyConfig did not return either property in this tenant or cloud.",
                "Verify co-authoring manually in Microsoft Purview > Information Protection > Settings > Co-authoring (https://learn.microsoft.com/purview/sensitivity-labels-coauthoring)."
            )
            return
        }

        $IsCoauthoringEnabled = ($EnableLabelCoauth -eq $true -or "$EnableLabelCoauth" -ieq "True" -or $EnableMipLabels -eq $true -or "$EnableMipLabels" -ieq "True")

        $ConfigObject = [CAMPCheckConfig]::new()
        $ConfigObject.Object = "Tenant Policy Configuration"
        $ConfigObject.ConfigItem = "EnableLabelCoauth: $EnableLabelCoauth; EnableMipLabels: $EnableMipLabels"
        if ($IsCoauthoringEnabled) {
            $ConfigObject.ConfigData = "Co-authoring for encrypted sensitivity-labeled documents appears enabled"
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
        }
        else {
            $ConfigObject.ConfigData = "Co-authoring for encrypted sensitivity-labeled documents is not enabled"
            $ConfigObject.InfoText = "Enable co-authoring for encrypted documents after validating app compatibility and sovereign-cloud availability."
            $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
        }
        $this.AddConfig($ConfigObject)

        $this.Completed = $true
    }
}
