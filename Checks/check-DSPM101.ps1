using module "..\CAMP.psm1"

class DSPM101 : CAMPCheck {
    <#
        Assign required DSPM RBAC roles
        Based on Microsoft Purview Deployment Models: Deploy and use Data Security Posture Management
    #>

    DSPM101() {
        $this.Control            = "DSPM-101"
        $this.ParentArea         = "Data Security Posture Management"
        $this.Area               = "DSPM"
        $this.Name               = "Assign Required DSPM RBAC Roles"
        $this.PassText           = "Your organization has assigned members to the required DSPM RBAC roles"
        $this.FailRecommendation = "Your organization should assign members to all required DSPM RBAC roles"
        $this.Importance         = "DSPM Step 2 requires least-privilege role assignments before enabling analytics and reviewing posture insights. At least one member in each critical Microsoft Entra role helps administrators configure data security, compliance, and security controls without relying on Global Administrator. DSPM is largely commercial-only in GCCH/DoD at the time of writing, so this check is marked CommercialOnly. DSPM generally relies on Microsoft Purview E5 Compliance capabilities plus Microsoft Graph access with RoleManagement.Read.Directory and Directory.Read.All."
        $this.ExpandResults      = $True
        $this.ItemName           = "DSPM RBAC Role"
        $this.DataType           = "Assignment Status"

        # Microsoft Purview Deployment Model alignment - REQUIRED for new checks
        $this.Blueprint        = [CAMPBlueprint]::DSPM
        $this.MaturityLevel    = [CAMPMaturityLevel]::Good
        $this.BlueprintStages  = @{ "DSPM" = 2 }

        # Optional but recommended metadata - powers future docs and runtime gating
        $this.RequiredCollections = @("GetEntraDirectoryRoles")
        $this.RequiredGraphScopes = @("RoleManagement.Read.Directory", "Directory.Read.All")
        $this.RequiredLicenses    = @("Microsoft 365 E5 Compliance")
        $this.CommercialOnly      = $true

        # Three-way link block - follow this exact pattern (mirrors check-IP106.ps1)
        if ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh") {
            $this.Links = @{
                "DSPM deployment model"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 2: Configure access"         = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step2"
                "Microsoft Purview portal - DSPM"       = "https://purview.microsoft.com/dspm"
                "Learn about DSPM"                      = "https://learn.microsoft.com/purview/data-security-posture-management"
            }
        }
        elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD") {
            $this.Links = @{
                "DSPM deployment model"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 2: Configure access"         = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step2"
                "Microsoft Purview portal - DSPM"       = "https://purview.microsoft.com/dspm"
                "Learn about DSPM"                      = "https://learn.microsoft.com/purview/data-security-posture-management"
            }
        }
        else {
            $this.Links = @{
                "DSPM deployment model"                 = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro"
                "DSPM Step 2: Configure access"         = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-step2"
                "Microsoft Purview portal - DSPM"       = "https://purview.microsoft.com/dspm"
                "Learn about DSPM"                      = "https://learn.microsoft.com/purview/data-security-posture-management"
            }
        }
    }

    GetResults($Config) {
        if (-not $this.HasCollection($Config, "GetEntraDirectoryRoles")) {
            $this.EmitAwarenessRecommendation(
                "<B>DSPM RBAC roles (manual review)</B>",
                "Microsoft Graph data not collected",
                "GetEntraDirectoryRoles was not available — install Microsoft.Graph and grant RoleManagement.Read.Directory + Directory.Read.All to enumerate directory roles.",
                "Verify role assignments manually in Microsoft Entra > Roles & admins. Confirm at least one user is assigned each of: Information Protection Admin, Compliance Administrator, Data Security Administrator (preview), Security Administrator."
            )
            return
        }

        $RequiredRoles = @(
            @{
                DisplayName = "Information Protection Admin"
                LookupNames = @("Information Protection Admin", "Information Protection Administrator")
            }
            @{
                DisplayName = "Information Protection Analyst"
                LookupNames = @("Information Protection Analyst")
            }
            @{
                DisplayName = "Compliance Administrator"
                LookupNames = @("Compliance Administrator")
            }
            @{
                DisplayName = "Data Security Administrator"
                LookupNames = @("Data Security Administrator")
            }
            @{
                DisplayName = "Security Administrator"
                LookupNames = @("Security Administrator")
            }
        )

        $DirectoryRoles = @($Config["GetEntraDirectoryRoles"])

        foreach ($RoleDefinition in $RequiredRoles) {
            $ExpectedRoleName = $RoleDefinition["DisplayName"]
            $DirectoryRole = $null

            foreach ($LookupName in @($RoleDefinition["LookupNames"])) {
                $DirectoryRole = $DirectoryRoles | Where-Object { $_.DisplayName -ieq $LookupName } | Select-Object -First 1
                if ($null -ne $DirectoryRole) {
                    break
                }
            }

            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object     = $ExpectedRoleName
            $ConfigObject.ConfigItem = "Required DSPM access role"

            if ($null -eq $DirectoryRole) {
                $ConfigObject.ConfigData = "Role is not active or has no assignments"
                $ConfigObject.InfoText   = "Assign at least one least-privilege administrator to the $ExpectedRoleName role. If this Microsoft Entra role is missing from Get-MgDirectoryRole, it is typically not active because no members are assigned."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                $this.AddConfig($ConfigObject)
                continue
            }

            if ([string]::IsNullOrWhiteSpace([string]$DirectoryRole.Id)) {
                $ConfigObject.ConfigData = "Role ID unavailable; cannot enumerate members"
                $ConfigObject.InfoText   = "Reconnect Microsoft.Graph with RoleManagement.Read.Directory and Directory.Read.All scopes, then re-run, or verify membership manually in Microsoft Entra > Roles & admins."
                $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
                $this.AddConfig($ConfigObject)
                continue
            }

            try {
                $RoleMembers = @($DirectoryRole.Members)
                if ($RoleMembers.Count -eq 0) {
                    $RoleMembers = @(Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRole.Id -ErrorAction:Stop)
                }
            }
            catch {
                $ConfigObject.ConfigData = "Unable to enumerate members: $($_.Exception.Message)"
                $ConfigObject.InfoText   = "Reconnect Microsoft.Graph with RoleManagement.Read.Directory and Directory.Read.All scopes, then re-run, or verify membership manually in Microsoft Entra > Roles & admins."
                $ConfigObject.SetResult([CAMPConfigLevel]::Recommendation, "Fail")
                $this.AddConfig($ConfigObject)
                continue
            }

            $MemberCount = @($RoleMembers).Count
            if ($MemberCount -gt 0) {
                $ConfigObject.ConfigData = "$MemberCount member(s) assigned"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            }
            else {
                $ConfigObject.ConfigData = "No members assigned"
                $ConfigObject.InfoText   = "Assign at least one user or group to the $ExpectedRoleName role so DSPM access is available without overusing Global Administrator."
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
            }

            $this.AddConfig($ConfigObject)
        }

        $this.Completed = $true
    }
}
