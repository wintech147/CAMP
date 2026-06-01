using module "..\CAMP.psm1"

class Audit101 : CAMPCheck {
    <#
    

    #>

    Audit101() {
        
        $this.Control = "Audit-101"
        $this.ParentArea = "Discovery & Response"
        $this.Area = "Audit"
        $this.Name = "Enable Auditing in Microsoft 365"
        $this.Blueprint = [CAMPBlueprint]::SecureByDefault -bor [CAMPBlueprint]::LightweightDLP -bor [CAMPBlueprint]::CopilotAgents -bor [CAMPBlueprint]::DSPM -bor [CAMPBlueprint]::ShadowAI
        $this.MaturityLevel = [CAMPMaturityLevel]::Good
        $this.BlueprintStages = @{ "LightweightDLP" = 1; "CopilotAgents" = 1; "ShadowAI" = 1 }
        $this.Foundational = $true
        $this.PassText = "Your organisation has enabled auditing for your Microsoft 365 tenant"
        $this.FailRecommendation = "Your organization should enable auditing for your Microsoft 365 tenant"
        $this.Importance = "Your organization should enable auditing for your Microsoft 365 tenant. When audit log search in the Microsoft Purview portal is turned on, user and admin activity from your organization is recorded in the audit log and retained for 90 days, and up to one year depending on the license assigned to users."
        $this.ExpandResults = $True
        $this.ItemName = "Configuration"
        $this.DataType = "Setting"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "How to search Audit Log"              = "https://aka.ms/mcca-aa-docs-action-audit-log"
                "Audit (Premium)"                      = "https://aka.ms/mcca-aa-docs-learn-more-audit"
                "Microsoft Purview portal - Audit Log search" = "https://aka.ms/mcca-gcch-aa-compliance-center"
                "Compliance Manager - Audit Actions" = "https://aka.ms/mcca-gcch-aa-compliance-manager"
                }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "How to search Audit Log"              = "https://aka.ms/mcca-aa-docs-action-audit-log"
                "Audit (Premium)"                      = "https://aka.ms/mcca-aa-docs-learn-more-audit"
                "Microsoft Purview portal - Audit Log search" = "https://aka.ms/mcca-dod-aa-compliance-center"
                "Compliance Manager - Audit Actions" = "https://aka.ms/mcca-dod-aa-compliance-manager"
                }
        }else
        {
            $this.Links = @{
                "How to search Audit Log"              = "https://aka.ms/mcca-aa-docs-action-audit-log"
                "Audit (Premium)"                      = "https://aka.ms/mcca-aa-docs-learn-more-audit"
                "Microsoft Purview portal - Audit Log search" = "https://aka.ms/mcca-aa-compliance-center"
                "Compliance Manager - Audit Actions" = "https://aka.ms/mcca-aa-compliance-manager"
                }
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config) {   
        if ($Config["GetAdminAuditLogConfig"] -eq "Error") {
            $this.Completed = $false
        }
        else {
            $ConfigObjectList = @()
            $Auditconfiguration = $Config["GetAdminAuditLogConfig"]
            $ConfigObject = [CAMPCheckConfig]::new()
            $ConfigObject.Object = "Configuration"
            $ConfigObject.ConfigItem = "Auditing in Microsoft 365"
            
            # Determine if UnifiedAuditLogIngestionEnabled is true in Audit Configuration
            If ($($Auditconfiguration.UnifiedAuditLogIngestionEnabled) -eq $true) {
                $ConfigObject.ConfigData = "Enabled"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
            } 
            Else {
                $ConfigObject.ConfigData = "Disabled"
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                $ConfigObject.RemediationAction = "Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled " + "$" + "true"
                Write-Host "$(Get-Date) Generating Remediation Action to enable Auditing" -ForegroundColor Yellow

            }
 
            $this.AddConfig($ConfigObject)
            $ConfigObjectList += $ConfigObject
            $hasRemediation = $this.Config | Where-Object { $_.RemediationAction -ne ''}
            if ($($hasremediation.count) -gt 0)
            {
                $this.CAMPRemediationInfo = New-Object -TypeName CAMPRemediationInfo -Property @{
                    RemediationAvailable = $True
                    RemediationText      = "You need to connect to Exchange Online PowerShell to execute the below commands. Please follow steps defined in <a href = 'https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps'> Connect to Exchange Online PowerShell</a>."
                }
            }
            $this.Completed = $True
        }
        
    }

}