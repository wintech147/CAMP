using module "..\CAMP.psm1"

class eDiscovery101 : CAMPCheck {
    <#
    

    #>

    eDiscovery101() {
        $this.Control = "eDiscovery-101"
        $this.ParentArea = "Discovery & Response"
        $this.Area = "eDiscovery"
        $this.Name = "Use eDiscovery (Standard) Cases to Support Legal Investigations"
        $this.PassText = "Your organization is using eDiscovery (Standard) cases to support legal investigations"
        $this.FailRecommendation = "Your organization needs to review (or set up) eDiscovery (Standard) cases"
        $this.Importance = "Your organization should use eDiscovery (Standard) cases to identify, hold, and export content found in Exchange Online mailboxes, Microsoft 365 Groups, Microsoft Teams, SharePoint Online and OneDrive for Business sites, and Skype for Business conversations, and Yammer teams."
        $this.ExpandResults = $True
        $this.ItemName = "Case Name"
        $this.DataType = "Case Status"
        if($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovGCCHigh")
        {
            $this.Links = @{
                "Get started with eDiscovery (Standard)"              = "https://aka.ms/mcca-ced-docs-action"
                "Microsoft Purview portal - eDiscovery (Standard)"    = "https://aka.ms/mcca-gcch-ced-compliance-center"
                "eDiscovery in Microsoft 365" = "https://aka.ms/mcca-aed-docs-learn-more"
                "Compliance Manager - eDiscovery" = "https://aka.ms/mcca-gcch-aed-compliance-manager"
            }
        }elseif ($this.ExchangeEnvironmentNameForCheck -ieq "O365USGovDoD")
        {
            $this.Links = @{
                "Get started with eDiscovery (Standard)"              = "https://aka.ms/mcca-ced-docs-action"
                "Microsoft Purview portal - eDiscovery (Standard)"    = "https://aka.ms/mcca-dod-ced-compliance-center"
                "eDiscovery in Microsoft 365" = "https://aka.ms/mcca-aed-docs-learn-more"
                "Compliance Manager - eDiscovery" = "https://aka.ms/mcca-dod-aed-compliance-manager"
            }
        }else
        {
            $this.Links = @{
                "Get started with eDiscovery (Standard)"              = "https://aka.ms/mcca-ced-docs-action"
                "Microsoft Purview portal - eDiscovery (Standard)"    = "https://aka.ms/mcca-ced-compliance-center"
                "eDiscovery in Microsoft 365" = "https://aka.ms/mcca-aed-docs-learn-more"
            }
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config) {   
        if ($Config["GetComplianceCaseCore"] -eq "Error") {
            $this.Completed = $false
        }
        else {
            $ConfigObjectList = @()
            
            $CasesPresent= $false
            $activecasepresent = $false
            ForEach ($CasesDefined in $Config["GetComplianceCaseCore"]) { 
                $Cases = $CasesDefined 
                $CasesPresent= $true
                
                if($($Cases.Status) -eq "Active")
                {
                    $ConfigObject = [CAMPCheckConfig]::new()
                    $ConfigObject.ConfigItem = "$($Cases.Name)"
                    $ConfigObject.ConfigData = "$($Cases.Status)"
                    $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                    $this.AddConfig($ConfigObject)
                    $ConfigObjectList += $ConfigObject
                    $activecasepresent= $true
                }
                $CasesPresent= $true
            }
            if(($activecasepresent -eq $false)  -and ($CasesPresent -eq $true))
            {
                    $ConfigObject = [CAMPCheckConfig]::new()
                    $ConfigObject.ConfigItem = "No active case"
                    $ConfigObject.ConfigData = ""
                    $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Pass")
                    $this.AddConfig($ConfigObject)
                    $ConfigObjectList += $ConfigObject
            }
            elseif($CasesPresent -eq $false)
            {
                $ConfigObject = [CAMPCheckConfig]::new()
                $ConfigObject.ConfigItem = "No eDiscovery cases found"
                $ConfigObject.ConfigData = ""
                $ConfigObject.SetResult([CAMPConfigLevel]::Ok, "Fail")
                $this.AddConfig($ConfigObject)
                $ConfigObjectList += $ConfigObject
            }
            
            $hasRemediation = $this.Config | Where-Object { $_.RemediationAction -ne ''}
            if ($($hasremediation.count) -gt 0)
            {
                $this.CAMPRemediationInfo = New-Object -TypeName CAMPRemediationInfo -Property @{
                    RemediationAvailable = $True
                    RemediationText      = "You need to connect to Security & Compliance PowerShell to execute the below commands. Please follow steps defined in <a href = 'https://learn.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps'> Connect to Security & Compliance PowerShell</a>."
                }
            }     
              $this.Completed = $True
        }
    }

}
