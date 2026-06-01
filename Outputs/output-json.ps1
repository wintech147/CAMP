using module "..\CAMP.psm1"

class json : CAMPOutput
{

    $OutputDirectory=$null

    json()
    {
        $this.Name="JSON"
    }

    RunOutput($Checks,$Collection)
    {

        # Write to file

        if($null -eq $this.OutputDirectory)
        {
            $OutputDir = $this.DefaultOutputDirectory
        }
        else 
        {
            $OutputDir = $this.OutputDirectory
        }

        $Tenant = $(($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName -split '\.')[0]
        $TenantDomain = ($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName
        $ReportFileName = "CAMP-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm').json"

        $OutputFile = Join-Path $OutputDir $ReportFileName

        # Build per-blueprint maturity scorecard data so downstream consumers (Power BI,
        # Splunk, custom dashboards) can chart Good/Better/Best progress per blueprint
        # without re-implementing the rollup logic.
        $BlueprintOrder = @(
            @{ Flag = [CAMPBlueprint]::SecureByDefault;      Label = "SecureByDefault" }
            @{ Flag = [CAMPBlueprint]::LightweightDLP;       Label = "LightweightDLP" }
            @{ Flag = [CAMPBlueprint]::ShadowAI;             Label = "ShadowAI" }
            @{ Flag = [CAMPBlueprint]::CopilotAgents;        Label = "CopilotAgents" }
            @{ Flag = [CAMPBlueprint]::DSPM;                 Label = "DSPM" }
            @{ Flag = [CAMPBlueprint]::ReduceFalsePositives; Label = "ReduceFalsePositives" }
        )

        $BlueprintScorecard = @{}
        foreach ($bp in $BlueprintOrder) {
            $BpChecks = @($Checks | Where-Object {
                $_.Blueprint -ne [CAMPBlueprint]::None -and
                ($_.Blueprint -band $bp.Flag) -eq $bp.Flag
            })
            $byLevel = @{}
            foreach ($level in @("Good","Better","Best")) {
                $matchingLevel = [CAMPMaturityLevel]::$level
                $atLevel = @($BpChecks | Where-Object { $_.MaturityLevel -eq $matchingLevel })
                $byLevel[$level] = @{
                    Total = $atLevel.Count
                    Pass  = @($atLevel | Where-Object { $_.Result -eq "Pass" }).Count
                    Fail  = @($atLevel | Where-Object { $_.Result -eq "Fail" }).Count
                    Info  = @($atLevel | Where-Object { $_.Result -eq "Recommendation" }).Count
                }
            }
            $BlueprintScorecard[$bp.Label] = @{
                TotalChecks = $BpChecks.Count
                ByMaturity  = $byLevel
            }
        }

        # Enrich each check with a serialization-friendly Blueprint name list — the raw
        # [Flags] enum serializes as an integer mask, which is opaque without the schema.
        $EnrichedChecks = foreach ($Check in $Checks) {
            $BlueprintNames = @()
            if ($Check.Blueprint -ne [CAMPBlueprint]::None) {
                foreach ($flag in [Enum]::GetValues([CAMPBlueprint])) {
                    if ($flag -ne [CAMPBlueprint]::None -and (($Check.Blueprint -band $flag) -eq $flag)) {
                        $BlueprintNames += $flag.ToString()
                    }
                }
            }

            [PSCustomObject]@{
                Control            = $Check.Control
                ParentArea         = $Check.ParentArea
                Area               = $Check.Area
                Name               = $Check.Name
                PassText           = $Check.PassText
                FailRecommendation = $Check.FailRecommendation
                Importance         = $Check.Importance
                BlueprintMask      = [int]$Check.Blueprint
                Blueprints         = $BlueprintNames
                MaturityLevel      = $Check.MaturityLevel.ToString()
                BlueprintStages    = $Check.BlueprintStages
                Foundational       = $Check.Foundational
                CommercialOnly     = $Check.CommercialOnly
                RequiredCollections = $Check.RequiredCollections
                RequiredGraphScopes = $Check.RequiredGraphScopes
                RequiredLicenses    = $Check.RequiredLicenses
                Result             = $Check.Result.ToString()
                Completed          = $Check.Completed
                UnavailableReason  = $Check.UnavailableReason
                FailCount          = $Check.FailCount
                PassCount          = $Check.PassCount
                InfoCount          = $Check.InfoCount
                Links              = $Check.Links
                Config             = $Check.Config | ForEach-Object {
                    [PSCustomObject]@{
                        Object           = $_.Object
                        ConfigItem       = $_.ConfigItem
                        ConfigData       = $_.ConfigData
                        InfoText         = $_.InfoText
                        Level            = $_.Level.ToString()
                        RemediationAction = $_.RemediationAction
                    }
                }
            }
        }

        $Result = New-Object -TypeName PSObject -Property @{
            SchemaVersion       = "2"
            ResultDate          = $(Get-Date -format s)
            Tenant              = $Tenant
            TenantDomain        = $TenantDomain
            TotalChecks         = $Checks.Count
            BlueprintScorecard  = $BlueprintScorecard
            Results             = $EnrichedChecks
        }

        $Result | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutputFile

        $this.Completed = $True
        $this.Result = $OutputFile

    }

}