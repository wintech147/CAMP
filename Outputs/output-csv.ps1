using module "..\CAMP.psm1"

class csv : CAMPOutput {

    $OutputDirectory = $null

    csv() {
        $this.Name = "CSV"
    }

    RunOutput($Checks, $Collection) {

        if ($null -eq $this.OutputDirectory) {
            $OutputDir = $this.DefaultOutputDirectory
        }
        else {
            $OutputDir = $this.OutputDirectory
        }

        $Tenant = $(($Collection["AcceptedDomains"] | Where-Object { $_.InitialDomain -eq $True }).DomainName -split '\.')[0]
        $ReportFileName = "CAMP-$($Tenant)-$(Get-Date -Format 'yyyyMMddHHmm').csv"
        $OutputFile = Join-Path $OutputDir $ReportFileName

        $Rows = @()

        foreach ($Check in $Checks) {

            # Build blueprint and stage strings up front so each row stays self-contained
            # and the CSV stays usable in Excel without needing a separate lookup table.
            $BlueprintNames = @()
            if ($Check.Blueprint -ne [CAMPBlueprint]::None) {
                foreach ($flag in [Enum]::GetValues([CAMPBlueprint])) {
                    if ($flag -ne [CAMPBlueprint]::None -and (($Check.Blueprint -band $flag) -eq $flag)) {
                        $BlueprintNames += $flag.ToString()
                    }
                }
            }
            $BlueprintString = $BlueprintNames -join ';'

            $StageString = ""
            if ($null -ne $Check.BlueprintStages -and $Check.BlueprintStages.Count -gt 0) {
                $StagePieces = @()
                foreach ($k in $Check.BlueprintStages.Keys) {
                    $StagePieces += "$k=$($Check.BlueprintStages[$k])"
                }
                $StageString = $StagePieces -join ';'
            }

            # If a check has any per-item config rows, emit one CSV row per config item so
            # admins can pivot/filter the report; otherwise emit a single summary row.
            if ($Check.Config.Count -gt 0) {
                foreach ($cfg in $Check.Config) {
                    $Rows += [PSCustomObject]@{
                        Control            = $Check.Control
                        ParentArea         = $Check.ParentArea
                        Area               = $Check.Area
                        Name               = $Check.Name
                        Blueprint          = $BlueprintString
                        MaturityLevel      = $Check.MaturityLevel.ToString()
                        Stages             = $StageString
                        Foundational       = $Check.Foundational
                        CommercialOnly     = $Check.CommercialOnly
                        Result             = $Check.Result.ToString()
                        Completed          = $Check.Completed
                        UnavailableReason  = $Check.UnavailableReason
                        FailCount          = $Check.FailCount
                        PassCount          = $Check.PassCount
                        InfoCount          = $Check.InfoCount
                        ItemObject         = $cfg.Object
                        ItemConfigItem     = $cfg.ConfigItem
                        ItemConfigData     = $cfg.ConfigData
                        ItemInfoText       = $cfg.InfoText
                        ItemLevel          = $cfg.Level.ToString()
                    }
                }
            }
            else {
                $Rows += [PSCustomObject]@{
                    Control            = $Check.Control
                    ParentArea         = $Check.ParentArea
                    Area               = $Check.Area
                    Name               = $Check.Name
                    Blueprint          = $BlueprintString
                    MaturityLevel      = $Check.MaturityLevel.ToString()
                    Stages             = $StageString
                    Foundational       = $Check.Foundational
                    CommercialOnly     = $Check.CommercialOnly
                    Result             = $Check.Result.ToString()
                    Completed          = $Check.Completed
                    UnavailableReason  = $Check.UnavailableReason
                    FailCount          = $Check.FailCount
                    PassCount          = $Check.PassCount
                    InfoCount          = $Check.InfoCount
                    ItemObject         = ""
                    ItemConfigItem     = ""
                    ItemConfigData     = ""
                    ItemInfoText       = ""
                    ItemLevel          = ""
                }
            }
        }

        $Rows | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

        $this.Completed = $true
        $this.Result = $OutputFile
    }
}
