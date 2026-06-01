using module "..\CAMP.psm1"

class html : CAMPOutput {

    $OutputDirectory = $null
    $DisplayReport = $True

    html() {
        $this.Name = "HTML"
    }

    RunOutput($Checks, $Collection) {
        <#

        OUTPUT GENERATION / Header

    #>

        # Obtain the tenant domain and date for the report
        $TenantDomain = ($Collection["AcceptedDomains"] | Where-Object { $_.InitialDomain -eq $True }).DomainName
        $ReportDate = "$(Get-Date -format 'dd-MMM-yyyy HH:mm') $($(Get-TimeZone).Id)"
    
        # Obtain the Remediation Report File name
    
        if ($null -eq $this.OutputDirectory) {
            $OutputDir = $this.DefaultOutputDirectory
        }
        else {
            $OutputDir = $this.OutputDirectory
        }

        $RemediationReportFileName = Join-Path $OutputDir "CAMP-$(Get-Date -Format 'yyyyMMddHHmm')-Remediation.html"
        
        # Summary - merged "Fail" + "Recommendation" into a single Recommendation bucket so
        # the report only has two visual states: Pass (meets recommended config) and
        # Recommendation (action suggested). The legacy CAMPResult enum still has three
        # values internally so blueprint tagging and per-check logic don't change.
        $PassCount = $($Checks | Where-Object { $_.Result -eq "Pass" }).Count
        $RecommendationCount = $($Checks | Where-Object { $_.Result -eq "Fail" -or $_.Result -eq "Recommendation" }).Count
        #>
        # Misc
        $ReportTitle = "Configuration Analyzer for Microsoft Purview"

        # Area icons
        $AreaIcon = @{}
        $AreaIcon["Default"] = "fas fa-user-cog"
        $AreaIcon["Data Loss Prevention"] = "fas fa-scroll"
    
        # Output start
        if ($null -ne $this.VersionCheck.Version) {
            $version = $($this.VersionCheck.Version.ToString())
        }
        else { 
            $Version = '' 
        }

        $output = "<!doctype html>
    <html lang='en'>
    <head>
        <!-- Required meta tags -->
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>

        <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/css/all.min.css' crossorigin='anonymous'>
        <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css' integrity='sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T' crossorigin='anonymous'>
        <script src='https://code.jquery.com/jquery-3.3.1.slim.min.js' integrity='sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo' crossorigin='anonymous'></script>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js' integrity='sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1' crossorigin='anonymous'></script>
        <script src='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js' integrity='sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM' crossorigin='anonymous'></script>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/js/all.js'></script>
       

        <style>
        .navbar-custom { 
            background-color: #005494;
            color: white; 
            padding-bottom: 10px;

            
        } 
        /* Modify brand and text color */ 
          
        .navbar-custom .navbar-brand, 
        .navbar-custom .navbar-text { 
            color: white; 
            padding-top: 70px;
            padding-bottom: 10px;

        } 
        .card-header {
            background-color: #0078D4;;
            color: white; 
        }
       
        .table-borderless td,
        .table-borderless th {
            border: 0;
            padding:5px; 

        }
        .bd-callout {
            padding: 1.25rem;
            margin-top: 1.25rem;
            margin-bottom: 1.25rem;
            border: 1px solid #eee;
            border-left-width: .25rem;
            border-radius: .25rem
        }
        
        .bd-callout h4 {
            margin-top: 0;
            margin-bottom: .25rem
        }
        
        .bd-callout p:last-child {
            margin-bottom: 0
        }
        
        .bd-callout code {
            border-radius: .25rem
        }
        
        .bd-callout+.bd-callout {
            margin-top: -.25rem
        }
        
        .bd-callout-info {
            border-left-color: #5bc0de
        }
        
        .bd-callout-info h4 {
            color: #5bc0de
        }
        
        .bd-callout-warning {
            border-left-color: #f0ad4e
        }
        
        .bd-callout-warning h4 {
            color: #f0ad4e
        }
        
        .bd-callout-danger {
            border-left-color: #d9534f
        }
        
        .bd-callout-danger h4 {
            color: #d9534f
        }

        .bd-callout-success {
            border-left-color: #00bd19
        }
        .app-footer{
            background-color: #005494;
            color: white; 
            padding-top:2px; 
            padding-bottom :2px; 
        }
        </style>

        <title>$($ReportTitle)</title>

    </head>
    <body class='app bg-light'>

        <nav class='navbar navbar-custom' >
            <div class='container-fluid'>
                <div class='col-sm' style='text-align:left'>
                    <div class='row'><div><i class='fas fa-binoculars'></i></div><div class='ml-3'><strong>Configuration Analyzer for Microsoft Purview (CAMP)</strong></div></div>
                </div>
              
                <div class='col-sm' style='text-align:right'>
                <button type='button' class='btn btn-primary' onclick='javascript:window.print();'>Print</button>
                 <BR/> 
               

                </div>
            </div>
        </nav>  
              <div class='app-body p-3'>
            <main class='main'>
                <!-- Main content here -->
                <div class='container' style='padding-top:10px;'></div>
                <div class='card'>
                        
                        <div class='card-body'>

                            <h2 class='card-title'>$($ReportTitle)</h2>"

                            if ($(Test-Path -Path "$PSScriptRoot\..\Image\logo.jpg") -eq $True) {
                                $Output += "<img src='$PSScriptRoot\..\Image\logo.jpg' align='right' width='250px' height='150px'/>
                                "
                            }
                    
                            $Output += "<strong>Version $version </strong>
                            <p> CAMP assesses your compliance posture, highlights risks and recommends remediation steps to ensure compliance with essential data protection and regulatory standards.</p>"

                            

        
        $Output += "<table><tr><td>
                            <strong>Date</strong>  </td>
                            <td><strong>: $($ReportDate)</strong>  </td>
                            </tr>
                           
                            "
        if ($Collection["GetOrganisationConfig"] -ne "Error") {
            $OrganisationName = $Collection["GetOrganisationConfig"].DisplayName
            if (($null -ne $($OrganisationName)) -and ($($OrganisationName) -ne "")) { 

                $output += " <tr><td><strong>Organization &nbsp;</strong> </td>
                                             <td><strong>: $($OrganisationName)</strong> </td></tr>
                                             " 
            }
        }   
        if (($null -ne $($TenantDomain)) -and ($($TenantDomain) -ne "")) {
            $output += " <tr><td><strong>Tenant &nbsp;</strong> </td>
                             <td><strong>: $($TenantDomain)</strong> </td></tr>
                             " 
        }   
        $TenantGeoLocations = $Collection["GetOrganisationRegion"] | Where-Object { $_ -ne "INTL" }
        if ($TenantGeoLocations -ne "Error") {
            $RegionString = ""
            $NumberToRegionMapping = Get-NumberRegionMappingHashTable
            foreach ($Region in $TenantGeoLocations) {
                foreach ($Numbers in $($NumberToRegionMapping.Keys)) {
                    if ($($NumberToRegionMapping[$Numbers].Code) -eq $Region) {
                        if ($RegionString -eq "") {
                            $RegionString += "$($NumberToRegionMapping[$Numbers].Description)" 
                        }
                        else {
                            $RegionString += ", $($NumberToRegionMapping[$Numbers].Description)" 
                        }
                    }
                }

            }
            $output += " <tr><td><strong>Note &nbsp;</strong> </td>
                             <td><strong>:</strong>&nbsp;The following report is customized for following geolocation(s): $RegionString</td></tr>
                             " 
        }
        else {
            $output += " <tr><td><strong>Note &nbsp;</strong> </td>
                             <td><strong>:</strong>&nbsp;The following report is generalized on all geolocations</td></tr>
                             " 
        }
                            
                            
        $output += "  </table>"
        <#

                OUTPUT GENERATION / Version Warning

        #>
                                
        If ($this.VersionCheck.Updated -eq $False) {

            $Output += "
            <div class='alert alert-danger pt-2' role='alert'>
                CAMP is out of date. You're running version $($this.VersionCheck.Version) but version $($this.VersionCheck.GalleryVersion) is available! Run Update-Module CAMP to get the latest definitions!
            </div>
            
            "
        }

        $Output += "</div>
                </div>"



        <#

        OUTPUT GENERATION / Summary cards

    #>

        $Output += "<br/>"

        # Result colour legend — promoted to the very top of the report so users see what
        # each badge colour means before encountering any colored badges below. Previously
        # this lived at the bottom of the Solutions Summary table; user feedback was that
        # it was buried.
        $Output += "
    <div class='card m-3'>
        <div class='card-body py-2' style='display:flex; align-items:center; gap:14px;'>
            <strong style='margin-right:8px;'>Legend:</strong>
            <span class='badge badge-success' style='padding:6px 12px;'>&nbsp;</span>&nbsp;<span><strong>Pass</strong> &mdash; meets the recommended configuration</span>
            <span class='badge badge-info' style='padding:6px 12px; margin-left:18px;'>&nbsp;</span>&nbsp;<span><strong>Recommendation</strong> &mdash; action suggested to improve posture</span>
        </div>
    </div>
    "





        <#
    
        OUTPUT GENERATION / Blueprint Maturity Scorecard
        Shows per-blueprint Good/Better/Best progress for the six Microsoft Purview
        Deployment Models. Only renders blueprints that have at least one tagged check.

    #>

        $BlueprintOrder = @(
            @{ Flag = [CAMPBlueprint]::SecureByDefault;      Label = "Secure by Default";                              Anchor = "https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro" }
            @{ Flag = [CAMPBlueprint]::LightweightDLP;       Label = "Lightweight DLP";                                Anchor = "https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro" }
            @{ Flag = [CAMPBlueprint]::ShadowAI;             Label = "Prevent data leak to shadow AI";                 Anchor = "https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro" }
            @{ Flag = [CAMPBlueprint]::CopilotAgents;        Label = "Secure & govern Microsoft 365 Copilot agents";   Anchor = "https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment" }
            @{ Flag = [CAMPBlueprint]::DSPM;                 Label = "Data Security Posture Management (DSPM)";        Anchor = "https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro" }
            @{ Flag = [CAMPBlueprint]::ReduceFalsePositives; Label = "Reduce false positives";                         Anchor = "https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives" }
        )

        $AnyBlueprintCheck = $false
        foreach ($bp in $BlueprintOrder) {
            $matchCount = @($Checks | Where-Object {
                $_.Blueprint -ne [CAMPBlueprint]::None -and
                ($_.Blueprint -band $bp.Flag) -eq $bp.Flag
            }).Count
            if ($matchCount -gt 0) { $AnyBlueprintCheck = $true; break }
        }

        if ($AnyBlueprintCheck) {
            $Output += "
    <div class='card m-3'>
    <a name='BlueprintScorecard'></a>
        <div class='card-header'>
          Microsoft Purview Deployment Model Maturity Scorecard
        </div>
        <div class='card-body'>
          <p>Each row shows how many checks at each Lightweight DLP maturity level (Good / Better / Best) are passing for that deployment model. Click a blueprint name to open the official Microsoft Learn deployment guide.</p>
          <table class='table table-sm'>
            <thead>
              <tr>
                <th>Blueprint</th>
                <th style='text-align:center;'>Good</th>
                <th style='text-align:center;'>Better</th>
                <th style='text-align:center;'>Best</th>
                <th style='text-align:center;'>Overall</th>
              </tr>
            </thead>
            <tbody>"

            foreach ($bp in $BlueprintOrder) {
                $BpChecks = @($Checks | Where-Object {
                    $_.Blueprint -ne [CAMPBlueprint]::None -and
                    ($_.Blueprint -band $bp.Flag) -eq $bp.Flag -and
                    $_.Completed -eq $true
                })
                if ($BpChecks.Count -eq 0) { continue }

                $cellHtml = @{}
                foreach ($levelName in @('Good','Better','Best')) {
                    $matchingLevel = [CAMPMaturityLevel]::$levelName
                    $atLevel = @($BpChecks | Where-Object { $_.MaturityLevel -eq $matchingLevel })
                    if ($atLevel.Count -eq 0) {
                        $cellHtml[$levelName] = "<span class='text-muted'>&mdash;</span>"
                    } else {
                        $pass = @($atLevel | Where-Object { $_.Result -eq 'Pass' }).Count
                        # Per-cell counts are progress ratios, not pass/recommendation status — render in
                        # neutral grey so the colour story stays reserved for actual check outcomes
                        # (green badge = Pass, blue badge = Recommendation) elsewhere in the report.
                        $cellHtml[$levelName] = "<span class='badge badge-secondary' style='padding:6px 10px;'>$pass / $($atLevel.Count)</span>"
                    }
                }

                $totalPass = @($BpChecks | Where-Object { $_.Result -eq 'Pass' }).Count
                $totalCount = $BpChecks.Count
                $overallCell = "<span class='badge badge-secondary' style='padding:6px 10px;'>$totalPass / $totalCount</span>"

                $Output += "
              <tr>
                <td><a href='$($bp.Anchor)' target='_blank'>$($bp.Label)</a></td>
                <td style='text-align:center;'>$($cellHtml['Good'])</td>
                <td style='text-align:center;'>$($cellHtml['Better'])</td>
                <td style='text-align:center;'>$($cellHtml['Best'])</td>
                <td style='text-align:center;'>$overallCell</td>
              </tr>"
            }

            $Output += "
            </tbody>
          </table>
          <small class='text-muted'>Maturity levels map to the Microsoft Purview <a href='https://learn.microsoft.com/purview/deploymentmodels/depmod-overview' target='_blank'>Deployment Models</a> Good / Better / Best progression.</small>
        </div>
    </div>
    "
        }

        <#
    
        OUTPUT GENERATION / Summary

    #>

        $Output += "
    <div class='card m-3'>
    <a name='Solutionsummary'></a>

        <div class='card-header'>
          Solutions Summary
        </div>
        <div class='card-body'>"
        $Output += "<table class='table table-borderless'>
        <tr>
            <td width='20'><i class='fas fa-user-cog'></i>
            <td><strong>All Solutions</strong></td>
            <td align='right'>
                <span class='badge badge-info' style='padding:15px;text-align:center;width:40px;"; $output += "'>$($RecommendationCount)</span>
                <span class='badge badge-success' style='padding:15px;text-align:center;width:40px;"; $output += "'>$($PassCount)</span>
            </td>
        </tr>
        "

        ForEach ($ParentArea in ($Checks | Where-Object { $_.Completed -eq $true } | Group-Object ParentArea)) {  
            $Icon = $AreaIcon["Default"]
            If ($Null -eq $Icon) { $Icon = $AreaIcon["Default"] }
            $Output += "
        <tr >
            <td width='20'><i class='$Icon'></i>
            <td><strong>$($ParentArea.Name)</strong></td>   
        </tr>
        "    
            ForEach ($Area in ($Checks | Where-Object { $_.Completed -eq $true } | Where-Object { $_.ParentArea -eq $ParentArea.Name } | Group-Object Area)) {

                $Pass = @($Area.Group | Where-Object { $_.Result -eq "Pass" }).Count
                # Treat both "Fail" and "Recommendation" as a single Recommendation bucket
                $Recs = @($Area.Group | Where-Object { $_.Result -eq "Fail" -or $_.Result -eq "Recommendation" }).Count
                # Sanitized link target must match the per-area card's anchor below
                # so areas with '&' or other non-word chars still scroll into view.
                $AreaAnchor = ([regex]::Replace($Area.Name, '[^A-Za-z0-9_-]', '_'))

                $Output += 
                "
            <tr>
                <td width='20'>
                <td style='vertical-align:middle;'>&nbsp;&nbsp;<i class='fa fa-cog'></i>&nbsp;&nbsp; <a href='`#$AreaAnchor'>$($Area.Name)</a></td>
                <td align='right' style='vertical-align:middle;'>
                <span class='badge badge-info' style='padding:10px;text-align:center;width:30px;"; $output += "'>$($Recs)</span>
                <span class='badge badge-success' style='padding:10px;text-align:center;width:30px;"; $output += "'>$($Pass)</span>
                </td>
            </tr>
            "
            }
        }


        $Output += "
    </table>"
        $Output += "
        </div>
    </div>
    "

        <#

        OUTPUT GENERATION / Zones

    #>
        # Group incomplete (Completed=$false) checks into two buckets so we don't show a
        # red "issue in fetching" banner for checks that intentionally skipped because the
        # required data source wasn't available (Microsoft.Graph not installed, preview
        # feature not enabled in tenant, sovereign cloud missing the capability, etc.).
        $NotAssessedChecks = @($Checks | Where-Object { $_.Completed -eq $False -and -not [string]::IsNullOrWhiteSpace($_.UnavailableReason) })
        $ErrorChecks       = @($Checks | Where-Object { $_.Completed -eq $False -and [string]::IsNullOrWhiteSpace($_.UnavailableReason) })

        # Minimal HTML-encode helper - avoid System.Web.HttpUtility (not available
        # cross-platform in PowerShell 7 by default).
        $htmlEscape = {
            param([string]$s)
            if ($null -eq $s) { return "" }
            return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
        }

        if ($ErrorChecks.Count -gt 0) {
            $ErrorAreaList = ($ErrorChecks | Group-Object Area | Sort-Object Name | ForEach-Object { $_.Name }) -join ', '
            $Output += "
        <div class='alert alert-danger m-3' role='alert'>
            <strong>Heads up:</strong> there was an issue fetching information for the following areas: <em>$(& $htmlEscape $ErrorAreaList)</em>. Try running the tool again after some time, or check the log file for details.
        </div>"
        }

        if ($NotAssessedChecks.Count -gt 0) {
            $Output += "
        <div class='alert alert-info m-3' role='alert'>
            <strong>Not assessed:</strong> $($NotAssessedChecks.Count) check(s) were skipped because the required data source wasn't available. These typically need the Microsoft.Graph SDK to be installed (<code>Install-Module Microsoft.Graph</code>), a tenant with the licensed feature, or commercial-cloud availability. See the collapsible list below for the per-check reason.
            <details class='mt-2'>
                <summary>Show the $($NotAssessedChecks.Count) not-assessed check(s)</summary>
                <table class='table table-sm mt-2 mb-0'>
                    <thead><tr><th>Control</th><th>Name</th><th>Reason</th></tr></thead>
                    <tbody>"
            foreach ($skipped in ($NotAssessedChecks | Sort-Object Control)) {
                $Output += "
                        <tr>
                            <td><code>$(& $htmlEscape $skipped.Control)</code></td>
                            <td>$(& $htmlEscape $skipped.Name)</td>
                            <td><small>$(& $htmlEscape $skipped.UnavailableReason)</small></td>
                        </tr>"
            }
            $Output += "
                    </tbody>
                </table>
            </details>
        </div>"
        }


        ForEach ($Area in ($Checks | Where-Object { $_.Completed -eq $True } | Group-Object Area)) {

            # Write the top of the card
            # Sanitize to a CSS/jQuery-safe identifier — area names like
            # "AI & Shadow IT" or "Copilot & Agents" contain '&' and other characters
            # that break Bootstrap's data-target='#...' selector lookup.
            $CollapseId = ([regex]::Replace($Area.Name, '[^A-Za-z0-9_-]', '_'))
            $Output += "<a name='$CollapseId'></a> 
        <div class='card m-3'>
            <div class='card-header'>
            <div class=""row"">
            <div class='col-sm' style='text-align:left; margin-top:auto; margin-bottom:auto;'><a>$($Area.Name)</a></div>
            <div class='col-sm' style='text-align:right; padding-right:10px;'> 
            <span id='more_$($CollapseId)' data-toggle='collapse' data-target='#$($CollapseId)_body' style='cursor:pointer;'>
            <i class='fas fa-chevron-down' >&nbsp;&nbsp;</i>
            </span>
            </div>  
            </div>        
            </div>
            
            <div class='card-body collapse show' id='$($CollapseId)_body'>"

            # Each check
            [int] $count = 1 
            ForEach ($Check in ($Area.Group | Sort-Object Result -Descending)) {
                $RemediationActionsExist = $false
                $CheckCollapseId = $($CollapseId) + $count.ToString()

            
                If ($Check.Result -eq "Pass") {
                    $CalloutType = "bd-callout-success"
                    $BadgeType = "badge-success"
                    $BadgeName = "Pass"
                    $Icon = "fas fa-thumbs-up"
                    $IconColor = "green"
                    $Title = $Check.PassText
                } 
                Else {
                    # Merged "Recommendation" (was gray) and "Improvement" (was yellow with thumbs-down)
                    # into a single blue Recommendation state. Both legacy CAMPResult values
                    # ("Recommendation" and "Fail") land here so the report has only two visible
                    # outcomes per check: Pass (green) or Recommendation (blue).
                    $CalloutType = "bd-callout-info"
                    $BadgeType = "badge-info"
                    $BadgeName = "Recommendation"
                    $Icon = "fas fa-info-circle"
                    $IconColor = "#005494"
                    $Title = $Check.FailRecommendation
                }

                $Output += "        
                    <div class='row border-bottom' style='padding:5px; vertical-align:middle;'>
                    <div class='col-sm-10' style='text-align:left; margin-top:auto; margin-bottom:auto;'><h6>$($Check.Name)</h6></div>
                    <div class='col' style='text-align:right;padding-right:10px;'> 
                    <h6>
                    <span class='badge $($BadgeType)'>$($BadgeName)</span>&nbsp;&nbsp;
                    <i class='fas fa-chevron-down' data-toggle='collapse' data-target='#$($CheckCollapseId)'></i>
                    </h6>
                    </div>  
                    </div> "
                $Output += "  
                    <div class='row collapse' id='$($CheckCollapseId)'>
                        <div class='bd-callout $($CalloutType) b-t-1 b-r-1 b-b-1 p-3' >
                            <div class='container-fluid'>
                                <div class='row'>
                                    <div><i class='$($Icon)' color='$($IconColor)'></i></div>
                                    <div class='col-8'><h6>$($Title)</h6></div>
                                   
                                </div>"

                if ($Check.Importance) {

                    $Output += "
                                <div class='row p-3'>
                                    <div><p>$($Check.Importance)</p></div>
                                </div>"

                }
                        
                        
                If ($Check.ExpandResults -eq $True) {
                             

                    # We should expand the results by showing a table of Config Data and Items
                    $Output += "
                            <div class='row pl-2 pt-3'>"
                    if ($Check.Control -ne "Compliance Manager") {
                        $Output += "  <table class='table'>
                                    <thead class='border-bottom'>
                                        <tr>"

                        If ($Check.CheckType -eq [CheckType]::ObjectPropertyValue) {
                            # Object, property, value checks need three columns
                            $Output += "
                                <th align='center' text-align='center'>$($Check.ObjectType)</th>
                                <th align='center' text-align='center'>$($Check.ItemName)</th>
                                <th align='center' text-align='center'> $($Check.DataType)</th>
                                <th align='center' text-align='center'>Status</th>
                                "    
                        }
                        Else {
                            $Output += "
                                <th  align='center' text-align='center'>$($Check.ItemName)</th>
                                <th align='center' text-align='center'>$($Check.DataType)</th>
                                <th align='center' text-align='center'>Status</th>
                                "     
                        }

                        $Output += "
                                            <th style='width:50px'></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                            "

                        ForEach ($o in $Check.Config | Sort-Object Level -Descending) {
                            $ActionRequired = $false
                            # Two-state per-item rendering aligned with the new check-level model:
                            #   - Pass (any Level >= Ok) -> green check-circle
                            #   - Recommendation (None / Recommendation) -> blue info-circle
                            if ($o.Level -ne [CAMPConfigLevel]::None -and $o.Level -ne [CAMPConfigLevel]::Recommendation) {
                                $oicon = "fas fa-check-circle text-success"
                                $LevelText = "Pass"
                            }
                            Else {
                                $oicon = "fas fa-info-circle text-info"
                                $LevelText = "Recommendation"
                                if ($o.Level -eq [CAMPConfigLevel]::None) { $ActionRequired = $true }
                            }

                            $Output += "
                                <tr>
                                "
                            if ($($o.RemediationAction)) {
                                $RemediationActionsExist = $true
                            }
                            If ($Check.CheckType -eq [CheckType]::ObjectPropertyValue) {
                                # Object, property, value checks need three columns
                                $Output += "
                                        <td>$($o.Object)</td>
                                        <td style='word-wrap:break-word;' width = '35%'>$($o.ConfigItem)</td>
                                        <td style='word-wrap:break-word;' width = '30%'>$($o.ConfigData)</td>
                                    "
                            }
                            Else {
                                $Output += "
                                        <td>$($o.ConfigItem)</td>
                                        <td style='word-wrap:break-word;' width = '35%'>$($o.ConfigData)</td>
                                    "
                            }

                            $Output += "
                                    <td style='text-align:left'>
                                        <div class='row badge badge-pill badge-light'>"
                            if ($o.Level -eq [CAMPConfigLevel]::Informational) {
                                $Output += "<span style='vertical-align: left;'>$($LevelText)</span><br/></div>"  
                            }
                            else {
                                $Output += "<span class='$($oicon)' style='vertical-align: left;'></span>
                                            <span style='vertical-align: left;'>$($LevelText)</span><br/></div>"
                            }
                            if ($ActionRequired -eq $true -and $($o.RemediationAction)) {
                                $Output += " <span style='vertical-align: left;'><small><center>Remediation Available</center></small></span> "
                            }
                            $Output += " 
                                    </td>
                                </tr>
                                "

                            # Recommendation segment
                            #if($o.Level -eq [CAMPConfigLevel]::Recommendation)
                            #{
                            if (($null -ne $($o.InfoText)) -and ($($o.InfoText) -ne "" ) ) {
                                        
                                $Output += "
                                    <tr>"
                                If ($Check.CheckType -eq [CheckType]::ObjectPropertyValue) {
                                    $Output += "<td colspan='4' style='border: 0;'>"
                                }
                                else {
                                    $Output += "<td colspan='3' style='border: 0;'>"
                                }
                                   
                                $Output += "
                                    <div class='alert alert-light' role='alert' style='text-align: left;'>
                                    <span class='fas fa-info-circle text-muted' style='vertical-align: left; padding-right:5px'></span>
                                    <span style='vertical-align: middle;'>$($o.InfoText)</span>
                                    </div>
                                    "
                                    
                                $Output += "</td></tr>
                                    
                                    "
                            }
                                    
                        }

                        #}

                        $Output += "
                                    </tbody>
                                </table>"
                    }
                    # If any links exist
                    If ($Check.Links) {
                        $Output += "
                                <table class='table'> <tr>"                                 
                        $LinksInfo = $Check.Links
                        [int] $CountOfLinks = $LinksInfo.Keys.Count
                        [int] $itr = 0
                        $LinksNameValuePair = $LinksInfo.GetEnumerator() | Sort-Object -Property Name
                        while ($itr -lt $CountOfLinks) {
                            $Output += "

                                   
                                    <td style='padding-top:20px;'><i class='fas fa-external-link-square-alt'></i>&nbsp;<a href='$($LinksNameValuePair.Value[$itr])' target=""blank"">$($LinksNameValuePair.Name[$itr])</a></td>
                                    
                                    "
                            $itr = $itr + 1
                        }

                        if ($RemediationActionsExist -eq $true) {
                                    
                            $Output += "
                            
                                    <td ><a class='btn btn-primary' href='$($RemediationReportFileName)' target='_blank' role='button'>Remediation Script</a></td>
                                     
                                    "
                                    
                        }
                        $Output += "
                               </tr> </table>
                                "
                        $Output += "
                                </table>
                                "
                    }

                    $Output += "
                            </div>"

                }
                        

                $Output += "
                            </div>
                        </div> </div> "
                $count += 1
            }            

            # End the card
            $Output += "   <div class='col-sm' style='text-align:right; padding-right:10px;'>  <a href='#Solutionsummary'>Go to Solutions Summary</a></div>
            </div>
                      

        </div>"
        }
        <#

        OUTPUT GENERATION / Footer

    #>

        $Output += "
            </main>
            <center>Bugs? Issues? Suggestions? <a href='https://github.com/OfficeDev/CAMP'>GitHub</center>
            </div>
            <footer class='app-footer'>
            <p><center><i>&nbsp;&nbsp;&nbsp;&nbsp;Disclaimer: Recommendations from  (CAMP) should not be interpreted as a guarantee of compliance. It is up to you to evaluate and validate the effectiveness of customer controls per your regulatory environment. <br>
               </i></center> </p></footer>
        </body>
    </html>"


        # Write to file

       
        $Tenant = $(($Collection["AcceptedDomains"] | Where-Object { $_.InitialDomain -eq $True }).DomainName -split '\.')[0]
        $ReportFileName = "CAMP-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm').html"

        $OutputFile = Join-Path $OutputDir $ReportFileName

        $Output | Out-File -FilePath $OutputFile

        If ($this.DisplayReport) {
            Invoke-Expression $OutputFile
        }

        $this.Completed = $True
        $this.Result = $OutputFile

    }

}