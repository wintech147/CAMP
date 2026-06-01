# Overview

Configuration Analyzer for Microsoft Purview (CAMP) is a tool which, on execution, generates a report highlighting known issues in your compliance configurations in achieving data protection guidelines and recommends best practices to follow.

# What is Configuration Analyzer for Microsoft Purview (CAMP)?

It is a PowerShell-based utility that will fetch your tenant’s current configurations & validate these configurations against Microsoft 365 recommended best practices. These best practices are based on a set of controls that include key regulations and standards for data protection and general data governance. CAMP then provides you with an actionable status report for improving your compliance posture.

# Why should I use it?

Often tenants face challenges in diagnosing their compliance posture & ensuring that they have the right configurations in place to protect their environment completely. These are largely manual processes which tend to be time consuming & allow for human error. Furthermore, with the evolving compliance landscape the risk of blind spots also increases.
CAMP is a diagnostic tool that will report the status of your current configurations. This allows you to focus efforts more on making the right configurations. 

# What is in scope?

This version will provide you recommendations for the Microsoft Purview solutions listed below. We will keep adding more solutions & richer recommendations in future versions of this tool.

        1.	Microsoft Information Protection
            a. 	Data Loss Prevention
            b.	Information Protection
        2.	Data Lifecycle Management
            a.	Data Lifecycle Management
            b.	Records Management
        3.	Insider Risk
            a.	Communication Compliance
            b.	Insider Risk Management
        4.	Discovery & Response
            a.	Audit
            b.	eDiscovery

## Microsoft Purview Deployment Model coverage

CAMP now ships explicit coverage for all six official [Microsoft Purview Deployment Models](https://learn.microsoft.com/purview/deploymentmodels/depmod-overview) — the "blueprints" that the Microsoft Purview product engineering team publishes as the recommended Good / Better / Best progressions:

| # | Blueprint | What CAMP checks |
|---|-----------|------------------|
| 1 | [Secure by Default](https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-intro) | Default labels, downgrade justification, SharePoint/OneDrive label enablement, encryption, container labels, label inheritance, default sharing link, co-authoring, all-credentials auto-labeling, label mismatch email, 5×5 taxonomy, Adaptive Protection. |
| 2 | [Lightweight guide to mitigate data leakage](https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro) | Dedicated Exchange DLP, Teams DLP, Endpoint DLP, unlabeled-content DLP, custom SITs, Adaptive Protection condition, Conditional Access tie-in. |
| 3 | [Prevent data leak to shadow AI](https://learn.microsoft.com/purview/deploymentmodels/depmod-data-leak-shadow-ai-intro) | DSPM for AI activation, endpoint browser restrictions on AI sites, Microsoft 365 Copilot location DLP, label-scoped Copilot processing, communication compliance for risky prompts, Entra/Defender/Intune coverage awareness. |
| 4 | [Secure & govern Microsoft 365 Copilot agents](https://learn.microsoft.com/purview/deploymentmodels/depmod-sc-agents-deployment) | Audit on for Copilot, Restricted SharePoint Search, data risk assessments, DLP restricting Copilot grounding, label inheritance in interactions, retention/eDiscovery/comms compliance for Copilot interactions. |
| 5 | [Deploy and use DSPM](https://learn.microsoft.com/purview/deploymentmodels/depmod-dspm-intro) | RBAC role assignment, DLP analytics, IRM analytics, DSPM recommendations review, Security Copilot integration. |
| 6 | [Reduce false positives with SITs & advanced classifiers](https://learn.microsoft.com/purview/deploymentmodels/depmod-reduce-false-positives) | Custom SIT tuning, Exact Data Match (EDM), trainable classifiers, document fingerprinting, confidence/instance-count thresholds. |

### Filter by blueprint with the new `-Blueprint` parameter

```powershell
# Default - run every check across every blueprint
Get-CAMPReport

# Only run the Shadow AI checks (plus foundational legacy CAMP checks)
Get-CAMPReport -Blueprint @(3)

# Run the Secure by Default + Lightweight DLP scorecard together
Get-CAMPReport -Blueprint @(1,2)
```

`-Blueprint` accepts numbers 1..6 matching the table above. The 19 legacy CAMP checks (Audit, eDiscovery, Information Governance, etc.) are flagged `Foundational` and are always included, so a `-Blueprint 3` (Shadow AI) report still surfaces baseline tenant hygiene findings.

### Multiple output formats with the new `-OutputFormat` parameter

```powershell
# Default - HTML only (unchanged from previous releases)
Get-CAMPReport

# Emit every supported format in one run
Get-CAMPReport -OutputFormat HTML,JSON,CSV,Markdown
```

Each format writes a separate file under your CAMP output directory:

* **HTML** — the original interactive report, now includes a **Blueprint Maturity Scorecard** at the top showing Good / Better / Best progress per blueprint.
* **JSON** — full per-check detail plus a programmatic `BlueprintScorecard` object (`SchemaVersion = "2"`), ready for Power BI / Splunk / Sentinel ingestion.
* **CSV** — one row per (check × per-item config) for easy pivoting in Excel.
* **Markdown** — leadership-friendly executive summary with the scorecard table and per-check findings, ready to paste into a ticket, OneNote, or status email.

### Optional: Microsoft Graph SDK for richer blueprint coverage

Several of the newer blueprint checks (Shadow AI, Secure Copilot Agents, DSPM, container-label sites) pull data from Microsoft Graph in addition to Security & Compliance PowerShell. Install the SDK once with:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

When the SDK is present, CAMP prompts you for an interactive Graph sign-in (read-only scopes: `Sites.Read.All`, `Directory.Read.All`, `Application.Read.All`, `InformationProtectionPolicy.Read`, `Policy.Read.All`, `RoleManagement.Read.Directory`). When the SDK is missing, those checks degrade gracefully with a clear "not assessed" message — every other check still runs.

### Per-check blueprint mapping

Each check's class declaration in `Checks/check-*.ps1` sets `$this.Blueprint = [CAMPBlueprint]::SecureByDefault -bor [CAMPBlueprint]::LightweightDLP` (etc.) and `$this.MaturityLevel = [CAMPMaturityLevel]::Good|Better|Best`. The HTML / JSON / Markdown reports surface this mapping automatically. Notable additions in this release:

| Area | New check IDs |
|------|---------------|
| Information Protection | `IP-109` … `IP-117` (auto-labeling, label inheritance, container labels, default sharing link, co-authoring, all-credentials SIT, label mismatch email, 5×5 taxonomy) |
| Insider Risk Management | `IRM-104` (Adaptive Protection), `IRM-105` (IRM analytics) |
| Data Loss Prevention | `DLP-203` … `DLP-208` (Exchange / Teams / unlabeled-content / custom SITs / Adaptive Protection / Conditional Access tie-in) |
| Microsoft Purview AI | `AI-101` … `AI-107` (DSPM for AI, browser DLP, Copilot DLP, label-scoped Copilot, comms compliance for prompts, Entra/Defender, Intune MAM) |
| Copilot & Agents | `COP-101` … `COP-108` (audit, Restricted Search, data risk assessments, grounding DLP, label inheritance, retention, eDiscovery, comms compliance) |
| Data Security Posture Management | `DSPM-101` … `DSPM-105` (RBAC roles, DLP analytics, IRM analytics, recommendations review, Security Copilot) |
| Classifier Tuning | `FP-101` … `FP-105` (custom SITs, EDM, trainable classifiers, document fingerprinting, threshold tuning) |

These checks help organizations implement Microsoft's recommended data protection strategies for preventing oversharing, data leakage, and securing AI/Copilot interactions.

# That is awesome! How do I run it?

#   Pre-Requisites

Before running the tool, you should confirm your Microsoft 365 subscription and any add-ons. To access and use CAMP, your organization must have one of the following subscriptions or add-ons:
   
    •	Microsoft 365 E5 subscription (paid or trial version)
    •	Microsoft 365 E3 subscription + the Microsoft 365 E5 Compliance add-on

You will be able to run this tool without an E5 subscription or M365 E5 Compliance add-on, but CAMP will still report statuses for E5 workloads & capabilities.

For running the tool:
     

1.  You must have PowerShell version 5.1 or above to run this tool. PowerShell 7.x is also supported and recommended for cross-platform use.

2.  You must have Exchange Online PowerShell module version 3.0.0 or higher (You can follow
    either of the following 2 methods to download the same)

    * Exchange Online PowerShell module that is available via the
    PowerShell gallery:

    > Install-Module -Name ExchangeOnlineManagement

    * Exchange Online PowerShell module (<https://aka.ms/exopsmodule>)

3.  You must have appropriate role/user permissions to be able to run
    this tool. The following table provides details of which roles will
    have access to which sections of the report.

Other roles within the organisation (not listed in the table below) may
not be able to run the tool or they may be able to run the tool with
limited information in the final report.


|User Role                           |MIP      |            | MIG          |                      |Insider Risk |     |Discovery & Response |         |
|------------------------------------|---------|------------|--------------|----------------------|---------|--------|-----------|---------------- |
|                                    |**DLP**  |**IP**      |**IG**        |**RM**                |**IRM**  |**CC**  |**Audit**  |**eDiscovery** |
|Azure Information Protection admin  |No       |No<sup>1</sup>       |No            |No                    |No       |No      |No <sup>4</sup>    |No |
|Compliance admin                    |Yes      |Yes         |Yes           |Yes                   |Yes      |Yes     |Yes        |Yes |
|Compliance Data Admin               |Yes      |Yes<sup>2</sup>      |Yes           |Yes                   |Yes      |Yes<sup>3</sup>  |Yes<sup>5</sup>     |No |
|Customer Lockbox access approver    |No       |No          |No            |No                    |No       |No      |No         |No |
|Exchange Admin                      |No       |No<sup>1</sup>       |No            |No                    |No       |No      |No<sup>4</sup>      |No |
|Global admin                    |Yes      |Yes         |Yes           |Yes                   |Yes      |Yes     |Yes        |Yes |
|Global reader                       |Yes      |Yes         |Yes           |Yes                   |No       |No      |Yes        |No |
|Helpdesk admin                      |No       |No<sup>1</sup>       |No            |No                    |No       |No      |No<sup>4</sup>      |No |
|Non-Admin User                      |No       |No          |No            |No                    |No       |No      |No         |No |
|Reports reader                      |No       |No          |No            |No                    |No       |No      |No         |No |
|Security admin                      |Yes      |Yes<sup>2</sup>      |No            |No                    |No       |No      |Yes<sup>5</sup>     |No |
|Security operator                   |Yes      |No          |No            |No                    |No       |No      |Yes<sup>5</sup>     |No |
|Security reader                     |Yes      |Yes<sup>2</sup>  |No            |No                    |No       |No      |Yes<sup>5</sup>     |No |
|Service support admin               |No       |No          |No            |No                    |No       |No      |No         |No |
|SharePoint admin                    |No       |No          |No            |No                    |No       |No      |No         |No |
|Teams service admin                 |No       |No          |No            |No                    |No       |No      |No         |No |
|User admin                          |No       |No          |No            |No                    |No       |No      |No         |No |

Exceptions:

<sup>1</sup> User will not be able generate report for IP apart from "Use IRM for Exchange Online" section.

<sup>2</sup> User will be able generate report for IP apart from "Use IRM for Exchange Online" section.

<sup>3</sup> User will be able generate report for IP apart from "Enable Communication Compliance in Microsoft 365" section.

<sup>4</sup> User will not be able generate report for IP apart from "Enable Auditing in Microsoft 365" section.

<sup>5</sup> User will be able generate report for IP apart from "Enable Auditing in Microsoft 365" section.

# Install Guide	

Step 1: Open PowerShell in administrator mode
    
Step 2: Install CAMP 
   
    Install-Module -Name CAMP

Step 3: Generate CAMP Report
  
    Use the following cmdlet to generate the CAMP report.
    Get-CAMPReport
    
   This will generate a report based on the geolocation of your tenant. If an error occurs while fetching your tenant’s geolocation, you will get a report covering all supported geolocations.
    
 You can learn more about this cmdlet by running the following.
    
    Get-Help Get-CAMPReport

  Input Parameters	
   You can also get a tailored report based on specific input parameters listed below.

   1.	Geolocation
         
     Get-CAMPReport -Geo @(1,7)
            This will generate a report based on the geolocations entered by you.You need to input appropriate numbers from the following list corresponding to the regions. 
            Input	Region
                1	Asia-Pacific
                2	Australia
                3	Canada
                4	Europe (excl. France) / Middle East / Africa
                5	France
                6	India
                7	Japan
                8	Korea
                9	North America (excl. Canada)
                10	South America
                11	South Africa
                12	Switzerland
                13	United Arab Emirates
                14	United Kingdom

    Note: As an add-on, the report will always include CAMP supported international sensitive information types like SWIFT Code, Credit Card Number etc.

   2.	Solutions
          
    Get-CAMPReport -Solution @(1,7)
          This will generate a report only for the solutions entered by you. You need to input appropriate numbers from the following list corresponding to the solution. 
            Input	Solution
                1	Data Loss Prevention
                2	Information Protection
                3	Data Lifecycle Management
                4	Records Management
                5	Communication Compliance
                6	Insider Risk Management
                7	Audit
                8	eDiscovery

   3. Multiple Parameters
            
          Get-CAMPReport -Solution @(1,7) -Geo @(9)
          
         This will generate a report only on for the solutions entered by you and based on the regions you have selected. 
  In either of the cases, there will be a prompt to enter your credentials. Once you enter your credentials, CAMP will run for a while and an HTML report will be generated.
 
  4. ExchangeEnvironmentName

        This will generate CAMP report for Security & Compliance PowerShell in a Microsoft 365 DoD organization or Microsoft GCC High organization

        O365USGovDoD
           This will generate CAMP report for Security & Compliance PowerShell in a Microsoft 365 DoD organization.

          Get-CAMPReport -ExchangeEnvironmentName O365USGovDoD

         O365USGovGCCHigh
           This will generate CAMP report for Security & Compliance PowerShell in a Microsoft GCC High organization.

           Get-CAMPReport -ExchangeEnvironmentName O365USGovGCCHigh
           
  5. TurnOffDataCollection

          Get-CAMPReport -TurnOffDataCollection
          
        If you wish to switch off data collection use this parameter.
        
# License
We use the following open source components in order to generate the report:
    •	Bootstrap, MIT License - https://getbootstrap.com/docs/4.0/about/license/
    •	Fontawesome, CC BY 4.0 License - https://fontawesome.com/license/free
    •	clipboard.js v1.5.3, MIT License - https://cdn.jsdelivr.net/clipboard.js/1.5.3/clipboard.min.js


## Frequently Asked Questions (FAQ)

### Will this tool make any changes to my existing settings, policies, etc.?

CAMP is a diagnostic tool that is "read-only". It fetches information
about your current configurations to generate a report but will not
alter any of your existing configurations.

### What different sections do I see in my report?

The report provides you with:

*   Solutions summary: It provides a break-down of statuses at a
    solution level. Each solution has counters that tell you how many
    recommendations are informational, require improvement and are OK.

*   Solution drill-down: Following solutions summary, each solution has
    a separate section that provides detailed information about
    configurations & their status.

    *   Each solution may have 1 or more improvement actions which will
        further be broken down into finer configurations. CAMP will
        provide you a status both at an improvement action level & also
        for finer configurations.

### Can I generate report for specific sections within the report?

Yes, you can generate report for specific sections within the report.
You can use the solution input parameter `--solution <input solution
number>` to generate the report for a specific solution from the
following list:

|Input  |Solution |
|-------|-------------------------- |
|1      |Data Loss Prevention |
|2      |Information Protection |
|3      |Data Lifecycle Management |
|4      |Records Management |
|5      |Communication Compliance |
|6      |Insider Risk Management |
|7      |Audit |
|8      |eDiscovery |

For e.g. If you wanted to create report for the DLP solution only then
you can run the following command:

```powershell
Get-CAMPReport --solution @(1)
```

You can learn more about this input parameter in the Input Parameters
section within the Install Guide above.

### What does Recommendation, Informational, Improvement & OK messages mean?

All recommendations provided by CAMP report are categorized in 3 types
of status:

*  Recommendations: These are best practices that your tenant
    should follow.\
    *Note: The support for these messages is limited in the current
    version so you may not see any recommendations in your report.*

*  Informational: These messages/statuses represent information
    in your current environment & are non-actionable in nature.

*  Improvement: These messages/statuses highlight areas that
    need your attention & are actionable. Sections which are marked as
    "Improvement" would generally have 1 or more configurations marked
    as "Improvement".

*  OK: These messages/statuses indicate that a given area is configured efficiently to meet data protection baselines.

### Why don't I see my tenant's name on the report?

Due to a technical error, the tool would not have been able to fetch
your tenant's name. In the event of such error, you may not see your
tenant name on the report. Please try running the tool again after some
time. If the issue persists, please reach out to us at
[CAMPhelp\@microsoft.com](mailto:CAMPhelp@microsoft.com) and/or contact
your Microsoft partner.

### Why do I see "No active policy defined" when I already have policies defined?

The policies created by you may be protecting a subset of information,
workloads, user groups and/or other criteria. "No active policy defined"
highlights the areas that are not protected by your current policies and
need an action on your part.

We provide "Remediation Scripts" which you can run from your PowerShell
console & the required policies will automatically be set up.

Please refer to "Remarks" section in your report to understand why you
are seeing "Improvement". If you still have concerns, please reach out
to us at [CAMPhelp\@microsoft.com](mailto:CAMPhelp@microsoft.com) or
contact your Microsoft partner.

### Why do I see "Policy defined but not protected on 1 or more workloads" when I already have policies defined?

Often there is a case where a given area (sensitive information,
workloads, user groups and/or other criteria) may be protected in 1 or
more policies in your environment but would not be protected across your
entire environment.

E.g. Your current policy configurations may U.S. / U.K. Passport Number
on SharePoint & Exchange but not on OneDrive & Teams. This puts you at
risk.

To avoid such cases, CAMP will highlight all the affected areas. You
will need to review these and either tweak your current policies and/or
create new ones to accommodate these areas.

### What are remediation scripts?

When CAMP identifies if your current policies have zero coverage for
certain sensitive information types, it provides you with "Remediation
Scripts" to help you avoid the hassle of manually setting up these
policies. These policies will be created in *Test* mode and you will
still have review & enable it manually.

You should review script parameters & then run these scripts from your *Windows PowerShell ISE* console or PowerShell terminal.
You would need to connect to [Security & Compliance PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps) or [Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps) to execute these scripts. On successful execution of the scripts, the
required policies will automatically be set up.

Note: These scripts are pre-configured and may need tweaking to achieve
best results for your organization. We are working on improving these
scripts in future versions of this tool.

### Why is the report asking me to protect Sensitive Information Types which I do not have in my environment?

This version of the tool aims to protect all possible sensitive
information types across multiple geographies and/or industries.

Future versions of this tool will provide recommendations to you based
on the nature of information you have in your environment.

### Can I generate the report to get recommendations for Sensitive Information Types applicable to my tenant's geographic regions?

Yes, you can generate the report for specific geographic regions.

By default, the tool will generate a report based on the geolocation for
your tenant. If you wish to run the report for specific geos then while
running the `Get-CAMPReport` cmdlet, you can input an extra parameter by
`--Geo` followed by 1 or more region numbers supported by CAMP.

Please refer the *Install Guide* section above for more detailed steps.

### How can I add my organization's Logo in the report?

You can quickly add your organization's logo in the report by replacing the image file present in the Image folder with your logo's image with same name and file extension (i.e. logo.jpg). Please note that your logo image should be able to accurately fit within the width of 250px and height of 150px respectively.

### How do I save my report?

Please use the "Print" button provided on top right corner of the report
to export a PDF (subject to your browser and/or system support for
printing as a PDF) or print a physical copy of your report.

#	This tool is awesome! How do I provide feedback and suggestions for future versions?
Please share your feedback & suggestions with us using this [form](https://forms.office.com/Pages/ResponsePage.aspx?id=v4j5cvGGr0GRqy180BHbR-ItstQd6pNMqw0W9LKA5vxUOFNGUFgxRDJFTkg3VE5NQTQwTUVVVDNVMi4u). We are dying to hear from you. :)

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Trademark

Trademarks This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft's Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
