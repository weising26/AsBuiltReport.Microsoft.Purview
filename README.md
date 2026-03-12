# AsBuiltReport.Microsoft.Purview

A PowerShell module for the [AsBuiltReport](https://github.com/AsBuiltReport/AsBuiltReport) framework that documents Microsoft Purview compliance configuration as Word, HTML, or Text reports.

---

## Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Import](#import)
- [Configuration](#configuration)
- [Running the Report](#running-the-report)
- [InfoLevel and Report Modes](#infolevel-and-report-modes)
- [Health Check Color Coding](#health-check-color-coding)
- [Covered Sections](#covered-sections)
- [File Structure](#file-structure)

---

## Prerequisites

### PowerShell Version

PowerShell 5.1 or above is required.

### Required Modules

Install these before running the report for the first time:

```powershell
Install-Module AsBuiltReport.Core       -MinimumVersion 1.4.0 -Force
Install-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -Force
Install-Module Microsoft.Graph          -MinimumVersion 2.0.0 -Force
```

> **Optional:** `AIPService` module — required to report AIP Unified Labeling migration status in the Information Protection coverage summary. If not installed, that field shows `Unknown` and report generation continues normally.
>
> ```powershell
> Install-Module AIPService -Force
> ```

### Microsoft 365 Subscription

| License | Sections Available |
|---|---|
| Microsoft 365 E3 | Information Protection, DLP, Retention, Records Management, Audit, Core eDiscovery |
| Microsoft 365 E5 or E5 Compliance add-on | All sections including Insider Risk Management, Communication Compliance, Advanced eDiscovery, Auto-Labeling |

The report generates for E3 tenants but E5-only sections will show no data. A pre-flight license check runs at startup and prints the detected tier to the console.

### Required User Role

The following table shows which Microsoft 365 admin roles provide access to each report section. The report performs a role check at startup and prints warnings to the console when permissions are insufficient for any section.

| User Role | DLP | IP | IG | RM | IRM | CC | Audit | eDiscovery |
|---|---|---|---|---|---|---|---|---|
| Azure Information Protection admin | No | No ¹ | No | No | No | No | No ⁴ | No |
| **Compliance Administrator** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |
| Compliance Data Administrator | Yes | Yes ² | Yes | Yes | Yes | Yes ³ | Yes ⁵ | No |
| Customer Lockbox access approver | No | No | No | No | No | No | No | No |
| Exchange Administrator | No | No ¹ | No | No | No | No | No ⁴ | No |
| **Global Administrator** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |
| Global Reader | Yes | Yes | Yes | Yes | No | No | Yes | No |
| Helpdesk Administrator | No | No ¹ | No | No | No | No | No ⁴ | No |
| Non-Admin User | No | No | No | No | No | No | No | No |
| Reports Reader | No | No | No | No | No | No | No | No |
| Security Administrator | Yes | Yes ² | No | No | No | No | Yes ⁵ | No |
| Security Operator | Yes | No | No | No | No | No | Yes ⁵ | No |
| Security Reader | Yes | Yes ² | No | No | No | No | Yes ⁵ | No |
| Service Support Administrator | No | No | No | No | No | No | No | No |
| SharePoint Administrator | No | No | No | No | No | No | No | No |
| Teams Service Administrator | No | No | No | No | No | No | No | No |
| User Administrator | No | No | No | No | No | No | No | No |

**Column key:** DLP = Data Loss Prevention · IP = Information Protection · IG = Information Governance (Retention) · RM = Records Management · IRM = Insider Risk Management · CC = Communication Compliance

**Exceptions:**

1. User cannot generate the IP section except for the "IRM for Exchange Online" subsection.
2. User can generate the IP section except for the "IRM for Exchange Online" subsection.
3. User can generate the CC section except for the "Enable Communication Compliance" subsection.
4. User cannot generate the Audit section except for the "Enable Auditing in Office 365" subsection.
5. User can generate the Audit section except for the "Enable Auditing in Office 365" subsection.

> **Recommendation:** Run the report as **Compliance Administrator** or **Global Administrator** for full coverage of all sections.

---

## Installation

### Step 1 — Extract the zip

Extract `AsBuiltReport_Microsoft_Purview.zip` to a local folder. The folder must be named exactly `AsBuiltReport.Microsoft.Purview`.

### Step 2 — Run Install.ps1

Open PowerShell and run:

```powershell
cd C:\Path\To\AsBuiltReport.Microsoft.Purview
.\Install.ps1
```

`Install.ps1` auto-detects the correct destination from `$env:PSModulePath`, copies the module files, validates the manifest, and upgrades any existing installation in-place. To specify a custom destination:

```powershell
.\Install.ps1 -Destination 'C:\MyModules'
```

### Step 3 — Verify

```powershell
Get-Module -ListAvailable AsBuiltReport.Microsoft.Purview
```

You should see the module listed with its version number.

---

## Import

After installation, import the module and its dependencies in the same PowerShell session:

```powershell
Import-Module AsBuiltReport.Core
Import-Module ExchangeOnlineManagement
Import-Module Microsoft.Graph
Import-Module AsBuiltReport.Microsoft.Purview
```

Verify all modules loaded:

```powershell
Get-Module AsBuiltReport.Core, ExchangeOnlineManagement, Microsoft.Graph, AsBuiltReport.Microsoft.Purview |
    Select-Object Name, Version
```

---

## Configuration

Edit `AsBuiltReport.Microsoft.Purview.json` before running. At minimum, set your admin UPN:

```json
{
  "Options": {
    "UserPrincipalName": "admin@yourtenant.onmicrosoft.com",
    "ReportType": "Both",
    "KeepConnected": true,
    "TranscriptPath": "C:\\Reports\\Purview_Transcript.log"
  },
  "InfoLevel": {
    "InformationProtection": 3,
    "DLP": 3,
    "Retention": 3,
    "RecordManagement": 3,
    "EDiscovery": 3,
    "Audit": 3,
    "InsiderRisk": 3,
    "CommunicationCompliance": 3,
    "ComplianceManager": 3
  },
  "HealthCheck": {
    "Purview": {
      "DLP": true,
      "InformationProtection": true,
      "Retention": true,
      "RecordManagement": true,
      "EDiscovery": true,
      "Audit": true,
      "InsiderRisk": true,
      "CommunicationCompliance": true,
      "ComplianceManager": true,
      "ACSC": true
    }
  }
}
```

### Options reference

| Option | Description |
|---|---|
| `UserPrincipalName` | UPN of the admin account (e.g. `admin@tenant.onmicrosoft.com`) |
| `ReportType` | `AsBuilt` = documentation only · `Assessment` = POA only · `Both` = full report |
| `KeepConnected` | `true` = reuse an existing IPPS/Graph session if already connected |
| `TranscriptPath` | Full path for the structured log file. Omit or leave blank to disable |

### InfoLevel reference

| Value | Behaviour |
|---|---|
| `0` | Section disabled — not collected or shown |
| `1` | Summary tables only |
| `2` | Summary tables + full per-item detail sections |
| `3` | All of the above + ACSC ISM / Essential Eight compliance checks + DLP category gap analysis |

---

## Running the Report

### Interactive login (MFA)

```powershell
New-AsBuiltReport -Report Microsoft.Purview `
    -Target 'yourtenant.onmicrosoft.com' `
    -OutputFolderPath 'C:\Reports' `
    -ReportConfigFilePath '.\AsBuiltReport.Microsoft.Purview.json' `
    -OutputFormat Word, HTML `
    -EnableHealthCheck
```

### Saved credentials (non-MFA / service account)

```powershell
$Cred = Get-Credential

New-AsBuiltReport -Report Microsoft.Purview `
    -Target 'yourtenant.onmicrosoft.com' `
    -Credential $Cred `
    -OutputFolderPath 'C:\Reports' `
    -ReportConfigFilePath '.\AsBuiltReport.Microsoft.Purview.json' `
    -OutputFormat Word, HTML `
    -EnableHealthCheck
```

### What happens at runtime

1. Connects to Security & Compliance PowerShell (`Connect-IPPSSession`) and Microsoft Graph (`Connect-MgGraph`)
2. Runs a **pre-flight check** — detects your Entra admin roles and M365 license tier, printing results and any warnings to the console
3. Collects data from each enabled section
4. Generates the report file(s) in `OutputFolderPath`

The report typically takes 2–5 minutes depending on the number of policies in the tenant.

---

## InfoLevel and Report Modes

### ReportType: AsBuilt

Standard documentation covering all configured Purview workloads, in this order:

1. **Information Protection** — Sensitivity Labels, Label Policies, Auto-Labeling, IRM, DLP Policies
2. **Data Lifecycle Management** — Retention Policies & Labels, Mailbox Archiving, Exchange MRM, Records Management
3. **eDiscovery** — Cases, Holds, Content Searches, Advanced eDiscovery details
4. **Audit** — Log Configuration, Retention Policies
5. **Risk and Compliance** — Insider Risk, Communication Compliance, Compliance Posture (Secure Score)
6. **Purview Optimization Assessment (POA)**

### ReportType: Assessment

Generates only the **Purview Optimization Assessment (POA)** — a scored compliance posture report across 65 controls in 9 workload areas. Useful for periodic health checks without the full documentation output.

### ReportType: Both

Generates both the AsBuilt documentation and the POA assessment in a single run.

---

## Health Check Color Coding

Applies when `-EnableHealthCheck` is passed to `New-AsBuiltReport`.

| Colour | Meaning |
|---|---|
| 🔴 **Red (Critical)** | Feature disabled, not configured, or missing — immediate action recommended |
| 🟡 **Yellow (Warning)** | Feature in test/simulation mode, scoped too narrowly, or partially implemented |
| ⬜ No colour | Meets recommended configuration |

---

## Covered Sections

| Section | Key Cmdlets / APIs | InfoLevel Key |
|---|---|---|
| Sensitivity Labels | `Get-Label` | `InformationProtection` |
| Sensitivity Label Policies | `Get-LabelPolicy` | `InformationProtection` |
| Auto-Labeling Policies | `Get-AutoSensitivityLabelPolicy` | `InformationProtection` |
| IRM Configuration (Exchange Online) | `Get-IRMConfiguration` | `InformationProtection` |
| DLP Policies & Rules | `Get-DlpCompliancePolicy`, `Get-DlpComplianceRule` | `DLP` |
| DLP Category Gap Analysis *(InfoLevel 3)* | `DLPImprovementActions.xml` + live policies | `DLP` |
| Retention Policies & Rules | `Get-RetentionCompliancePolicy`, `Get-RetentionComplianceRule` | `Retention` |
| Retention Labels | `Get-ComplianceTag` | `Retention` |
| Mailbox Archiving | `Get-EXOMailbox` | `Retention` |
| Exchange MRM Policies | `Get-RetentionPolicy`, `Get-RetentionPolicyTag` | `Retention` |
| Records Management Labels | `Get-ComplianceTag` (record/regulatory only) | `RecordManagement` |
| eDiscovery Cases & Holds | `Get-ComplianceCase`, `Get-CaseHoldPolicy` | `EDiscovery` |
| Content Searches | `Get-ComplianceSearch` | `EDiscovery` |
| Advanced eDiscovery Case Details | `Get-ComplianceCaseMember` | `EDiscovery` |
| Audit Log Configuration | `Get-AdminAuditLogConfig` | `Audit` |
| Audit Retention Policies | `Get-UnifiedAuditLogRetentionPolicy` | `Audit` |
| Insider Risk Policies | `Get-InsiderRiskPolicy` | `InsiderRisk` |
| Communication Compliance Policies & Rules | `Get-SupervisoryReviewPolicyV2` | `CommunicationCompliance` |
| Compliance Posture (Microsoft Secure Score) | Graph `v1.0/security/secureScores` | `ComplianceManager` |
| Purview Optimization Assessment (POA) | All of the above | All |

---

## File Structure

```
AsBuiltReport.Microsoft.Purview/
├── AsBuiltReport.Microsoft.Purview.json       # Report config (InfoLevel, HealthCheck, Options)
├── AsBuiltReport.Microsoft.Purview.psd1       # Module manifest
├── AsBuiltReport.Microsoft.Purview.psm1       # Module loader
├── AsBuiltReport.json                         # AsBuiltReport framework metadata
├── Install.ps1                                # One-click installer
├── README.md
└── Src/
    ├── Public/
    │   ├── Invoke-AsBuiltReport.Microsoft.Purview.ps1   # Main entry point
    │   └── AsBuiltReport.Microsoft.Purview.png          # Cover page logo
    └── Private/
        ├── Connect-PurviewSession.ps1                   # Auth / session management
        ├── Helpers.ps1                                  # Shared utility functions
        ├── Get-AbrPurviewSections.ps1                   # Section orchestrators
        ├── Get-AbrPurviewSensitivityLabel.ps1
        ├── Get-AbrPurviewDLPPolicy.ps1
        ├── Get-AbrPurviewRetentionPolicy.ps1
        ├── Get-AbrPurviewRecordManagement.ps1
        ├── Get-AbrPurviewEDiscovery.ps1
        ├── Get-AbrPurviewAuditPolicy.ps1
        ├── Get-AbrPurviewInsiderRisk.ps1
        ├── Get-AbrPurviewCommunicationCompliance.ps1
        ├── Get-AbrPurviewComplianceManager.ps1
        ├── Get-AbrPurviewAssessment.ps1
        └── Data/
            └── DLPImprovementActions.xml                # MCCA DLP category definitions
```
