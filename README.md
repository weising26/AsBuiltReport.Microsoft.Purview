# AsBuiltReport.Microsoft.Purview

An AsBuiltReport module for documenting Microsoft Purview compliance configuration
in Word, HTML, or Text format.

---

## Covered Sections

| Section | Cmdlet Source | InfoLevel Key |
|---|---|---|
| Sensitivity Labels & Policies | `Get-Label`, `Get-LabelPolicy` | `InformationProtection` |
| DLP Policies & Rules | `Get-DlpCompliancePolicy`, `Get-DlpComplianceRule` | `DLP` |
| Retention Policies, Rules & Labels | `Get-RetentionCompliancePolicy`, `Get-ComplianceTag` | `Retention` |
| Records Management Labels | `Get-ComplianceTag` (record/regulatory labels) | `RecordManagement` |
| eDiscovery Cases, Holds & Content Searches | `Get-ComplianceCase`, `Get-CaseHoldPolicy`, `Get-ComplianceSearch` | `EDiscovery` |
| Audit Log Config & Retention Policies | `Get-AdminAuditLogConfig`, `Get-UnifiedAuditLogRetentionPolicy` | `Audit` |
| Insider Risk Policies & Settings | Graph API `/beta/security/insiderRiskPolicies` | `InsiderRisk` |
| Communication Compliance Policies & Rules | `Get-SupervisoryReviewPolicyV2`, `Get-SupervisoryReviewRule` | `CommunicationCompliance` |
| Compliance Manager Assessments & Actions | Graph API `/beta/compliance/complianceManager/assessments` | `ComplianceManager` |

---

## Prerequisites

| Module | Minimum Version | Install |
|---|---|---|
| `AsBuiltReport.Core` | 1.4.0 | `Install-Module AsBuiltReport.Core` |
| `ExchangeOnlineManagement` | 3.0.0 | `Install-Module ExchangeOnlineManagement` |
| `Microsoft.Graph` | 2.0.0 | `Install-Module Microsoft.Graph` |

### Required Permissions

The account used must hold the following roles:

- **Compliance Administrator** (Purview portal) — required for all Exchange Online compliance cmdlets
- **Global Reader** (Microsoft 365 admin center) — required for Graph API read access
- Or equivalent custom roles with read access to each workload

---

## Installation

### Option A — Standard install (from zip)

Run `Install.ps1` once after extracting. It auto-detects the right destination from `$env:PSModulePath`:

```powershell
.\Install.ps1
```

The script will find the best destination (upgrades in-place if already installed, otherwise picks your CurrentUser modules folder), copy the files, validate the manifest, and warn you if the destination isn't in `$env:PSModulePath`.

Override the destination explicitly if needed:

```powershell
.\Install.ps1 -Destination 'C:\MyModules'
```

---

### Option B — Dev layout (no copy needed)

If working from a local checkout alongside a dev build of `AsBuiltReport.Core`, add both parent folders to `$env:PSModulePath`. PowerShell finds modules directly without copying.

```powershell
# Add to your session (or put in $PROFILE to persist)
$env:PSModulePath = @(
    "$env:USERPROFILE\Documents\PowerShell\Modules"
    "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
    "C:\Program Files\PowerShell\Modules"
    "C:\Program Files\WindowsPowerShell\Modules"
    "C:\Program Files\PowerShell\7\Modules"
    "C:\Path\To\AsBuiltReport.Core-dev"   # parent folder containing AsBuiltReport.Core-dev\
    "C:\Path\To\AsBuilt"                  # parent folder containing AsBuiltReport.Microsoft.Purview\
) -join ';'
```

> **Layout requirement:** each path must be the *parent* of the module folder, not the module folder itself, and the module folder must be named exactly `AsBuiltReport.Microsoft.Purview`.

Verify both modules are discoverable before running:

```powershell
Get-Module -ListAvailable AsBuiltReport.Core
Get-Module -ListAvailable AsBuiltReport.Microsoft.Purview
```

---

## Usage

### 1. Install prerequisite modules (first time only)

```powershell
Install-Module AsBuiltReport.Core          -Force
Install-Module ExchangeOnlineManagement    -Force
Install-Module Microsoft.Graph             -Force
```

### 2. Configure the report

Edit `AsBuiltReport.Microsoft.Purview.json` — at minimum set your UPN:

```json
"Options": {
    "UserPrincipalName": "admin@yourtenant.onmicrosoft.com",
    "ReportType": "Both"
}
```

`InfoLevel` controls what appears in each section — `0` = disabled, `1` = summary, `2` = full detail, `3` = full detail + triggers the ACSC ISM / Essential Eight compliance summary. Setting **any** key to `3` appends the ACSC section after all AsBuilt content.

### 3. Generate the report

```powershell
# Interactive / MFA login
New-AsBuiltReport -Report Microsoft.Purview `
    -Target 'contoso.onmicrosoft.com' `
    -OutputFolderPath 'C:\Reports' `
    -ReportConfigFilePath '.\AsBuiltReport.Microsoft.Purview.json' `
    -OutputFormat Word, HTML `
    -EnableHealthCheck

# With saved credentials (non-MFA / service account)
$Cred = Get-Credential
New-AsBuiltReport -Report Microsoft.Purview `
    -Target 'contoso.onmicrosoft.com' `
    -Credential $Cred `
    -OutputFolderPath 'C:\Reports' `
    -ReportConfigFilePath '.\AsBuiltReport.Microsoft.Purview.json' `
    -OutputFormat Word, HTML `
    -EnableHealthCheck
```

---

## Health Check Color Coding

| Color | Meaning |
|---|---|
| 🔴 Red (Critical) | Feature disabled or misconfigured — immediate action recommended |
| 🟡 Yellow (Warning) | Feature in audit/test mode only, or review recommended |
| 🟢 Green (Advisory) | No issues found |

---

## File Structure

```
AsBuiltReport.Microsoft.Purview/
├── AsBuiltReport.Microsoft.Purview.json       # Default report config (InfoLevel, HealthCheck, Options)
├── AsBuiltReport.Microsoft.Purview.psd1       # Module manifest
├── AsBuiltReport.Microsoft.Purview.psm1       # Module loader (dot-sources Src/)
├── AsBuiltReport.json                         # AsBuiltReport framework config (author, company, email)
├── Install.ps1                                # One-click installer / dev-path aware
├── README.md
└── Src/
    ├── Public/
    │   ├── Invoke-AsBuiltReport.Microsoft.Purview.ps1   # Main entry point
    │   └── AsBuiltReport.Microsoft.Purview.png          # Cover page logo
    └── Private/
        ├── Connect-PurviewSession.ps1                   # Auth / session management
        ├── Helpers.ps1                                  # Utility functions
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
        └── Get-AbrPurviewAssessment.ps1                 # POA assessment report
```
