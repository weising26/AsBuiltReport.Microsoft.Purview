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

## Usage

### 1. Install AsBuiltReport

```powershell
Install-Module AsBuiltReport
```

### 2. Create a report configuration file (first run)

```powershell
New-AsBuiltReportConfig -Report Microsoft.Purview -FolderPath 'C:\Reports'
```

Edit `AsBuiltReport.Microsoft.Purview.json` to enable/disable sections via `InfoLevel`:
- `0` = Disabled (section skipped entirely)
- `1` = Summary
- `2` = Detailed

### 3. Generate the report

```powershell
# Interactive / MFA login
New-AsBuiltReport -Report Microsoft.Purview `
    -Target 'contoso.onmicrosoft.com' `
    -OutputFolderPath 'C:\Reports' `
    -OutputFormat Word, HTML `
    -EnableHealthCheck

# With saved credentials (service principal / non-MFA account)
$Cred = Get-Credential
New-AsBuiltReport -Report Microsoft.Purview `
    -Target 'contoso.onmicrosoft.com' `
    -Credential $Cred `
    -OutputFolderPath 'C:\Reports' `
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
├── AsBuiltReport.Microsoft.Purview.json       # Default report config
├── Src/
│   ├── Public/
│   │   └── Invoke-AsBuiltReport.Microsoft.Purview.ps1   # Main entry point
│   └── Private/
│       ├── Get-AbrPurviewSections.ps1                   # Section orchestrators
│       ├── Get-AbrPurviewDLPPolicy.ps1
│       ├── Get-AbrPurviewSensitivityLabel.ps1
│       ├── Get-AbrPurviewRetentionPolicy.ps1
│       ├── Get-AbrPurviewEDiscovery.ps1
│       ├── Get-AbrPurviewAuditPolicy.ps1
│       ├── Get-AbrPurviewInsiderRisk.ps1
│       ├── Get-AbrPurviewCommunicationCompliance.ps1
│       └── Get-AbrPurviewComplianceManager.ps1
└── README.md
```
