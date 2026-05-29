# ComplianceHub — Intune Compliance Dashboard

A lightweight, offline-capable compliance monitoring dashboard for Microsoft Intune.  
**Made by K K Shal** — All rights reserved.

---

## How It Works

1. **`Get-IntuneData.ps1`** — PowerShell script that authenticates to Microsoft Graph API using OAuth2 client credentials, fetches all Intune data (devices, policies, apps, update rings, etc.), and writes it to `data.json`.
2. **`index.html`** — Open this in any modern browser. It loads `data.json` (via auto-detect, drag & drop, or file picker) and renders a full dashboard — **no backend server needed**.
3. **`Invoke-IntuneVisibilityToolkit.ps1`** *(optional)* — Runs 5 advanced analysis modules (policy conflicts, security audit, compliance reality check, app diagnostics, patch audit) and outputs `visibility.json` for the Visibility tab.

---

## Prerequisites

- A Microsoft 365 tenant with **Intune** licenses
- Azure AD app registration with `DeviceManagement.Read.All` permission
- PowerShell 5.1+ (built into Windows)
- Modern browser (Edge, Chrome, Firefox)

---

## Step 1: Azure AD App Registration

1. Go to [Azure Portal](https://portal.azure.com) → **Azure Active Directory** → **App registrations**
2. Click **New registration**, name it (e.g. `IntuneDashboard`), choose *Accounts in this organizational directory only*
3. Copy the **Application (Client) ID** and **Directory (Tenant) ID**
4. Go to **Certificates & secrets** → **New client secret**, copy the value
5. Go to **API permissions** → **Add permission** → **Microsoft Graph** → **Application permissions** → add `DeviceManagement.Read.All`
6. Click **Grant admin consent**

## Step 2: Run the Data Collector

```powershell
.\Get-IntuneData.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-secret"
```

This fetches devices, policies, configs, apps, update rings, and autopilot data — then writes `data.json`.

## Step 3: Open the Dashboard

Double-click **`index.html`** in any browser.  
The dashboard auto-detects `data.json` in the same folder. You can also drag & drop any `data.json` onto the page.

## Step 4: Visibility Toolkit (Optional)

```powershell
.\Invoke-IntuneVisibilityToolkit.ps1 -TenantId "x" -ClientId "y" -ClientSecret "z"
```

Drag the generated `visibility.json` into the **Visibility** tab for:
- Policy conflict detection
- Security anomaly audit
- Compliance reality check (stale/orphaned devices)
- App failure diagnostics
- Third-party patch audit

---

## Dashboard Tabs

| Tab | What It Shows |
|-----|--------------|
| **Overview** | KPIs, OS breakdown, co-management status, executive summary |
| **Compliance** | Policy status breakdown, compliance reasons chart, per-policy table |
| **Devices** | Searchable device table with compliance, OS, risk, and encryption filters |
| **Apps** | App inventory with search, filter by platform/publisher |
| **Updates** | Update ring deployment status |
| **Policies** | All compliance policies with details |
| **Security** | Risk levels, encryption status, health scripts, device anomalies |
| **Reports** | Enrollment trends, OS version/manufacturer charts |
| **Visibility** | *(requires visibility.json)* Health score, conflicts, anomalies, recommendations |

---

## Scheduling (Optional)

Use Windows Task Scheduler to run `Get-IntuneData.ps1` daily:
- **Program:** `powershell.exe`
- **Arguments:** `-ExecutionPolicy Bypass -File "C:\path\to\Get-IntuneData.ps1" -TenantId "..." -ClientId "..." -ClientSecret "..."`

Users open the same `index.html` from a shared drive — always seeing fresh data.

---

---

## Top Intune Admin Challenges (2026)

1. **CORS & Graph API Limitations** — Intune data can't be queried directly from browsers; server-side PowerShell is required. ComplianceHub solves this with its offline JSON workflow.
2. **Multi Admin Approval (MAA)** — Post-March 2026 breach, Microsoft requires MAA for wipe/retire/delete, RBAC changes, and compliance/config policies. Many orgs haven't configured it.
3. **MAM SDK Enforcement** — Since Jan 2026, Intune blocks older iOS/Android wrapped apps, causing helpdesk spikes when Outlook/Teams refuse to launch.
4. **Policy Conflicts** — Overlapping compliance and config policies with contradictory settings silently break device behavior.
5. **Compliance ≠ Security** — Compliance policies check state but don't enforce it. Devices show "compliant" with disabled firewalls and local admin rights.
6. **Stale & Orphaned Devices** — Devices not syncing for 90+ days or showing false-green compliance are easily missed without dedicated tooling.
7. **RBAC Complexity** — Too much standing privilege, no scope tags, no PIM for Intune roles. Least-privilege is hard to maintain manually.
8. **Configuration Drift** — Policies get outdated, devices slip through cracks, visibility erodes without continuous monitoring.

ComplianceHub directly addresses challenges **#1**, **#4**, **#5**, **#6**, and **#8**.

---

## License

This project is provided for internal use.  
**Made by K K Shal** — All rights reserved.
