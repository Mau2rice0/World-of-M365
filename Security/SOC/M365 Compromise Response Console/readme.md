# M365 Compromise Response Console

A self-contained, cross-platform PowerShell tool with a built-in web GUI for rapid investigation and response to compromised Microsoft 365 accounts — a local SOC console that runs entirely on your machine.

## Disclaimer

**Important Notice**

This tool was designed, built and tested by **Maurice Flöthmann** based on real-world Microsoft 365 incident-response experience.

I place great value on genuine, maintainable, and production-ready code. Every collector, analysis routine, and response action has been carefully designed around a security-first architecture: the client secret never leaves the machine, the browser only ever talks to localhost, and every active intervention requires explicit confirmation.

---

## Overview

This tool solves a common challenge during a Microsoft 365 account compromise: getting a complete, correlated picture of what happened and being able to respond — **fast**, from a single pane of glass, without installing anything.

It runs a small local web server (built-in .NET `HttpListener`) and serves a modern SOC web GUI in your browser. You sign in with client credentials directly in the GUI; the secret stays server-side in RAM and is cleared on exit.

It automatically:

- Collects evidence across identity, data, communication, and security signals via Microsoft Graph
- Correlates everything into an auto-triage view, a graphical timeline, and a MITRE ATT&CK mapping
- Calculates a weighted risk score and surfaces the highest-value indicators first
- Enriches sign-in IPs with threat intel (Tor / anonymizer detection)
- Lets you contain the incident (revoke sessions, disable account, reset password, delete malicious inbox rules) — each gated by a confirmation
- Preserves a tamper-evident evidence snapshot (JSON + SHA256) and exports IOCs in multiple formats

## Features

- **Cross-platform**: Runs on macOS and Windows with PowerShell 7
- **Zero-install web GUI**: Single script serves the entire HTML/CSS/JS interface
- **Secret stays local**: Client secret held only in server-side RAM
- **Permission preflight**: Green/red matrix shows granted permissions before scanning
- **24 targeted probes** including devices, MFA, OAuth grants, mail rules, sign-ins, risk events, etc.
- **Live full scan** with progress bar and automatic correlation
- **Auto-triage**, MITRE ATT&CK mapping, impossible-travel detection and visual dashboard
- **Containment actions** with explicit confirmation and rollback option
- **Evidence preservation** and multiple export formats (CSV, JSON, STIX, MISP, Markdown, PDF)

## Author

**Maurice Flöthmann**  
[mo-cloud.de](https://mo-cloud.de)

**Questions or support requests:** [ask-maurice@mo-cloud.de](mailto:ask-maurice@mo-cloud.de)

## License

© 2026 Maurice Flöthmann

This tool is provided **for personal and internal company use only**.  
Redistribution, public sharing, or commercial use (including modification for resale or SaaS products) is **strictly prohibited** without explicit written permission from the author.

If you wish to use this tool in a commercial context or share it publicly, please contact me at **ask-maurice@mo-cloud.de**.

---

## Prerequisites

### 1. Runtime

- PowerShell 7.0 or higher (Windows, macOS, Linux)
- Modern web browser
- Outbound HTTPS access to Microsoft Graph (the GUI binds to localhost only)

### 2. Enterprise App Registration Setup

1. Go to the [Microsoft Entra Admin Center](https://entra.microsoft.com)
2. Navigate to **Applications** → **App registrations** → **New registration**
3. Enter a name (e.g. `M365 Compromise Response Console`)
4. Select **Accounts in this organizational directory only**
5. Click **Register**
6. Go to **API permissions** → **Add a permission** → **Microsoft Graph**
7. Select **Application permissions** and add the following:

   **Required Read Permissions:**
   - `User.Read.All`
   - `Directory.Read.All`
   - `AuditLog.Read.All`
   - `Mail.Read`
   - `MailboxSettings.Read`
   - `Files.Read.All`
   - `Sites.Read.All`
   - `Device.Read.All`
   - `DeviceManagementManagedDevices.Read.All`
   - `UserAuthenticationMethod.Read.All`
   - `Chat.Read.All`
   - `IdentityRiskyUser.Read.All`
   - `IdentityRiskEvent.Read.All`
   - `Policy.Read.All`
   - `SecurityAlert.Read.All`

   **Optional Containment Permissions:**
   - `User.ReadWrite.All`
   - `MailboxSettings.ReadWrite`

8. Click **Grant admin consent** for your tenant
9. Go to **Certificates & secrets** → **New client secret**, create a secret and copy it immediately

> **Note:** Keep your **Tenant ID**, **Client ID** (Application ID) and **Client Secret** ready. They are entered only in the GUI at runtime and are never stored in the script.

## Usage

1. Download the script
2. Run it with PowerShell 7
3. The web GUI will open automatically in your browser (`http://localhost:8723`)

The tool binds exclusively to localhost and clears all credentials when you stop it.

## How It Works (Detailed Flow)

1. Local web server starts
2. Sign in with Tenant ID, Client ID and Client Secret via the browser
3. Permission preflight check (green/red matrix)
4. Enter the affected user and time range
5. Full evidence collection via Microsoft Graph
6. Automatic analysis, risk scoring, timeline & MITRE ATT&CK mapping
7. Optional containment actions with explicit confirmation
8. Evidence snapshot and export

## Security Notes

- The client secret **never** leaves your machine
- The web server binds exclusively to localhost
- Every active response action requires explicit confirmation
- All credentials are cleared when the tool is closed

---

**Thank you for using this tool. Created with care by Maurice Flöthmann**

---

*Last updated: June 2026*