# Inactive Enterprise Apps – Azure Automation Runbook

An Azure Automation Runbook that automatically identifies **self‑created Enterprise Apps (Service Principals)** that have had **no sign‑in activity for at least 30 days**, and sends a clean HTML report via email.

## Disclaimer

**Important Notice**  
This script was written **entirely without any AI assistance**.  
It is **fully hand‑crafted, production‑ready PowerShell**, designed based on real‑world experience with Microsoft Entra ID, Azure Automation, and Microsoft Graph.

Every line of logic, every API call, and every error‑handling mechanism was intentionally designed to ensure reliability, maintainability, and operational safety in enterprise environments.

---

## Overview

This Runbook solves a common operational and security challenge:  
**Which Enterprise Apps exist in the tenant but are no longer used?**

The script:

- Retrieves all Service Principals in the tenant  
- Filters for self‑created Enterprise Apps  
- Queries sign‑in logs from the last 30 days using the **Microsoft Graph Beta endpoint**  
- Identifies apps with zero activity  
- Generates a structured HTML report  
- Sends the report automatically via email  

Perfect for recurring audits, cleanup tasks, and security reviews.

---

## Features

- **Fully automated** – No manual review required  
- **Uses Beta Sign‑In API** – Supports `servicePrincipal` and `nonInteractiveUser` sign‑in types  
- **Accurate filtering** – Only apps created within the tenant are considered  
- **HTML reporting** – Clean table with DisplayName, AppId, and creation date  
- **Email notification** – Sends the report to a defined recipient  
- **Robust logging** – Every step is logged for transparency  
- **Scalable** – Works in tenants with thousands of Service Principals  

---

## Synopsis

This Runbook identifies **inactive Enterprise Apps** by loading all Service Principals, filtering for tenant‑owned applications, and evaluating their sign‑in activity over the last 30 days using the Microsoft Graph Beta sign‑in logs.  
Apps without activity are compiled into an HTML report and emailed to a designated recipient.  
Ideal for security audits, lifecycle management, and automated hygiene processes.

---

## Author

**Maurice Flöthmann**  
mo-cloud.de

**Contact:** [ask@mo-cloud.de](mailto:ask@mo-cloud.de)

---

## License

© 2026 Maurice Flöthmann

This script is provided **for private or internal company use only**.  
Redistribution, public sharing, or commercial use is **strictly prohibited** without explicit written permission.

For commercial use or publication requests, contact:  
**ask@mo-cloud.de**

---

## Prerequisites

### 1. Azure Automation Variables

| Variable Name      | Description                                   | Example |
|--------------------|-----------------------------------------------|---------|
| `RecipientEmail`   | Email address receiving the HTML report       | `recipient@company.com` |
| `SenderEmail`      | UPN of the mailbox used to send the report    | `sender@company.com` |

### 2. Required Permissions

The Runbook uses a **System‑Assigned Managed Identity** and requires:
- `Directory.Read.All`  
- `AuditLog.Read.All`
- `Application.Read.All`  
- `Mail.Send`  

### 3. Azure Automation Setup

- Runbook type: **PowerShell 5.1**  
- Enable Managed Identity  
- Assign Graph API permissions in Entra ID  

---

## How It Works (Detailed Flow)

1. **Load configuration**  
   Reads sender and recipient email addresses from Automation Variables.

2. **Authenticate**  
   Uses Managed Identity to obtain a Microsoft Graph access token.

3. **Load Service Principals**  
   Retrieves all Enterprise Apps via `/servicePrincipals`.

4. **Filter self‑created apps**  
   Only apps where `appOwnerOrganizationId` matches the tenant ID are included.

5. **Load sign‑ins from the last 30 days**  
   Uses the Beta endpoint `/auditLogs/signIns` with filters for relevant sign‑in types.

6. **Identify inactive apps**  
   Compares app IDs against sign‑in activity.

7. **Generate HTML report**  
   Builds a clean table with DisplayName, AppId, and creation date.

8. **Send email**  
   Sends the report using the Microsoft Graph `/sendMail` endpoint.

---

## Files in this Repository

- `README.md` – This documentation  
- `ReportUnusedEnterpriseApps.ps1` – The complete Runbook script  

---

## Installation Guide

1. Create a new **PowerShell 5.1 Runbook** in Azure Automation  
2. Paste the script into the Runbook  
3. Create the Automation Variables `RecipientEmail` and `SenderEmail`  
4. Enable the Managed Identity  
5. Assign the required Graph permissions  
6. Publish the Runbook  
7. (Optional) Create a schedule (e.g., weekly)  

---

## Example Email Notification

**Subject:**  
`Inactive Enterprise Apps Report (12)`

The HTML report includes:

- Total number of inactive apps  
- A table containing:
  - DisplayName  
  - AppId  
  - CreatedDateTime  
- Timestamp of the report  

---

## Logging

The Runbook logs:

- Start and completion markers  
- Number of Service Principals loaded  
- Number of self‑created apps  
- Number of apps with sign‑in activity  
- Number of inactive apps  
- Email delivery confirmation  

All logs are visible in the Azure Automation job output.

---

## Troubleshooting

- **No email received**  
  Ensure the sender mailbox exists and has permission to send mail.

- **403 when loading sign‑ins**  
  Missing `AuditLog.Read.All` permission.

- **Empty result list**  
  No self‑created apps exist in the tenant.

- **Managed Identity cannot authenticate**  
  Ensure the MI has Graph API permissions assigned.

---

## Why This Script Exists

Over time, tenants accumulate unused Enterprise Apps.  
These can pose security risks, clutter audits, and complicate lifecycle management.

This Runbook provides:

- Visibility  
- Automation  
- Security  
- Operational hygiene  

…while saving administrators significant time.

---

**Thank you for using this script.  
Created with dedication, caffeine, and genuine craftsmanship.**

---

*Last updated: May 2026*
