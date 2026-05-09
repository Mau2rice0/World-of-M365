# Microsoft 365 Service Health Monitor

**An Azure Automation Runbook that monitors Microsoft 365 service health and sends professional HTML reports only when issues are detected.**

## Disclaimer

**Important Notice**  
This entire script was written **without any AI assistance**. It is 100% hand-crafted, real-world PowerShell code developed and tested by Maurice Flöthmann.  

I place great value on genuine, maintainable, and production-ready code. Every function, logic flow, error handling, and HTML design has been carefully crafted based on real-world experience with Microsoft Graph, Azure Automation, and Microsoft 365 operations.

---

## Overview

This Runbook solves a common challenge for Microsoft 365 administrators: staying informed about service degradations and outages without being flooded with unnecessary notifications.

It automatically:
- Checks the current health status of all Microsoft 365 services
- Detects degradations and interruptions
- Sends a detailed, well-formatted HTML report **only when issues exist**
- Includes recent Message Center announcements
- Remains completely silent when everything is operational

---

## Features

- **Issue-only alerting**: No email is sent if all services are healthy
- **Rich HTML reports**: Clean, professional design with color-coded status
- **Message Center integration**: Shows relevant announcements from the last 7 days
- **Secure authentication**: Uses System-assigned Managed Identity (no secrets)
- **Robust decision logic**: Early exit when no action is required
- **Detailed logging**: Every step is clearly documented
- **Production ready**: Designed for scheduled execution in Azure Automation
- **Zero spam philosophy**: Only real problems trigger notifications

---

## Author

**Maurice Flöthmann**  
mo-cloud.de  

**Questions or support requests:** [ask@mo-cloud.de](mailto:ask@mo-cloud.de)

---

## License

© 2026 Maurice Flöthmann  

This script is provided **for personal and internal company use only**.  
Redistribution, public sharing, or commercial use (including modification for resale or SaaS products) is **strictly prohibited** without explicit written permission from the author.  

If you wish to use this script in a commercial context or share it publicly, please contact me at **ask@mo-cloud.de**.

---

## Prerequisites

### 1. Azure Automation Variables

| Variable Name      | Description                                      | Example |
|--------------------|--------------------------------------------------|---------|
| `RecipientEmail`   | Email address that receives the alert            | `recipient@company.com` |
| `SenderEmail`      | Sender mailbox (must be licensed)                | `servicehealth@company.com` |

### 2. Microsoft Graph API Permissions

- `ServiceHealth.Read.All`
- `ServiceMessage.Read.All`
- `Mail.Send`

### 3. Azure Automation Account Setup

- System-assigned Managed Identity enabled
- Grant the above Graph permissions to the Managed Identity (admin consent required)

---

## How It Works (Detailed Flow)

1. **Configuration** – Loads `RecipientEmail` and `SenderEmail` from Automation Variables
2. **Authentication** – Connects using System-assigned Managed Identity and acquires Graph token
3. **Service Health Check** – Queries all service health overviews including active issues
4. **Decision Point** – If no services are degraded or interrupted → silent exit
5. **Message Center** – Retrieves announcements from the last 7 days
6. **HTML Report** – Builds a professional, responsive HTML email
7. **Email Delivery** – Sends the report via Microsoft Graph
8. **Completion** – Logs success and ends

---

## Files in this Repository

- `README.md` – This documentation file
- `ServiceHealthNotificationService.ps1` – The main PowerShell Runbook script

---

## Installation Guide

1. Create a new **PowerShell 5.1** (or 7.2) Runbook in Azure Automation
2. Copy the entire content of the script into the runbook
3. Create the two Automation Variables (`RecipientEmail` and `SenderEmail`)
4. Enable System-assigned Managed Identity and grant the required Graph permissions
5. Save and **Publish** the runbook
6. Create a schedule (recommended: every Hour)

---

## Example Email Notification

**Subject:**
`Microsoft 365 Service Issues (2 services affected) - 08.05.2026`

The email contains:
- Clear summary with number of affected services
- Color-coded table of impacted services (red = Interruption, orange = Degradation)
- Recent Message Center announcements
- Professional styling with company-friendly design

---

## Logging

The runbook produces clear, timestamped logs including:

- Runbook start and completion
- Number of services with issues
- Warning level when problems are detected
- Success confirmation after email delivery

All logs are visible in the Azure Automation job history.

---

## Troubleshooting

Common issues and solutions:

- **No email received**: Verify `SenderEmail` has a valid mailbox and `Mail.Send` permission is granted.
- **Authentication errors**: Ensure the Managed Identity has the correct Graph permissions.
- **No issues detected**: This is expected behavior – the runbook stays silent.
- **HTML looks broken**: The email is fully self-contained and tested in Outlook and web clients.

If you encounter any problems, please send the full job output to **ask@mo-cloud.de**.

---

## Why This Script Exists

Constantly checking the Microsoft 365 Service Health page or receiving too many alerts is inefficient.  
This runbook brings quiet reliability: you only hear from it when something is actually wrong.

**Main goal:** Stay informed about Microsoft 365 service issues at all times — even without having to log into the Microsoft 365 Admin Portal.

---

**Thank you for using this script. Created with care (and many late evenings) by Maurice Flöthmann**  
…while my girlfriend was sleeping, relationship.status = still intact :)

---

*Last updated: May 2026*
