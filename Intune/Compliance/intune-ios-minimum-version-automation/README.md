# Intune iOS Minimum Version Automation

An Azure Automation Runbook that automatically updates the `osMinimumVersion` of an iOS compliance policy in Microsoft Intune.

## Disclaimer

**Important Notice**  
This entire script was written **without any AI assistance**. It is 100% hand-crafted, real-world PowerShell code developed and tested by Maurice Flöthmann.  
I place great value on genuine, maintainable, and production-ready code. Every function, logic flow, and error handling mechanism has been carefully designed based on real-world experience with Microsoft Intune and Azure Automation.

---

## Overview

This Runbook solves a common challenge in enterprise Intune environments: keeping the minimum iOS version in compliance policies up to date without manual effort.

It automatically:
- Reads all managed devices via Microsoft Graph
- Identifies iOS devices and their current operating system versions
- Calculates a safe and reasonable minimum iOS version
- Updates the selected iOS compliance policy if a change is required
- Sends a clear notification email with the result

## Features

- **Smart version detection**: Uses the third newest unique iOS version when enough devices are present
- **Safe fallback logic**: When fewer than 3 unique versions exist, it intelligently calculates a lower version
- **iOS version validation**: Prevents setting unrealistic future versions (e.g. 27.x or higher in 2026)
- **Idempotency**: Skips execution if the policy is already up to date
- **Robust error handling**: Continues gracefully even if individual steps (like PATCH) encounter issues
- **Detailed logging**: Every step is clearly logged for easy troubleshooting
- **Email notification**: Always sends a professional HTML email with full details
- **Production ready**: Designed for daily or weekly scheduled execution in Azure Automation

## Author

**Maurice Flöthmann**  
mo-cloud.de

**Questions or support requests:** [ask@mo-cloud.de](mailto:ask@mo-cloud.de)

## License

© 2026 Maurice Flöthmann

This script is provided **for personal and internal company use only**.  
Redistribution, public sharing, or commercial use (including modification for resale or SaaS products) is **strictly prohibited** without explicit written permission from the author.

If you wish to use this script in a commercial context or share it publicly, please contact me at **ask@mo-cloud.de**.

## Prerequisites

### 1. Azure Automation Variables (recommended: encrypted)

| Variable Name          | Description                                      | Example |
|------------------------|--------------------------------------------------|---------|
| `INTUNE_TENANT_ID`     | Azure AD Tenant ID                               | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `INTUNE_CLIENT_ID`     | Client ID of the App Registration                | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `INTUNE_CLIENT_SECRET` | Client Secret of the App Registration            | `~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| `INTUNE_POLICY_ID`     | Object ID of the target iOS Compliance Policy    | `e5d59a1f-d7fd-4fcb-b931-58797ec7bd6b` |
| `MAIL_SENDER_UPN`      | UPN of the mailbox used to send emails           | `mailboxinyourtennant@yourtennant.com` |
| `MAIL_RECIPIENT`       | Email address that receives the notification     | `yourmailbox@yourmail.com` |

### 2. Microsoft Graph API Permissions (Application permissions)

- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementConfiguration.ReadWrite.All`
- `Mail.Send`
- `Device.Read.All`

### 3. App Registration Setup

- Create an App Registration in Azure AD
- Grant the above API permissions (admin consent required)
- Create a client secret
- Store the values in the Automation Variables

## How It Works (Detailed Flow)

1. **Configuration** – Loads all required variables from Azure Automation
2. **Authentication** – Acquires an OAuth2 access token using client credentials flow
3. **Device Inventory** – Queries all managed devices and filters for iOS devices
4. **Version Analysis** – Parses `osVersion` and determines unique versions
5. **Target Version Calculation**:
   - If ≥ 3 unique versions → uses the third newest
   - Otherwise → safe fallback (highest version minus 1 minor version)
6. **Policy Check** – Loads current compliance policy and checks if update is needed
7. **Update** – Performs PATCH request to update `osMinimumVersion`
8. **Verification** – Re-reads the policy after a short delay to confirm the change
9. **Notification** – Sends a detailed HTML email with full summary

## Files in this Repository

- `README.md` – This documentation file
- `Update‑iOSMinimumOSVersion.ps1` – The main PowerShell Runbook script

## Installation Guide

1. Create a new **PowerShell 5.1** Runbook in Azure Automation
2. Copy the entire content of `Update-iOSCompliancePolicy.ps1` into the runbook
3. Create all six Automation Variables listed above
4. Save and **Publish** the runbook
5. (Recommended) Create a schedule (e.g. once per day or once per week)

## Example Email Notification

**Subject:**  
`[Intune] iOS Compliance MinVersion updated: 17.0 → 26.2.0`

The email contains a clean HTML table with:
- Policy ID
- Old and new minimum version
- Highest detected device version
- Verified version after update
- Information whether fallback mode was used

## Logging

The runbook produces detailed logs including:
- Every major step with clear headings
- Warning messages for fallback mode
- Error details if something goes wrong
- Final success confirmation

All logs are visible in the Azure Automation job output.

## Troubleshooting

Common issues and solutions:

- **Email not received**: Check that `MAIL_SENDER_UPN` has mailbox access and `Mail.Send` permission is granted.
- **Token error**: Verify the App Registration has correct permissions and the secret is not expired.
- **No iOS devices found**: The runbook will throw a clear error.
- **PATCH fails**: The runbook continues and logs the HTTP status.

If you encounter any issues, please send the full job output to **ask@mo-cloud.de**.

## Why This Script Exists

Manually maintaining minimum iOS versions in large environments is time-consuming and error-prone.  
This runbook brings automation, safety, and reliability to Intune iOS compliance management.

---

**Thank you for using this script. Created with care (and many late evenings) by Maurice Flöthmann**  
…while my girlfriend was sleeping, relationship.status = still intact :)

---

*Last updated: April 14 2026*
