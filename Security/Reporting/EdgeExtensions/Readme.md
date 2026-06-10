# Edge Extension Inventory Collector

A robust PowerShell script for comprehensive collection of Microsoft Edge extensions across all user profiles, with reliable forwarding of inventory data to Azure Log Analytics.

## Disclaimer

**Important Notice**

This entire script was developed **without any AI assistance**. It is 100% hand-crafted, production-grade PowerShell code, authored and thoroughly tested by Maurice Flöthmann.

Emphasis has been placed on creating maintainable, enterprise-ready code. Every function, logic path, and error-handling routine has been meticulously designed based on real-world experience with Microsoft Intune and Azure Log Analytics.

---

## Overview

This script addresses the lack of visibility into installed browser extensions in enterprise environments. It systematically scans all user profiles for installed Microsoft Edge extensions and transmits the collected data reliably to an Azure Log Analytics workspace. The script is engineered for high resilience, automatically creating necessary local log directories and ensuring consistent execution even when partial failures occur.

## Features

* **Complete Inventory Collection** of all Edge extensions per user and profile
* **Robust Directory Management** — automatically creates `C:\Temp` and dedicated log folders as needed
* **Reliable Data Ingestion** into Azure Log Analytics, even with partial success
* **Detailed Timestamped Logging** with support for multiple log levels
* **Consistent Execution** — always returns exit code 0
* **Intune-Optimized** — specifically designed for execution as a Remediation Script
* **Production-Grade** — comprehensive error handling and fallback mechanisms

## Author

**Maurice Flöthmann**  
[mo-cloud.de](https://mo-cloud.de)  

**Questions or Support Requests:** [ask@mo-cloud.de](mailto:ask@mo-cloud.de)

## License

© 2026 Maurice Flöthmann

This script is provided **exclusively for personal and internal enterprise use**. Redistribution, public disclosure, or commercial utilization (including modification for resale or SaaS offerings) is **strictly prohibited** without explicit written permission from the author.  

For commercial licensing or distribution inquiries, please contact: **ask@mo-cloud.de**.

## Prerequisites

* PowerShell 5.1 or higher
* Execution in System context (recommended for Intune)
* Azure Log Analytics workspace with target table `EdgeExtensionInventory`
* Workspace ID and Shared Key (configurable via script parameters)

## Installation / Deployment (Intune)

1. Download the script `EdgeExtensionInventory.ps1` (and `detect.ps1` if applicable)
2. Create a Log Analytics workspace and retrieve the Shared Key
3. Insert your Workspace ID and Shared Key into the script parameters
4. Enable local logging if required by setting `$EnableLogging = $true`
5. Create a **Remediation Script** deployment in Intune and upload the script(s)
6. Assign the script to the target device group(s)

## How It Works

1. **Preparation** — Creation of required directories (`C:\Temp` and log folder)
2. **Profile Discovery** — Enumeration of all user profiles (excluding system profiles)
3. **Extension Scanning** — Recursive search for `manifest.json` files within Edge user data directories
4. **Data Enrichment** — Extraction of extension name, version, ID, profile information, and other metadata
5. **Transmission** — Batch submission of all collected records to Azure Log Analytics
6. **Completion** — Comprehensive logging of results and execution status

## Parameters

| Parameter       | Description                                      | Default Value                  |
|-----------------|--------------------------------------------------|--------------------------------|
| `$WorkspaceId`  | Azure Log Analytics Workspace ID                 | (required)                     |
| `$SharedKey`    | Shared Key for the workspace                     | (required)                     |
| `$LogType`      | Destination table name in Log Analytics          | `EdgeExtensionInventory`       |
| `$EnableLogging`| Enable local log file output                     | `$false`                       |

## Logging

The script produces detailed logging output:

* Console output (visible in Intune execution logs)
* Optional persistent log files under `C:\Temp\EdgeInventoryLogs\`

## Troubleshooting

* For data transmission issues: Set `$EnableLogging = $true` and review the generated log files
* Ensure the script is executed in **System context**
* Verify permissions and configuration of the target Azure Log Analytics workspace

---

**Thank you for using this script.**  

Carefully developed with dedication and extensive real-world testing by Maurice Flöthmann.

*Last updated: June 2026*
