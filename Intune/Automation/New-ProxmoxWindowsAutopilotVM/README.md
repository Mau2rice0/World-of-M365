# Automatic Autopilot Proxmox-VM Creator with Azure Hybrid Runbook

An Azure Automation Runbook that creates a Windows 11 VM on Proxmox, prepares Windows and imports the device into Windows Autopilot.


## Disclaimer

**Important Notice**  
I created this automation because I regularly need new test devices for Microsoft Intune policies, applications and configuration profiles. Taking several physical devices with me is not practical, especially while travelling.

Virtual machines are perfect for these tests, but creating the VM, adjusting the hardware, collecting the hardware hash and importing it into Windows Autopilot takes too much time when it has to be done manually. This Runbook takes care of the complete process.

I use Proxmox because it is free, flexible and easy to manage. Once a Windows 11 template has been prepared, Azure Automation can create new test VMs whenever they are needed, provided that enough compute and storage resources are available.

The Runbook changes the virtual hardware, Windows partitions and Windows Recovery configuration. Test it in a non-production environment first :)

I created this script to solve a problem that had been bothering me for quite some time. It is still under development and may contain bugs that I have not encountered yet. If you find an issue, please open a GitHub issue, and I will take a look and try to fix it.

---

## Overview

The Runbook creates a full clone of an existing Windows 11 template on a Proxmox server or cluster. It then prepares the VM and registers it with Windows Autopilot.

# It automatically:
- Creates a full clone of the Windows 11 template
- Assigns a new VM ID and a unique SMBIOS serial number
- Configures CPU, memory and disk size from the Runbook parameters
- Expands the virtual disk and the Windows `C:` partition when required
- Removes a blocking Recovery partition only when it can be clearly identified
- Recreates the Recovery partition and enables Windows RE again
- Waits for the QEMU Guest Agent
- Collects the hardware hash through the Windows MDM bridge
- Imports the device into Windows Autopilot through Microsoft Graph
- Monitors the Autopilot import until it is completed
- Reboots the VM through Proxmox so that it can retrieve its Autopilot profile

No user or Group Tag is assigned during the import.

## Features

- **Full clone deployment:** Creates an independent VM including EFI and TPM state disks
- **Automatic VM sizing:** CPU, memory and disk size are controlled through Runbook parameters
- **Automatic disk expansion:** Resizes the Proxmox disk and the Windows system partition
- **Recovery handling:** Handles a blocking Recovery partition and configures Windows RE again
- **Native hardware hash collection:** Reads `DeviceHardwareData` from `MDM_DevDetail_Ext01`
- **Managed Identity authentication:** No Azure credentials or client secrets are required
- **No module dependency:** `Az.Accounts`, AzureRM and `Microsoft.Graph.Authentication` are not required
- **Flexible TLS validation:** Supports standard validation, certificate pinning or an explicit bypass
- **Retry logic:** Retries suitable API requests without repeating unsafe POST operations
- **Detailed logging:** Logs all important steps, state changes and errors
- **PowerShell 5.1 compatible:** PowerShell 7 is not required on the Windows Hybrid Worker

## Files in This Project

- `New-ProxmoxWindowsAutopilotVM.ps1` – Main Azure Automation Runbook
- `Assign-permissions.ps1` – Helper script for assigning the Microsoft Graph permission
- `README.md` – Documentation, installation and troubleshooting

> Update the Managed Identity Principal ID in `Assign-permissions.ps1` before running the script.

## Author

**Maurice Flöthmann**  
[mo-cloud.de](https://mo-cloud.de)

Questions or support requests: [ask@mo-cloud.de](mailto:ask@mo-cloud.de)

## License

© 2026 Maurice Flöthmann

This script is provided for personal and internal company use only. Redistribution, public sharing or commercial use is prohibited without explicit written permission from the author.

---

## Requirements

### 1. Proxmox Host

I tested the solution on a Lenovo ThinkStation P520 with the following hardware:

- 2 × 128 GB SATA SSDs in a ZFS mirror for Proxmox
- 1 × 1 TB NVMe SSD for the VMs
- 256 GB DDR4 ECC memory
- Intel Xeon W-2123 CPU, which is the main bottleneck in this setup

This system ran up to eight Windows 11 VMs smoothly in my tests. A CPU with more cores should be able to run considerably more VMs. Storage performance also has to scale because insufficient IOPS can quickly become the next bottleneck. :)

### 2. Azure Automation and Hybrid Worker

- Azure Automation Account with an enabled **System-assigned Managed Identity**
- Windows Hybrid Runbook Worker with Windows PowerShell 5.1
- Network access to the Proxmox API, normally TCP port `8006`
- Outbound HTTPS access to `graph.microsoft.com`
- Access to Automation Variables through `Get-AutomationVariable`
- Active Microsoft Intune licensing in the tenant

I tested the Runbook with Windows Server 2025 as the Hybrid Worker. The Graph token is requested directly from the Managed Identity endpoint. Therefore, `Az.Accounts` and `Microsoft.Graph.Authentication` are not required.

### 3. Microsoft Graph Permission

The Managed Identity requires the following **Application permission**:

- `DeviceManagementServiceConfig.ReadWrite.All`

The included `Assign-permissions.ps1` helper can assign the permission after the Managed Identity Principal ID has been updated.

### 4. Proxmox Windows Template

The template should contain:

- Windows 11 Enterprise or Pro
- UEFI/OVMF firmware and an EFI disk
- TPM state disk with TPM 2.0
- Installed and running QEMU Guest Agent
- Installed VirtIO drivers
- System disk of at least 32 GB
- Windows prepared for OOBE, normally with Sysprep

Shut down the source VM before cloning and convert it into a Proxmox template. The Runbook creates full clones only so that the EFI and TPM state disks are copied as well.

---

## Azure Automation Variables

### Required Variables

| Variable Name | Type | Description | Example |
|---|---|---|---|
| `PVE_HOST` | String | Proxmox hostname or IP address without protocol | `pve01.mo-cloud.local` |
| `PVE_PORT` | String | Proxmox API port | `8006` |
| `PVE_API_TOKEN_ID` | String | Token ID in `user@realm!tokenname` format | `azureautomation@pve!runbook` |
| `PVE_API_TOKEN_SECRET` | Encrypted String | UUID secret of the API token | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `PVE_TEMPLATE_ID` | String | VM ID of the Windows template | `101` |

### Optional Variables

| Variable Name | Type | Default | Description |
|---|---|---|---|
| `PVE_TARGET_NODE` | String | Template node | Node on which the new VM will be created |
| `PVE_TARGET_STORAGE` | String | Template/default storage | Target storage for the full clone |
| `PVE_VALIDATE_CERTIFICATE` | Boolean | `true` | Enables or disables TLS certificate validation |
| `PVE_CERT_THUMBPRINT` | String | Empty | 40-character SHA-1 thumbprint used for certificate pinning |

Store `PVE_API_TOKEN_SECRET` as an **encrypted Automation Variable**.

> **Security warning:** Set `PVE_VALIDATE_CERTIFICATE` to `false` only in a controlled lab or temporarily for troubleshooting. Keep certificate validation enabled in production.

## Runbook Parameters

| Parameter | Type | Default | Range | Description |
|---|---|---|---|---|
| `Cores` | Integer | `4` | 1–64 | Number of virtual CPU cores |
| `MemoryGB` | Integer | `8` | 4–256 | VM memory in GB |
| `DiskSizeGB` | Integer | `128` | 32–4096 | Final Windows system disk size in GB |

`DiskSizeGB` cannot be smaller than the template disk. The Runbook expands the virtual Proxmox disk before extending Windows `C:`.

---

## Installation Guide

### Step 1: Create the Proxmox User, Role and API Token

Run the following commands as `root` in the shell of one Proxmox cluster node. Change the example names if required.

```bash
PVE_USER='azureautomation@pve'
PVE_TOKEN_NAME='runbook'
PVE_ROLE='AutopilotProvisioner'

pveum user add "$PVE_USER" \
    --comment 'Azure Automation Autopilot VM provisioning'

pveum role add "$PVE_ROLE" \
    --privs 'Sys.Audit Datastore.Audit Datastore.AllocateSpace VM.Audit VM.Allocate VM.Clone VM.Config.CPU VM.Config.Memory VM.Config.Disk VM.Config.HWType VM.Config.Options VM.PowerMgmt VM.Monitor'

pveum acl modify / \
    --user "$PVE_USER" \
    --role "$PVE_ROLE" \
    --propagate 1

pveum user token add "$PVE_USER" "$PVE_TOKEN_NAME" \
    --privsep 0 \
    --comment 'Azure Automation Runbook'
```

The final command displays:

- `full-tokenid` – Store this as `PVE_API_TOKEN_ID`
- `value` – Store this immediately as the encrypted `PVE_API_TOKEN_SECRET`

> **Important:** Proxmox displays the token secret only once. If it is lost, remove the token and create a new one. Never publish the secret or add it to the documentation.

The `--privsep 0` setting makes the token inherit the permissions of its user. The effective token permissions are still limited by the permissions assigned to that user.

### Step 2: Verify the Proxmox Configuration

The password of the API-only service user is not required by this Runbook. Authentication uses the token ID and its secret.

The following commands verify the user, role, ACL and effective token permissions without exposing the secret:

```bash
PVE_USER='azureautomation@pve'
PVE_TOKEN_NAME='runbook'
PVE_ROLE='AutopilotProvisioner'

pveum user list | grep -F "$PVE_USER"
pveum role list | grep -F "$PVE_ROLE"
pveum acl list | grep -F "$PVE_USER"
pveum user token list "$PVE_USER"
pveum user permissions "$PVE_USER"
pveum user token permissions "$PVE_USER" "$PVE_TOKEN_NAME"
```

To replace a lost or exposed token:

```bash
pveum user token remove azureautomation@pve runbook
pveum user token add azureautomation@pve runbook \
    --privsep 0 \
    --comment 'Azure Automation Runbook'
```

Save the newly displayed `value` immediately and update `PVE_API_TOKEN_SECRET` in Azure Automation.

### Step 3: Configure Azure and Deploy the Runbook

Recommended order:

1. Create the Azure Automation Account
2. Enable its System-assigned Managed Identity
3. Assign `DeviceManagementServiceConfig.ReadWrite.All` and grant admin consent
4. Install the Windows Hybrid Runbook Worker and test it with a simple local Runbook
5. Prepare Windows 11 with the VirtIO drivers and QEMU Guest Agent
6. Run Sysprep for OOBE, shut down Windows and convert the VM into a template
7. Create the Proxmox user, role, ACL and API token
8. Create and populate the Azure Automation Variables
9. Create a PowerShell 5.1 Runbook, paste the script, save and publish it
10. Start the Runbook in the test pane and select the Hybrid Worker
11. Verify the clone, Autopilot import and profile retrieval after the reboot

Example parameters:

```text
Cores      = 4
MemoryGB   = 8
DiskSizeGB = 128
```

---

## How It Works

1. **Validation** – Initializes logging and checks the runtime
2. **Configuration** – Reads and validates the Automation Variables
3. **TLS configuration** – Enables standard validation, certificate pinning or the configured bypass
4. **Proxmox authentication** – Connects to the Proxmox API using the API token
5. **Template lookup** – Finds the template in the visible cluster resources
6. **VM preparation** – Allocates a new VM ID and generates a unique serial number
7. **Clone** – Creates and monitors the full clone
8. **Disk resize** – Expands the detected system disk
9. **VM configuration** – Sets CPU, memory, Guest Agent and SMBIOS serial number
10. **Windows preparation** – Starts the VM, expands `C:` and configures Windows RE
11. **Hardware hash** – Reads the serial number and `DeviceHardwareData`
12. **Graph authentication** – Requests a token through the Managed Identity
13. **Autopilot import** – Submits the serial number and hardware hash without a user or Group Tag
14. **Import monitoring** – Waits for the import to complete or fail
15. **Reboot** – Reboots the VM through Proxmox after a short propagation delay
16. **Result** – Returns the VM details, import ID, status and runtime

## Runtime

The runtime depends on the template size, storage speed, current hypervisor load, Windows startup and Intune processing.

In my tests, a new VM was usually created and registered within approximately five minutes. Microsoft service load can increase this considerably. The Runbook waits up to 20 minutes for the Autopilot import.

## Successful Result

```text
Success            : True
VMName             : PROX0123456789AB
VMID               : 102
ProxmoxNode        : pve02
Cores              : 4
MemoryGB           : 8
DiskSizeGB         : 128
AutopilotImportID  : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AutopilotCompleted : True
RestartScheduled   : True
RuntimeSeconds     : 216.6
```

---

## Logging

The Runbook logs:

- Run ID, Hybrid Worker, PowerShell version and current step
- Proxmox API path, request duration, HTTP status and retry information
- Clone, resize, start and reboot task status
- QEMU Guest Agent availability
- Partition layout before and after the expansion
- Recovery partition removal, recreation and activation
- MDM bridge and hardware hash status
- Graph authentication and Autopilot import status
- Failure step, exception type, position and stack trace

The logs are available in the Azure Automation job output and locally under:

```text
C:\ProgramData\AzureAutomation\Proxmox
```

Token secrets, Graph access tokens and the complete hardware hash are not logged.

## Troubleshooting

- **Proxmox HTTP 401:** Check the token ID, current secret, expiration and permissions of the token and user
- **TLS trust failure:** Install a trusted certificate, configure `PVE_CERT_THUMBPRINT` or disable validation temporarily in a lab
- **Template not found:** Check `PVE_TEMPLATE_ID` and whether the token can see the template
- **Clone fails:** Check the Proxmox task log, free storage, storage health and current I/O load
- **Disk is not expanded:** Review the detected disk and partition layout in the logs
- **QEMU Guest Agent unavailable:** Check its installation, service status and the Proxmox agent option
- **Hardware hash unavailable:** Check `MDM_DevDetail_Ext01` under `root/cimv2/mdm/dmmap`
- **Windows Recovery fails:** Check `winre.wim`, the partition layout and `reagentc` output
- **Managed Identity fails:** Check the Hybrid Worker, `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`
- **Autopilot import rejected:** Check the Graph permission, admin consent, Intune license and duplicate serial numbers
- **Profile does not appear immediately:** Check the profile assignment and target group, then allow additional processing time

## Security Notes

- Never place token secrets in the source code
- Store `PVE_API_TOKEN_SECRET` as an encrypted Automation Variable
- Never publish API tokens, access tokens or hardware hashes
- Revoke and replace an exposed token immediately
- Keep certificate validation enabled in production
- Use a dedicated Proxmox user with only the required permissions
- Keep the Hybrid Worker, Windows, VirtIO drivers and QEMU Guest Agent updated

---

## Why This Script Exists

Manually creating Windows 11 test VMs, resizing the disks and uploading Autopilot hardware hashes takes time. Carrying several physical test devices is not a useful alternative when I am working remotely or travelling.

This Runbook combines Proxmox provisioning and Windows Autopilot registration into one repeatable process.

The goal is simple: create a new Windows 11 test VM with as little manual work as possible, register it with Windows Autopilot and let it retrieve the assigned profile.

---

Thank you for using this script. Created with care and several long evenings by Maurice Flöthmann.  
…while my girlfriend was working, `relationship.status = still intact` :)

---

Last updated: September 2026
