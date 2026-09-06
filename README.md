# World of M365

I'm Maurice, and this is where I share the PowerShell scripts I build for my work with Microsoft 365.

Most of them started with something I wanted to make easier: keeping track of service issues, reviewing unused apps, or setting up another Autopilot test VM. The repository covers Entra ID, Intune and security, with a few things around them, like Proxmox.

Each project has its own README with setup instructions, required permissions and examples.

## The scripts

### Entra ID and reporting

**[Service Health Monitor](Entra/Reporting/ServiceHealthNotificationService/README.md)**  
Checks Microsoft 365 service health and emails a report when there are issues, along with recent Message Center announcements. No email when everything is healthy.

**[Inactive Enterprise Apps Report](Entra/Reporting/UnusedEnterpriseAppsReport/README.md)**  
Finds tenant-owned Enterprise Apps with no sign-in activity found in the last 30 days and emails you the results. Useful when reviewing which apps you still need.

### Intune and automation

**[Proxmox Windows Autopilot VM](Intune/Automation/New-ProxmoxWindowsAutopilotVM/README.md)**  
Creates a Windows VM from a Proxmox template, sets its CPU, memory and disk size, and registers it with Windows Autopilot. I built this to make creating fresh test VMs less of a manual job.

**[iOS Minimum Version Automation](Intune/Compliance/intune-ios-minimum-version-automation/README.md)**  
Uses the iOS versions running on your managed devices to update the minimum version in an Intune compliance policy, then emails you the result.

### Security

**[Edge Extension Inventory](Security/Reporting/EdgeExtensions/Readme.md)**  
Collects installed Edge extensions across user profiles and sends the results to Azure Log Analytics. Runs on Windows devices through Intune Remediations.

**[M365 Compromise Response Console](Security/SOC/M365%20Compromise%20Response%20Console/readme.md)**  
A local web interface for investigating compromised Microsoft 365 accounts, powered by PowerShell. It brings evidence together, helps you review related activity and lets you export findings or confirm actions to contain the incident.

## Getting started

Pick a project above and follow its README. Some scripts run in Azure Automation, some through Intune, and others on your own machine. The PowerShell version, permissions and configuration depend on the script.

You can download just the files you need or clone the whole repository:

```bash
git clone https://github.com/Mau2rice0/World-of-M365.git
```

Before running a script, read through it and check what it will change. Adjust the settings for your environment and test it before scheduling it or deploying it more widely.

## Feedback

If something doesn't work, [open an issue](https://github.com/Mau2rice0/World-of-M365/issues/new/choose) with the script name, what you were trying to do and the error you received. Relevant logs are helpful; please remove any secrets or sensitive tenant data.

Suggestions and improvements are welcome as well. For security issues, use the private reporting options in the [security policy](.github/SECURITY.md).

## License

See [LICENSE](LICENSE) and the notices in each project folder. Some project notices currently differ from the root license. Please contact me if you need clarification.

---

**Maurice Flöthmann** · [mo-cloud.de](https://mo-cloud.de) · [GitHub](https://github.com/Mau2rice0)

A few late evenings went into this. `relationship.status = still intact` :)
