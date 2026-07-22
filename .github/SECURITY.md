# Security Policy

## Supported Versions

This repository contains **PowerShell automation scripts for Microsoft 365** (Entra ID, Intune, Security, etc.).

I actively support the **latest version** of the scripts in the `main` branch. Older versions or archived scripts may no longer receive security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in any of the scripts, please **do not** report it publicly via Issues.

I take security seriously and appreciate responsible disclosure.

### How to report
- **Preferred method**: Use GitHub's **Private vulnerability reporting**   
- **Alternative**: Send an email to `maurice.floethmann@mo-cloud.de` (or the email linked in your GitHub profile)

Please include the following information in your report:
- Description of the vulnerability
- Affected script(s) and path (e.g. `Intune/Compliance/...`)
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if available)
- Any additional context (e.g. affected M365 tenant configuration)


## Security Best Practices for Users

Since these are automation scripts with high privileges (often Global Admin / Graph permissions), we recommend:

- Always review scripts before execution
- Use least-privilege service principals where possible
- Store credentials securely (e.g. Azure Key Vault, Managed Identity)
- Keep your scripts updated from this repository

## Security Updates

Security-relevant fixes will be:
- Released as soon as possible
- Clearly marked in the commit messages and release notes

---

Thank you for helping keep the **World-of-M365** toolkit secure!
