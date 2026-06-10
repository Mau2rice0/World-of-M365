#Requires -Version 5.1
<#
.SYNOPSIS
    Collects Microsoft Edge extension inventory data across devices and ensures
    reliable remediation by always creating a local log directory and sending
    collected data to Azure Log Analytics.

    Designed for robustness and consistency, this script guarantees execution
    outcomes even in error scenarios and provides centralized visibility of
    installed browser extensions.

.AUTHOR
    Maurice Flöthmann

.COPYRIGHT
    © 2026 mo-cloud.de Maurice Flöthmann

.LICENSE
    This script is provided for personal and internal company use only.
    Redistribution or commercial use without explicit permission is prohibited.

    Questions or support requests: ask@mo-cloud.de
#>

# These are the parameters you must customize for your environment
param (
    [string]$WorkspaceId = "", #Your Workspace ID
    [string]$SharedKey = "", #Your Workspace Shared Key
    [string]$LogType = "EdgeExtensionInventory", #Table name in your Log Analytics Workspace
    [bool]  $EnableLogging = $false # Control if you want a local log file, useful for debugging or first deployment if your table is new
)

# Logging variables, recommended defaults
$LogRoot = "C:\Temp\EdgeInventoryLogs"
$LogFile = Join-Path $LogRoot "EdgeExt_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $Entry = "[$Time] [$Level] $Message"
    
    if (-not $EnableLogging) {
            return
        }
    # Always output to console (visible in Intune)
    switch ($Level) {
        "ERROR"   { Write-Error $Entry -ErrorAction Continue }
        "WARNING" { Write-Warning $Entry }
        default   { Write-Output $Entry }
    }
    
    # Write to file
    try {
        if (-not (Test-Path $LogRoot)) {
            New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
            Write-Output "[$Time] [INFO] Log directory $LogRoot has been created."
        }
        $Entry | Out-File -FilePath $LogFile -Encoding UTF8 -Append -Force
    }
    catch {
        Write-Error "LOG WRITE ERROR: $($_.Exception.Message)" -ErrorAction Continue
    }
}

# Start logging immediately
Write-Log "=== Edge Extension Inventory Collector started ==="
Write-Log "PowerShell version: $($PSVersionTable.PSVersion) | 64-bit: $([Environment]::Is64BitProcess)"
Write-Log "Log: $LogFile"

# Ensure C:\Temp exists
try {
    if (-not (Test-Path "C:\Temp")) {
        New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null
        Write-Log "C:\Temp was newly created" "WARNING"
    }
    if (-not (Test-Path $LogRoot)) {
        New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
        Write-Log "Log directory $LogRoot successfully created" "INFO"
    }
}
catch {
    Write-Log "Error while creating directories: $($_.Exception.Message)" "ERROR"
}

# =============================================
# 2. VARIABLES
# =============================================
$Hostname = $env:COMPUTERNAME
$Timestamp = (Get-Date).ToUniversalTime().ToString("o")
$LogEntries = @()
$SuccessCount = 0

Write-Log "Starting search for Edge extensions..."

# =============================================
# 3. SEARCH EXTENSIONS
# =============================================
try {
    $UserProfiles = Get-ChildItem "C:\Users" -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch "^(Public|Default|Default User|All Users|systemprofile)$" }

    Write-Log "Detected user profiles: $($UserProfiles.Count)"

    foreach ($Profile in $UserProfiles) {
        $ExtensionsBasePath = Join-Path $Profile.FullName "AppData\Local\Microsoft\Edge\User Data"
        
        if (-not (Test-Path $ExtensionsBasePath)) {
            Write-Log "No Edge directory for profile: $($Profile.Name)" "WARNING"
            continue
        }

        Write-Log "Scanning profile: $($Profile.Name)"

        $ManifestFiles = Get-ChildItem -Path $ExtensionsBasePath -Filter "manifest.json" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\Extensions\\[a-z0-9]{32}' }

        foreach ($Manifest in $ManifestFiles) {
            try {
                $ManifestContent = Get-Content $Manifest.FullName -Raw -Encoding UTF8 | ConvertFrom-Json

                # Only real extensions
                if (-not $ManifestContent.name -or -not $ManifestContent.version) {
                    continue
                }

                $PathParts = $Manifest.FullName -split "\\"
                $ExtensionID = $PathParts[$PathParts.Count - 3]
                
                # Only valid extension IDs
                if ($ExtensionID -notmatch '^[a-z0-9]{32}$') { continue }

                $EdgeProfileIndex = [array]::IndexOf($PathParts, "User Data") + 1
                $EdgeProfileName = if ($EdgeProfileIndex -lt $PathParts.Count) { $PathParts[$EdgeProfileIndex] } else { "Default" }

                $ExtensionName = $ManifestContent.name
                if ($ExtensionName -match "^__MSG_") {
                    $ExtensionName = if ($ManifestContent.short_name) { $ManifestContent.short_name } else { "Localized_$ExtensionID" }
                }

                $LogEntries += [PSCustomObject]@{
                    Hostname         = $Hostname
                    WindowsUser      = $Profile.Name
                    EdgeProfile      = $EdgeProfileName
                    ExtensionName    = $ExtensionName
                    ExtensionID      = $ExtensionID
                    ExtensionVersion = $ManifestContent.version
                    Description      = $ManifestContent.description
                    Timestamp        = $Timestamp
                    ScriptVersion    = "2025.06.05-FINAL"
                }

                $SuccessCount++
                Write-Log "Extension found: $ExtensionName ($ExtensionID)" "INFO"
            }
            catch {
                Write-Log "Error while reading: $($Manifest.FullName) - $($_.Exception.Message)" "WARNING"
            }
        }
    }
}
catch {
    Write-Log "Critical error during scanning: $($_.Exception.Message)" "ERROR"
}

# =============================================
# 4. SEND DATA (Batch)
# =============================================
if ($LogEntries.Count -gt 0) {
    try {
        $jsonBody = $LogEntries | ConvertTo-Json -Depth 5 -Compress
        $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonBody)
        $bodyLength = $jsonBytes.Length

        $uri = "https://$WorkspaceId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")

        $stringToHash = "POST`n$bodyLength`napplication/json`nx-ms-date:$rfc1123date`n/api/logs"
        $bytesToHash = [System.Text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($SharedKey)
        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.Key = $keyBytes
        $signature = [Convert]::ToBase64String($sha256.ComputeHash($bytesToHash))

        $headers = @{
            "Authorization"       = "SharedKey $WorkspaceId`:$signature"
            "Log-Type"            = $LogType
            "x-ms-date"           = $rfc1123date
            "time-generated-field" = "Timestamp"
            "Content-Type"        = "application/json"
        }

        Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $jsonBytes -ErrorAction Stop
        
        Write-Log "SUCCESS: $($LogEntries.Count) extensions sent!" "INFO"
        Write-Output "Successfully sent $($LogEntries.Count) Edge extensions."
    }
    catch {
        Write-Log "SEND ERROR: $($_.Exception.Message)" "ERROR"
        Write-Log "Status: $($_.Exception.Response.StatusCode)" "ERROR"
        Write-Output "Error during send operation: $($_.Exception.Message)"
    }
}
else {
    Write-Log "No Edge extensions found." "INFO"
    Write-Output "No Edge extensions found."
}

# =============================================
# 5. COMPLETION
# =============================================
Write-Log "=== Script finished ==="
Write-Log "Found & sent extensions: $SuccessCount"
Write-Log "Log file: $LogFile"

 if ($EnableLogging -eq $true) {
    Write-Output "=== Remediation completed - log available at C:\Temp\EdgeInventoryLogs ==="
            
    }


exit 0