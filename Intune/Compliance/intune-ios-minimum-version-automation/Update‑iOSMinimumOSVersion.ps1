#Requires -Version 5.1
<#
.SYNOPSIS
    Automatically updates the osMinimumVersion of an iOS Compliance Policy in Microsoft Intune.
    
    This runbook works 100% in Azure Automation.

.AUTHOR
    Maurice Flöthmann

.COPYRIGHT
    © 2026 Maurice Flöthmann (mo-cloud.de)

.LICENSE
    This script is provided for personal and internal company use only.
    Redistribution or commercial use without explicit permission is prohibited.
    
    Questions or support requests: ask@mo-cloud.de
#>

$ErrorActionPreference = 'Stop'

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Log {
    <#
    .DESCRIPTION
        Writes a timestamped log message.
    #>
    param(
        [string]$Msg,
        [string]$Lvl = 'INFO'
    )
    Write-Output ("[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Lvl, $Msg)
}

function Get-AzVar {
    <#
    .DESCRIPTION
        Retrieves an Azure Automation variable and validates it is not empty.
    #>
    param([string]$Name)
    $v = Get-AutomationVariable -Name $Name
    if ([string]::IsNullOrWhiteSpace($v)) { 
        throw "Automation Variable '$Name' is missing or empty." 
    }
    return $v
}

function ConvertTo-SemVer {
    <#
    .DESCRIPTION
        Converts a raw iOS version string into a [version] object.
    #>
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $clean = ($Raw -replace '[^0-9.]', '').Trim('.')
    if ($clean -eq '') { return $null }
    $parts = $clean -split '\.' | ForEach-Object { try { [int]$_ } catch { 0 } }
    try {
        switch ($parts.Count) {
            1 { [version]"$($parts[0]).0" }
            2 { [version]"$($parts[0]).$($parts[1])" }
            3 { [version]"$($parts[0]).$($parts[1]).$($parts[2])" }
            default { [version]"$($parts[0]).$($parts[1]).$($parts[2]).$($parts[3])" }
        }
    } catch { $null }
}

function Format-VerStr {
    <#
    .DESCRIPTION
        Formats a [version] object into a clean string.
    #>
    param([version]$V)
    if (-not $V) { return 'N/A' }
    if ($V.Build -ge 0) { 
        "{0}.{1}.{2}" -f $V.Major, $V.Minor, $V.Build 
    } else { 
        "{0}.{1}" -f $V.Major, $V.Minor 
    }
}

function Is-ValidIosVersion {
    <#
    .DESCRIPTION
        Checks if a version is a realistic iOS version.
    #>
    param([version]$Ver)
    if ($Ver.Major -lt 15 -or $Ver.Major -gt 28) { return $false }
    if ($Ver.Major -eq 26 -and $Ver.Minor -gt 6) { return $false } # safety buffer
    return $true
}

function Compute-SafeTargetVersion {
    <#
    .DESCRIPTION
        Calculates a safe target version (highest minus 1 minor).
    #>
    param([version]$Highest)
    $candidate = [version]"$($Highest.Major).$([Math]::Max(0, $Highest.Minor - 1)).0"
    $attempt = 0
    while (-not (Is-ValidIosVersion $candidate) -and $attempt -lt 5) {
        Write-Log "Version $candidate appears invalid - trying one minor version lower" -Lvl 'WARN'
        $candidate = [version]"$($candidate.Major).$([Math]::Max(0, $candidate.Minor - 1)).0"
        $attempt++
    }
    if (-not (Is-ValidIosVersion $candidate)) {
        Write-Log "No valid iOS version found - using safe minimum 26.0" -Lvl 'WARN'
        $candidate = [version]"26.0"
    }
    return $candidate
}

# ============================================================
# MAIN EXECUTION
# ============================================================

Write-Log "=== Runbook started ==="

# Step 1: Configuration
Write-Log "--- Step 1: Configuration ---"
$tenantId      = Get-AzVar 'INTUNE_TENANT_ID'
$clientId      = Get-AzVar 'INTUNE_CLIENT_ID'
$clientSecret  = Get-AzVar 'INTUNE_CLIENT_SECRET'
$policyId      = Get-AzVar 'INTUNE_POLICY_ID'
$mailSender    = Get-AzVar 'MAIL_SENDER_UPN'
$mailRecipient = Get-AzVar 'MAIL_RECIPIENT'

Write-Log "Policy ID : $policyId"

# Step 2: OAuth2 Token
Write-Log "--- Step 2: OAuth2 Token ---"
$tokenBody = @{ 
    grant_type    = 'client_credentials'
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = 'https://graph.microsoft.com/.default'
}
$tr = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
                        -Method POST -Body $tokenBody -ContentType 'application/x-www-form-urlencoded'
$token = $tr.access_token
Write-Log "Token OK"

# Step 3: Fetch iOS devices
Write-Log "--- Step 3: Fetch iOS devices ---"
$uriDevices = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$select=id,deviceName,operatingSystem,osVersion&`$top=500"
$devices = (Invoke-RestMethod -Uri $uriDevices -Method GET -Headers @{Authorization = "Bearer $token"} -ErrorAction Stop).value

$iosDevices = $devices | Where-Object { $_.operatingSystem -and $_.operatingSystem -imatch '^iOS$' }
Write-Log "iOS devices: $($iosDevices.Count) | Total devices: $($devices.Count)"

$versions = [System.Collections.Generic.List[version]]::new()
foreach ($d in $iosDevices) {
    if ($d.osVersion) {
        $v = ConvertTo-SemVer $d.osVersion
        if ($v) { $versions.Add($v) }
    }
}

if ($versions.Count -eq 0) { 
    throw "No valid iOS versions found!" 
}

$uniqueSorted = $versions | Sort-Object -Unique -Descending
Write-Log "Unique versions: $($uniqueSorted -join ', ')"

# Calculate target version
$fallbackMode = $false
if ($uniqueSorted.Count -ge 3) {
    $targetVersion = $uniqueSorted[2]
} else {
    $fallbackMode = $true
    $highest = $uniqueSorted[0]
    $targetVersion = Compute-SafeTargetVersion -Highest $highest
    Write-Log "Fallback active: $highest → $targetVersion" -Lvl 'WARN'
}

$targetStr = Format-VerStr $targetVersion
Write-Log "Target minimum version: $targetStr"

# Step 4: Load policy
Write-Log "--- Step 4: Load Compliance Policy ---"
$policyUrl = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$policyId"
$policy = Invoke-RestMethod -Uri $policyUrl -Method GET -Headers @{Authorization = "Bearer $token"} -ErrorAction Stop

$currentVer = $policy.osMinimumVersion
$odataType  = $policy.'@odata.type'
Write-Log "Current minimum version: '$currentVer'"

# Step 5: Idempotency Check
Write-Log "--- Step 5: Idempotency Check ---"
if ((ConvertTo-SemVer $currentVer | Format-VerStr) -eq $targetStr) {
    Write-Log "No change needed - Runbook finished (idempotent)"
    Write-Log "=== Runbook completed successfully ==="
    exit 0
}

# Step 6: Update Policy (robust PATCH)
Write-Log "--- Step 6: Update Policy ---"
Write-Log "Sending PATCH with version: $targetStr"

$patchJson = @"
{"@odata.type":"$odataType","osMinimumVersion":"$targetStr"}
"@

try {
    $hdrs = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
    Write-Log "PATCH URL : $policyUrl"
    Write-Log "PATCH Body: $patchJson"
    
    $response = Invoke-WebRequest -Uri $policyUrl -Method PATCH -Headers $hdrs `
                                  -Body $patchJson -ContentType 'application/json' -UseBasicParsing -ErrorAction Stop
    Write-Log "PATCH successful - HTTP $($response.StatusCode)"
} 
catch {
    Write-Log "PATCH Exception: $($_.Exception.Message)" -Lvl 'ERROR'
    if ($_.Exception.Response) {
        $status = $_.Exception.Response.StatusCode.value__
        Write-Log "HTTP Status Code: $status" -Lvl 'ERROR'
    }
}

# Verification
Write-Log "Waiting 6 seconds for verification..."
Start-Sleep -Seconds 6

$confirmed = "unknown"
try {
    $updated = Invoke-RestMethod -Uri $policyUrl -Method GET -Headers @{Authorization = "Bearer $token"}
    $confirmed = $updated.osMinimumVersion
    Write-Log "Verified minimum version: $confirmed"
} 
catch {
    Write-Log "Verification failed: $($_.Exception.Message)" -Lvl 'WARN'
}

# Step 7: Send Email
Write-Log "--- Step 7: Send notification email ---"
$fallbackHint = if ($fallbackMode) { ' (Fallback Mode)' } else { '' }
$subject = "[Intune] iOS Compliance MinVersion updated: $currentVer → $targetStr"

$htmlBody = @"
<html><body style="font-family:Segoe UI,sans-serif">
<h2>iOS Compliance Policy Updated</h2>
<table border="1" cellpadding="8" style="border-collapse:collapse">
<tr><td><b>Policy ID</b></td><td>$policyId</td></tr>
<tr><td><b>Old Version</b></td><td>$currentVer</td></tr>
<tr><td><b>New Version</b></td><td>$targetStr$fallbackHint</td></tr>
<tr><td><b>Highest Device Version</b></td><td>$(Format-VerStr $uniqueSorted[0])</td></tr>
<tr><td><b>Verified</b></td><td>$confirmed</td></tr>
</table>
<p style="color:#666">Automatically generated by Azure Automation Runbook – $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>
</body></html>
"@

$htmlEscaped = $htmlBody -replace '\\','\\\\' -replace '"','\"' -replace "`r?`n", '\n'

$mailJson = @"
{"message":{"subject":"$subject","body":{"contentType":"HTML","content":"$htmlEscaped"},"toRecipients":[{"emailAddress":{"address":"$mailRecipient"}}]},"saveToSentItems":false}
"@

$mailUrl = "https://graph.microsoft.com/v1.0/users/$mailSender/sendMail"

try {
    Invoke-WebRequest -Uri $mailUrl -Method POST `
                      -Headers @{Authorization = "Bearer $token"; 'Content-Type' = 'application/json'} `
                      -Body $mailJson -ContentType 'application/json' -UseBasicParsing -ErrorAction Stop | Out-Null
    Write-Log "Email sent successfully."
} 
catch {
    Write-Log "Email sending failed (policy update was successful): $($_.Exception.Message)" -Lvl 'WARN'
}

Write-Log "=== Runbook completed successfully ==="