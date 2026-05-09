#Requires -Version 5.1
<#
.SYNOPSIS
    Retrieves Microsoft 365 Service Health and Message Center announcements.
    Sends a detailed HTML report only when one or more services have issues
    (Degradation or Interruption). If all services are operational, no email is sent.

.AUTHOR
    Maurice Flöthmann

.COPYRIGHT
    © 2026 mo-cloud.de Maurice Flöthmann

.LICENSE
    This script is provided for personal and internal company use only.
    Redistribution or commercial use without explicit permission is prohibited.
   
    Questions or support requests: your.email@domain.com
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

# ============================================================
# MAIN EXECUTION
# ============================================================

Write-Log "=== Runbook started ==="

# Step 1: Configuration
Write-Log "--- Step 1: Configuration ---"
$RecipientEmail = Get-AzVar 'RecipientEmail'
$SenderEmail    = Get-AzVar 'SenderEmail'

Write-Log "Recipient : $RecipientEmail"
Write-Log "Sender    : $SenderEmail"

# Step 2: Authentication with Managed Identity
Write-Log "--- Step 2: Authentication ---"
Write-Log "Connecting using System-assigned Managed Identity..."
Connect-AzAccount -Identity | Out-Null

$token = (Get-AzAccessToken -ResourceTypeName MSGraph).Token

$headers = @{
    Authorization  = "Bearer $token"
    "Content-Type" = "application/json"
}

Write-Log "Successfully authenticated with Microsoft Graph (Managed Identity)"

# Step 3: Retrieve Service Health
Write-Log "--- Step 3: Retrieve Service Health ---"
$healthUrl = "https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/healthOverviews?`$expand=issues"
$healthOverviews = (Invoke-RestMethod -Uri $healthUrl -Headers $headers -Method Get).value

$problemServices = $healthOverviews | Where-Object { $_.status -ne "serviceOperational" }
$issueCount = $problemServices.Count

Write-Log "Total services checked: $($healthOverviews.Count) | Services with issues: $issueCount"

# Step 4: Decision - Send report only if issues exist
Write-Log "--- Step 4: Decision ---"
if ($issueCount -eq 0) {
    Write-Log "All Microsoft 365 services are operational. No notification will be sent."
    Write-Log "=== Runbook completed successfully ==="
    exit 0
}

Write-Log "Service issues detected ($issueCount). Proceeding with report generation." -Lvl 'WARN'

# Step 5: Retrieve recent Message Center messages
Write-Log "--- Step 5: Retrieve Message Center ---"
$filterDate = (Get-Date).AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$messagesUrl = "https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/messages?`$filter=startDateTime ge $filterDate&`$orderby=lastModifiedDateTime desc&`$top=30"
$messages = (Invoke-RestMethod -Uri $messagesUrl -Headers $headers -Method Get).value

Write-Log "Message Center entries retrieved: $($messages.Count)"

# Step 6: Build HTML Report
Write-Log "--- Step 6: Build HTML Report ---"

$html = @"
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background-color: #f9f9f9; }
        h1 { color: #d13438; border-bottom: 3px solid #d13438; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; }
        .summary { font-size: 18px; font-weight: bold; color: #d13438; background-color: #fff; padding: 15px; border-radius: 6px; border-left: 6px solid #d13438; margin: 20px 0; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; background-color: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #ddd; padding: 12px 10px; text-align: left; }
        th { background-color: #0078d4; color: white; }
        tr:nth-child(even) { background-color: #f8f8f8; }
        .critical { color: #d13438; font-weight: bold; }
        .warning { color: #ff8c00; font-weight: bold; }
        .service-name { font-weight: 600; }
    </style>
</head>
<body>
    <h1>Microsoft 365 Service Issues Detected</h1>
    <p><strong>Report Date:</strong> $(Get-Date -Format "dddd, dd. MMMM yyyy HH:mm") UTC</p>
    
    <div class="summary">
        Currently <strong>$issueCount</strong> Microsoft 365 service(s) are experiencing issues.
    </div>
"@

# Affected Services Table
$html += "<h2>Affected Services ($issueCount)</h2>"
$html += "<table><tr><th>Service</th><th>Status</th><th>Issues / Description</th></tr>"

foreach ($service in $problemServices) {
    $statusClass = if ($service.status -eq "serviceInterruption") { "critical" } else { "warning" }
    $statusText  = switch ($service.status) {
        "serviceDegradation"  { "Degraded" }
        "serviceInterruption" { "Service Interruption" }
        default               { $service.status }
    }
    
    $issues = if ($service.issues) { 
                ($service.issues | ForEach-Object { "• $($_.title)" }) -join "<br>" 
              } else { "No detailed issues available" }
    
    $html += "<tr><td class='service-name'>$($service.service)</td><td class='$statusClass'>$statusText</td><td>$issues</td></tr>"
}
$html += "</table>"

# Message Center Table
if ($messages) {
    $html += "<h2>Recent Message Center Announcements (last 7 days)</h2>"
    $html += "<table><tr><th>ID</th><th>Title</th><th>Category</th><th>Severity</th><th>Start Date</th><th>Affected Services</th></tr>"
    
    foreach ($msg in $messages) {
        $services = if ($msg.services) { $msg.services -join ", " } else { "—" }
        $start = if ($msg.startDateTime) { (Get-Date $msg.startDateTime).ToString("dd.MM.yyyy HH:mm") } else { "—" }
        
        $html += "<tr><td>$($msg.id)</td><td>$($msg.title)</td><td>$($msg.category)</td><td>$($msg.severity)</td><td>$start</td><td>$services</td></tr>"
    }
    $html += "</table>"
}

$html += "</body></html>"

# Step 7: Send Email
Write-Log "--- Step 7: Send Email ---"

$mailBody = @{
    message = @{
        subject = "Microsoft 365 Service Issues ($issueCount services affected) - $(Get-Date -Format 'dd.MM.yyyy')"
        body    = @{
            contentType = "HTML"
            content     = $html
        }
        toRecipients = @(@{ emailAddress = @{ address = $RecipientEmail } })
    }
    saveToSentItems = $false
} | ConvertTo-Json -Depth 10

$sendUrl = "https://graph.microsoft.com/v1.0/users/$SenderEmail/sendMail"

try {
    Invoke-RestMethod -Uri $sendUrl -Headers $headers -Method Post -Body $mailBody -ContentType "application/json" | Out-Null
    Write-Log "Email sent successfully to $RecipientEmail"
}
catch {
    Write-Log "Failed to send email: $($_.Exception.Message)" -Lvl 'ERROR'
    throw
}

Write-Log "=== Runbook completed successfully ==="