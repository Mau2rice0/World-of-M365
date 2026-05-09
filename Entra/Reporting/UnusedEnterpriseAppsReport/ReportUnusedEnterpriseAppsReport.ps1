#Requires -Version 5.1
<#
.SYNOPSIS
    Identifies inactive Enterprise Applications (Service Principals) in a Microsoft Entra ID tenant.
    Evaluates sign‑in activity from the last 30 days using Microsoft Graph (Beta) and sends
    an HTML report via email only when inactive applications are found.

.AUTHOR
    Maurice Flöthmann

.COPYRIGHT
    © 2026 mo-cloud.de Maurice Flöthmann

.LICENSE
    This script is provided for personal and internal company use only.
    Redistribution or commercial use without explicit permission is prohibited.

    Questions or support requests: ask@mo-cloud.de
#>

$ErrorActionPreference = 'Stop'

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    Write-Output ("[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.PadRight(5), $Message)
}

Write-Log "=== Runbook started ==="

$RecipientEmail = Get-AutomationVariable -Name 'RecipientEmail'
$SenderEmail = Get-AutomationVariable -Name 'SenderEmail'
Write-Log "Recipient : $RecipientEmail"
Write-Log "Sender : $SenderEmail"

Write-Log "--- Authentication ---"
Connect-AzAccount -Identity | Out-Null
$token = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
$headers = @{
    Authorization = "Bearer $token"
    "Content-Type" = "application/json"
}

$org = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/organization" -Headers $headers -Method GET
$tenantId = $org.value[0].id
Write-Log "Tenant ID: $tenantId"

Write-Log "--- Loading Service Principals ---"
$uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,displayName,appId,appOwnerOrganizationId,servicePrincipalType,createdDateTime,tags&`$top=999"
$allServicePrincipals = @()
$nextLink = $uri
while ($nextLink) {
    $response = Invoke-RestMethod -Uri $nextLink -Headers $headers -Method GET -ErrorAction Stop
    $allServicePrincipals += $response.value
    $nextLink = $response.'@odata.nextLink'
    Write-Log "Service Principals loaded: $($allServicePrincipals.Count)..."
}
Write-Log "Total Service Principals loaded: $($allServicePrincipals.Count)"

$myApps = $allServicePrincipals | Where-Object {
    $_.appOwnerOrganizationId -eq $tenantId -and
    $_.servicePrincipalType -eq "Application" -and
    $_.displayName -ne "P2P Server"
}
Write-Log "Self-created Enterprise Apps found: $($myApps.Count)"

Write-Log "--- Loading Sign-Ins (last 30 days) - Beta ---"
$startDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
$signInUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $startDate and (signInEventTypes/any(t: t eq 'servicePrincipal' or t eq 'nonInteractiveUser'))&$select=appId,createdDateTime,signInEventTypes&$top=999"
$allSignIns = @()
$nextLink = $signInUri
while ($nextLink) {
    $response = Invoke-RestMethod -Uri $nextLink -Headers $headers -Method GET -ErrorAction Stop
    $allSignIns += $response.value
    $nextLink = $response.'@odata.nextLink'
    Write-Log "Sign-Ins loaded: $($allSignIns.Count)..."
}
$usedAppIds = $allSignIns | Select-Object -ExpandProperty appId -Unique
Write-Log "Apps with sign-in activity in last 30 days: $($usedAppIds.Count)"

$inactiveApps = $myApps | Where-Object { $_.appId -notin $usedAppIds } |
    Select-Object displayName, appId, id, createdDateTime |
    Sort-Object createdDateTime -Descending
Write-Log "INACTIVE self-created Enterprise Apps found: $($inactiveApps.Count)" -Level $(if($inactiveApps.Count -gt 0){'WARN'}else{'INFO'})

$html = @"
<html>
<body style="font-family:Segoe UI, Arial, sans-serif; margin:30px;">
<h1 style="color:#d13438;">Inaktive Enterprise Apps</h1>
<p><strong>Report Date:</strong> $(Get-Date -Format "dd.MM.yyyy HH:mm")</p>
<p><strong>Inactive for more than 30 days:</strong> $($inactiveApps.Count)</p>
"@

if ($inactiveApps.Count -gt 0) {
    $html += "<table border='1' cellpadding='8' style='border-collapse:collapse;'><tr><th>DisplayName</th><th>App ID</th><th>Created</th></tr>"
    foreach ($app in $inactiveApps) {
        $created = if ($app.createdDateTime) { (Get-Date $app.createdDateTime).ToString("dd.MM.yyyy") } else { "N/A" }
        $html += "<tr><td>$($app.displayName)</td><td>$($app.appId)</td><td>$created</td></tr>"
    }
    $html += "</table>"
} else {
    $html += "<p><strong>No inactive self-created Enterprise Apps found.</strong></p>"
}

$html += "</body></html>"

$mailBody = @{
    message = @{
        subject = "Inaktive Enterprise Apps Report ($($inactiveApps.Count))"
        body = @{ contentType = "HTML"; content = $html }
        toRecipients = @(@{ emailAddress = @{ address = $RecipientEmail } })
    }
    saveToSentItems = $false
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$SenderEmail/sendMail" `
    -Headers $headers -Method Post -Body $mailBody -ContentType "application/json" | Out-Null

Write-Log "Email sent successfully"
Write-Log "=== Runbook completed successfully ==="
