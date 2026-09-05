#Requires -Version 5.1
<#
.SYNOPSIS
    Clones a Windows 11 template on Proxmox, prepares Windows and imports
    the device into Windows Autopilot.

.DESCRIPTION
    This Azure Automation runbook creates a full clone of a Windows 11
    template on Proxmox, configures the virtual hardware, expands the system
    disk, prepares Windows Recovery, retrieves the hardware hash through the
    QEMU Guest Agent and imports the device into the Windows Autopilot Database.

.AUTHOR
    Maurice Flöthmann

.COPYRIGHT
    © 2026 Maurice Flöthmann (mo-cloud.de)

.LICENSE
    This script is provided for personal and internal company use only.
    Redistribution or commercial use without explicit permission is prohibited.

    Questions or support requests: ask@mo-cloud.de

.NOTES
    Required Azure Automation variables:
    PVE_HOST, PVE_PORT, PVE_API_TOKEN_ID, PVE_API_TOKEN_SECRET, PVE_TEMPLATE_ID

    Optional Azure Automation variables:
    PVE_TARGET_NODE, PVE_TARGET_STORAGE, PVE_CERT_THUMBPRINT,
    PVE_VALIDATE_CERTIFICATE (default: true)
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 64)][int]$Cores = 4,
    [ValidateRange(4, 256)][int]$MemoryGB = 8,
    [ValidateRange(32, 4096)][int]$DiskSizeGB = 128
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ============================================================
# SCRIPT STATE
# ============================================================

$script:LogRoot = 'C:\ProgramData\AzureAutomation\Proxmox'
$script:LogFile = Join-Path $script:LogRoot ('ProvisionWindows11_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$script:PveUrl = $null
$script:PveHeaders = $null
$started = Get-Date
$createdVmId = $null
$targetNode = $null
$certificateCallbackChanged = $false
$previousCertificateCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
$script:PveCertificateThumbprint = $null
$script:StepNumber = 0
$script:CurrentStep = 'Initialization'
$script:RunId = [guid]::NewGuid().ToString('N').Substring(0, 12).ToUpperInvariant()

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Log {
    <#
    .DESCRIPTION
        Writes a timestamped message to the Azure Automation output and log file.
    #>
    param([Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')][string]$Level = 'INFO')
    $elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
    $entry = '[{0}] [{1}] [+{2}s] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $elapsed, $Message
    if ($Level -eq 'WARNING') { Write-Warning $entry }
    elseif ($Level -eq 'ERROR') { Write-Host $entry -ForegroundColor Red }
    else { Write-Host $entry }
    try {
        if (-not (Test-Path -LiteralPath $script:LogRoot)) {
            New-Item $script:LogRoot -ItemType Directory -Force | Out-Null
        }
        Add-Content -LiteralPath $script:LogFile -Value $entry -Encoding UTF8
    }
    catch { Write-Warning "Log write failed: $($_.Exception.Message)" }
}

function Write-Step {
    <#
    .DESCRIPTION
        Starts and logs a numbered runbook step.
    #>
    param([Parameter(Mandatory)][string]$Message)
    $script:StepNumber++
    $script:CurrentStep = $Message
    Write-Log ("========== STEP {0}: {1} ==========" -f $script:StepNumber, $Message)
}

function Get-RequiredVariable {
    <#
    .DESCRIPTION
        Retrieves and validates a required Azure Automation variable.
    #>
    param([string]$Name)
    $value = Get-AutomationVariable -Name $Name
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
        throw "Azure Automation variable '$Name' is missing or empty."
    }
    return $value
}

function Get-OptionalVariable {
    <#
    .DESCRIPTION
        Retrieves an optional Azure Automation variable.
    #>
    param([string]$Name)
    try { return [string](Get-AutomationVariable -Name $Name -ErrorAction Stop) }
    catch { return '' }
}

function Get-SafePropertyValue {
    <#
    .DESCRIPTION
        Safely reads a property and returns a fallback value when unavailable.
    #>
    param([object]$Object, [string]$Name, [string]$Default = '<not set>')
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return [string]$property.Value
}

function Get-PrimaryVmDisk {
    <#
    .DESCRIPTION
        Identifies the primary operating system disk in a Proxmox VM configuration.
    #>
    param([Parameter(Mandatory)][object]$Config)

    $diskNames = @($Config.PSObject.Properties.Name | Where-Object {
            $_ -match '^(scsi|sata|virtio|ide)\d+$'
        })

    $bootOrder = @()
    if ($Config.PSObject.Properties.Name -contains 'boot' -and $Config.boot -match 'order=([^,]+)') {
        $bootOrder = @($Matches[1] -split ';')
    }

    $orderedCandidates = @($bootOrder + $diskNames | Select-Object -Unique)
    foreach ($name in $orderedCandidates) {
        if ($diskNames -notcontains $name) { continue }
        $value = [string]$Config.$name
        if ($value -match 'media=cdrom' -or $value -match 'cloudinit') { continue }
        return $name
    }

    throw 'Unable to identify the primary VM disk from the cloned configuration.'
}

function Invoke-Pve {
    <#
    .DESCRIPTION
        Calls the Proxmox API with logging, timeout handling and safe retries.
    #>
    param(
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE')][string]$Method,
        [string]$Path, [hashtable]$Body, [hashtable]$Query,
        [switch]$Json, [ValidateRange(1, 10)][int]$Attempts = 4,
        [ValidateRange(3, 300)][int]$TimeoutSeconds = 5
    )
    $url = "$script:PveUrl/api2/json$Path"
    if ($Query) {
        $pairs = @($Query.Keys | Where-Object { $null -ne $Query[$_] } | ForEach-Object {
                '{0}={1}' -f [uri]::EscapeDataString([string]$_),
                [uri]::EscapeDataString([string]$Query[$_])
            })
        if ($pairs.Count) { $url += '?' + ($pairs -join '&') }
    }
    for ($try = 1; $try -le $Attempts; $try++) {
        $requestTimer = [Diagnostics.Stopwatch]::StartNew()
        $bodyKeys = if ($Body) { @($Body.Keys | Sort-Object) -join ',' } else { 'none' }
        $queryKeys = if ($Query) { @($Query.Keys | Sort-Object) -join ',' } else { 'none' }
        Write-Log "PVE-API START method=$Method path=$Path attempt=$try/$Attempts bodyKeys=[$bodyKeys] queryKeys=[$queryKeys] timeout=${TimeoutSeconds}s keepAlive=false"
        try {
            $p = @{ Uri = $url; Method = $Method; Headers = $script:PveHeaders
                ErrorAction = 'Stop'; UseBasicParsing = $true; TimeoutSec = $TimeoutSeconds
                DisableKeepAlive = $true 
            }
            if ($Body) {
                if ($Json) {
                    $p.ContentType = 'application/json'
                    $p.Body = $Body | ConvertTo-Json -Depth 10 -Compress
                }
                else {
                    $p.ContentType = 'application/x-www-form-urlencoded'
                    $p.Body = $Body
                }
            }
            $apiResult = (Invoke-RestMethod @p).data
            $requestTimer.Stop()
            $resultType = if ($null -eq $apiResult) { 'null' } else { $apiResult.GetType().FullName }
            $resultCount = if ($apiResult -is [array]) { $apiResult.Count } else { 1 }
            Write-Log "PVE-API OK method=$Method path=$Path durationMs=$($requestTimer.ElapsedMilliseconds) resultType=$resultType resultCount=$resultCount" SUCCESS
            return $apiResult
        }
        catch {
            $requestTimer.Stop()
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            $apiDetails = ''
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $apiDetails = ([string]$_.ErrorDetails.Message).Trim()
            }
            # Only retry idempotent requests automatically. Retrying POST can
            # create the same VM or start the same operation more than once.
            $retryableMethod = $Method -in @('GET', 'PUT')
            $retry = $retryableMethod -and ($code -eq 0 -or $code -in 408, 429 -or $code -ge 500)
            Write-Log "PVE-API ERROR method=$Method path=$Path durationMs=$($requestTimer.ElapsedMilliseconds) http=$code retryable=$retry exceptionType=$($_.Exception.GetType().FullName)" WARNING
            if (-not $retry -or $try -eq $Attempts) {
                if ($code -eq 401) {
                    throw "Proxmox rejected the API token (HTTP 401). Verify PVE_API_TOKEN_ID (user@realm!tokenname), PVE_API_TOKEN_SECRET, token status and expiration."
                }
                if ($apiDetails) {
                    throw "Proxmox $Method $Path failed (HTTP $code): $apiDetails"
                }
                throw "Proxmox $Method $Path failed (HTTP $code): $($_.Exception.Message)"
            }
            $retryDelay = [int][math]::Min(30, [math]::Pow(2, $try))
            Write-Log "Temporary Proxmox connection error (HTTP $code): $($_.Exception.Message). Retrying in $retryDelay seconds." WARNING
            Start-Sleep -Seconds $retryDelay
        }
    }
}

function Wait-PveTask {
    <#
    .DESCRIPTION
        Waits for a Proxmox task and validates its final exit status.
    #>
    param([string]$Node, [string]$Upid, [int]$TimeoutSeconds = 1800)
    $end = (Get-Date).AddSeconds($TimeoutSeconds)
    $id = [uri]::EscapeDataString($Upid)
    $poll = 0
    Write-Log "Waiting for Proxmox task. Timeout: $TimeoutSeconds seconds."
    while ((Get-Date) -lt $end) {
        $poll++
        $s = Invoke-Pve GET "/nodes/$Node/tasks/$id/status"
        if ($s.status -eq 'stopped') {
            if ($s.exitstatus -eq 'OK') {
                Write-Log 'Proxmox task completed successfully.' SUCCESS
                return
            }
            throw "Proxmox task failed: $($s.exitstatus)"
        }
        if ($poll -eq 1 -or ($poll % 10) -eq 0) {
            Write-Log "Proxmox task is still running (status: $($s.status))."
        }
        Start-Sleep 3
    }
    throw "Proxmox task timed out. UPID: $Upid"
}

function Wait-GuestAgent {
    <#
    .DESCRIPTION
        Waits until the QEMU Guest Agent responds reliably.
    #>
    param([string]$Node, [int]$VmId)
    $startedWaiting = Get-Date
    $end = (Get-Date).AddMinutes(15)
    $attempt = 0
    $consecutiveSuccesses = 0
    Write-Log 'Waiting for QEMU Guest Agent. Timeout: 15 minutes.'
    while ((Get-Date) -lt $end) {
        $attempt++
        $elapsedSeconds = [int]((Get-Date) - $startedWaiting).TotalSeconds
        $remainingSeconds = [math]::Max(0, [int]($end - (Get-Date)).TotalSeconds)
        try {
            $vmStatus = Invoke-Pve GET "/nodes/$Node/qemu/$VmId/status/current" -Attempts 2 -TimeoutSeconds 10
            Write-Log "Guest Agent wait attempt ${attempt}: VM status='$(Get-SafePropertyValue $vmStatus 'status')', uptime=$(Get-SafePropertyValue $vmStatus 'uptime')s, elapsed=${elapsedSeconds}s, remaining=${remainingSeconds}s."
        }
        catch {
            Write-Log "Guest Agent wait attempt ${attempt}: unable to read VM status: $($_.Exception.Message)" WARNING
        }
        try {
            Invoke-Pve POST "/nodes/$Node/qemu/$VmId/agent/ping" -Attempts 1 -TimeoutSeconds 10 | Out-Null
            $consecutiveSuccesses++
            Write-Log "QEMU Guest Agent ping succeeded (attempt $attempt; stable responses $consecutiveSuccesses/3)."
            if ($consecutiveSuccesses -ge 3) {
                Write-Log "QEMU Guest Agent is stable after attempt $attempt." SUCCESS
                return
            }
            Start-Sleep 3
        }
        catch {
            $consecutiveSuccesses = 0
            Write-Log "QEMU Guest Agent is not ready (attempt $attempt, elapsed=${elapsedSeconds}s). Proxmox response: $($_.Exception.Message). Next check in 10 seconds." WARNING
            Start-Sleep 10
        }
    }
    throw "QEMU Guest Agent for VM $VmId was unavailable after 15 minutes. Verify that the QEMU Guest Agent is installed in Windows, its service start type is Automatic, and the Proxmox VM option 'QEMU Guest Agent' is enabled."
}

function Invoke-GuestPowerShell {
    <#
    .DESCRIPTION
        Executes PowerShell inside Windows through the QEMU Guest Agent.
    #>
    param([string]$Node, [int]$VmId, [string]$Script)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
    Write-Log 'Submitting PowerShell command to the Windows guest.'
    try {
        $exec = Invoke-Pve POST "/nodes/$Node/qemu/$VmId/agent/exec" -Json -Attempts 1 -TimeoutSeconds 60 -Body @{
            command = @('powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
        }
    }
    catch {
        throw "Unable to submit PowerShell to QEMU Guest Agent within 60 seconds. The command was not retried because its execution state is unknown: $($_.Exception.Message)"
    }
    if (-not $exec.pid) { throw 'Guest Agent returned no PID.' }
    Write-Log "Guest PowerShell process started with PID $($exec.pid)."
    $end = (Get-Date).AddMinutes(15)
    $poll = 0
    while ((Get-Date) -lt $end) {
        $poll++
        Start-Sleep 2
        $s = Invoke-Pve GET "/nodes/$Node/qemu/$VmId/agent/exec-status" -TimeoutSeconds 15 -Query @{pid = $exec.pid }
        if ($s.exited) {
            if ([int]$s.exitcode -ne 0) { throw "Guest command failed: $($s.'err-data')" }
            Write-Log 'Guest PowerShell process completed successfully.' SUCCESS
            return [string]$s.'out-data'
        }
        if (($poll % 15) -eq 0) {
            Write-Log 'Guest PowerShell process is still running.'
        }
    }
    throw 'Guest command timed out.'
}

function Invoke-Graph {
    <#
    .DESCRIPTION
        Calls Microsoft Graph with consistent error handling and logging.
    #>
    param([string]$Method, [string]$Uri, [hashtable]$Headers, [object]$Body)
    for ($try = 1; $try -le 4; $try++) {
        $requestTimer = [Diagnostics.Stopwatch]::StartNew()
        $bodyState = if ($null -eq $Body) { 'none' } else { 'present-redacted' }
        Write-Log "GRAPH START method=$Method uri=$Uri attempt=$try/4 body=$bodyState timeout=120s"
        try {
            $p = @{Uri = $Uri; Method = $Method; Headers = $Headers; ErrorAction = 'Stop'
                UseBasicParsing = $true; TimeoutSec = 120
            }
            if ($null -ne $Body) {
                $p.ContentType = 'application/json'
                $p.Body = $Body | ConvertTo-Json -Depth 10 -Compress
            }
            $graphResult = Invoke-RestMethod @p
            $requestTimer.Stop()
            Write-Log "GRAPH OK method=$Method uri=$Uri durationMs=$($requestTimer.ElapsedMilliseconds)" SUCCESS
            return $graphResult
        }
        catch {
            $requestTimer.Stop()
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            Write-Log "GRAPH ERROR method=$Method uri=$Uri durationMs=$($requestTimer.ElapsedMilliseconds) http=$code exceptionType=$($_.Exception.GetType().FullName)" WARNING
            if ($try -eq 4 -or -not ($code -eq 0 -or $code -in 408, 429 -or $code -ge 500)) { throw }
            Start-Sleep -Seconds ([math]::Min(30, [math]::Pow(2, $try)))
        }
    }
}

function Get-AutomationManagedIdentityToken {
    <#
    .DESCRIPTION
        Requests a Microsoft Graph token from the Hybrid Worker's managed identity endpoint.
    #>
    param([Parameter(Mandatory)][string]$Resource)

    if ([string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT)) {
        throw 'IDENTITY_ENDPOINT is not available. Verify that the Automation Account system-assigned Managed Identity is enabled and that this job runs on the configured Hybrid Worker.'
    }
    if ([string]::IsNullOrWhiteSpace($env:IDENTITY_HEADER)) {
        throw 'IDENTITY_HEADER is not available. Azure Automation did not inject the Managed Identity authentication header into this job.'
    }

    $separator = if ($env:IDENTITY_ENDPOINT.Contains('?')) { '&' } else { '?' }
    $tokenUri = $env:IDENTITY_ENDPOINT + $separator +
    'resource=' + [uri]::EscapeDataString($Resource) +
    '&api-version=2019-08-01'
    $headers = @{'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER }

    for ($attempt = 1; $attempt -le 4; $attempt++) {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        Write-Log "IDENTITY START resource=$Resource attempt=$attempt/4 timeout=60s. Authentication header is redacted."
        try {
            $response = Invoke-RestMethod `
                -Uri $tokenUri `
                -Method GET `
                -Headers $headers `
                -UseBasicParsing `
                -DisableKeepAlive `
                -TimeoutSec 60 `
                -ErrorAction Stop
            $timer.Stop()
            $accessToken = Get-SafePropertyValue $response 'access_token' ''
            if ([string]::IsNullOrWhiteSpace($accessToken)) {
                throw 'Managed Identity endpoint returned no access_token.'
            }
            Write-Log "IDENTITY OK resource=$Resource durationMs=$($timer.ElapsedMilliseconds), tokenLength=$($accessToken.Length). Token content is not logged." SUCCESS
            return $accessToken
        }
        catch {
            $timer.Stop()
            $statusCode = 0
            if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
            Write-Log "IDENTITY ERROR resource=$Resource durationMs=$($timer.ElapsedMilliseconds) http=$statusCode exceptionType=$($_.Exception.GetType().FullName)." WARNING
            if ($attempt -eq 4 -or ($statusCode -ne 0 -and $statusCode -notin 408, 429 -and $statusCode -lt 500)) {
                throw "Managed Identity token request failed: $($_.Exception.Message)"
            }
            Start-Sleep -Seconds ([math]::Min(30, [math]::Pow(2, $attempt)))
        }
    }
}

# ============================================================
# MAIN EXECUTION
# ============================================================

Write-Log "=== Runbook started ==="

try {
    Write-Log "Provisioning started. RunId=$script:RunId"
    Write-Log "Hybrid Worker: $env:COMPUTERNAME; PowerShell: $($PSVersionTable.PSVersion); PID: $PID."
    Write-Log "Runtime details: OS=$([Environment]::OSVersion.VersionString); 64BitProcess=$([Environment]::Is64BitProcess); user=$([Environment]::UserName)."
    Write-Log "Requested VM sizing: $Cores CPU cores, $MemoryGB GB RAM and $DiskSizeGB GB system disk."
    Write-Log "Log file: $script:LogFile"
    Write-Step 'Validate local prerequisites'
    Write-Log 'No Az.Accounts or AzureRM modules are required; Azure authentication uses the Automation Managed Identity REST endpoint.' SUCCESS

    Write-Step 'Load Azure Automation variables'
    $hostName = ([string](Get-RequiredVariable PVE_HOST)).Trim()
    $portText = ([string](Get-RequiredVariable PVE_PORT)).Trim()
    $tokenId = ([string](Get-RequiredVariable PVE_API_TOKEN_ID)).Trim()
    $tokenSecret = ([string](Get-RequiredVariable PVE_API_TOKEN_SECRET)).Trim()
    $templateText = ([string](Get-RequiredVariable PVE_TEMPLATE_ID)).Trim()
    $targetNode = Get-OptionalVariable PVE_TARGET_NODE
    $storage = Get-OptionalVariable PVE_TARGET_STORAGE
    $certificateThumbprint = (Get-OptionalVariable PVE_CERT_THUMBPRINT) -replace '[^A-Fa-f0-9]', ''
    $validateCertificateText = Get-OptionalVariable PVE_VALIDATE_CERTIFICATE
    $validateCertificate = $true

    if (-not [string]::IsNullOrWhiteSpace($validateCertificateText)) {
        if (-not [bool]::TryParse($validateCertificateText.Trim(), [ref]$validateCertificate)) {
            throw "PVE_VALIDATE_CERTIFICATE must be either 'true' or 'false'."
        }
    }

    $port = 0; $templateId = 0
    if (-not [int]::TryParse($portText, [ref]$port) -or $port -notin 1..65535) {
        throw 'PVE_PORT is invalid.'
    }
    if (-not [int]::TryParse($templateText, [ref]$templateId) -or $templateId -lt 100) {
        throw 'PVE_TEMPLATE_ID is invalid.'
    }
    if ($hostName -notmatch '^[A-Za-z0-9.-]+$') { throw 'PVE_HOST is invalid.' }
    if ($tokenId -notmatch '^[^@!\s]+@[^@!\s]+![^=!\s]+$') {
        throw "PVE_API_TOKEN_ID has an invalid format. Expected: user@realm!tokenname (without 'PVEAPIToken=' and without the secret)."
    }
    if ($tokenSecret -notmatch '^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$') {
        throw "PVE_API_TOKEN_SECRET is invalid (length: $($tokenSecret.Length)). Expected only the 36-character UUID secret, without quotes, prefix or invisible characters."
    }

    Write-Log "Variables validated. Proxmox: $hostName`:$port; template: $templateId; certificate validation: $validateCertificate."
    Write-Log "Optional destination settings: targetNode='$(if ($targetNode) {$targetNode} else {'<template node>'})'; targetStorage='$(if ($storage) {$storage} else {'<template/default>'})'; certificateThumbprintConfigured=$([bool]$certificateThumbprint)."
    Write-Step 'Configure TLS certificate handling'
    if (-not $validateCertificate) {
        if (-not ('PveTlsCertificateValidator' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class PveTlsCertificateValidator
{
    public static bool DisableValidation { get; set; }
    public static string ExpectedThumbprint { get; set; }

    public static bool Validate(
        object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors errors)
    {
        if (DisableValidation)
            return true;

        if (certificate == null || String.IsNullOrWhiteSpace(ExpectedThumbprint))
            return false;

        return String.Equals(
            certificate.GetCertHashString(),
            ExpectedThumbprint,
            StringComparison.OrdinalIgnoreCase);
    }
}
'@
        }
        [PveTlsCertificateValidator]::DisableValidation = $true
        [PveTlsCertificateValidator]::ExpectedThumbprint = $null
        $validationMethod = [PveTlsCertificateValidator].GetMethod('Validate')
        $validationDelegate = [Delegate]::CreateDelegate(
            [Net.Security.RemoteCertificateValidationCallback],
            $validationMethod
        )
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $validationDelegate
        $certificateCallbackChanged = $true
        Write-Log 'WARNING: Proxmox TLS certificate validation is disabled by PVE_VALIDATE_CERTIFICATE.' WARNING
    }
    elseif ($certificateThumbprint) {
        if ($certificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
            throw 'PVE_CERT_THUMBPRINT must be a 40-character SHA-1 certificate thumbprint.'
        }
        if (-not ('PveTlsCertificateValidator' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class PveTlsCertificateValidator
{
    public static bool DisableValidation { get; set; }
    public static string ExpectedThumbprint { get; set; }

    public static bool Validate(
        object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors errors)
    {
        if (DisableValidation)
            return true;

        if (certificate == null || String.IsNullOrWhiteSpace(ExpectedThumbprint))
            return false;

        return String.Equals(
            certificate.GetCertHashString(),
            ExpectedThumbprint,
            StringComparison.OrdinalIgnoreCase);
    }
}
'@
        }
        $script:PveCertificateThumbprint = $certificateThumbprint.ToUpperInvariant()
        [PveTlsCertificateValidator]::DisableValidation = $false
        [PveTlsCertificateValidator]::ExpectedThumbprint = $script:PveCertificateThumbprint
        $validationMethod = [PveTlsCertificateValidator].GetMethod('Validate')
        $validationDelegate = [Delegate]::CreateDelegate(
            [Net.Security.RemoteCertificateValidationCallback],
            $validationMethod
        )
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $validationDelegate
        $certificateCallbackChanged = $true
        Write-Log 'Proxmox TLS certificate pinning is enabled.'
    }

    $script:PveUrl = 'https://{0}:{1}' -f $hostName, $port
    $script:PveHeaders = @{Authorization = "PVEAPIToken=$tokenId=$tokenSecret" }
    Write-Step 'Connect and authenticate to Proxmox'
    Write-Log "Using Proxmox token '$tokenId' with a $($tokenSecret.Length)-character secret."
    $version = Invoke-Pve GET '/version'
    Write-Log "Connected to Proxmox version=$(Get-SafePropertyValue $version 'version'), release=$(Get-SafePropertyValue $version 'release'), repositoryId=$(Get-SafePropertyValue $version 'repoid')." SUCCESS

    Write-Step 'Locate Windows template'
    $resources = @(Invoke-Pve GET '/cluster/resources' -Query @{type = 'vm' })
    Write-Log "Proxmox returned $($resources.Count) VM resources visible to this token."
    if ($resources.Count -eq 0) {
        throw "Proxmox returned no visible VMs or templates. The token '$tokenId' is authenticated but has no effective VM permissions. Configure an ACL for its user or token."
    }
    $template = $resources | Where-Object { [int]$_.vmid -eq $templateId } | Select-Object -First 1
    if (-not $template) {
        throw "Template $templateId was not found among the $($resources.Count) VM resources visible to token '$tokenId'. Verify the template ID and Proxmox ACLs."
    }
    if (-not [bool]$template.template) { throw "VM $templateId is not a template." }
    $sourceNode = [string]$template.node
    if ([string]::IsNullOrWhiteSpace($targetNode)) { $targetNode = $sourceNode }
    Write-Log "Template found: ID $templateId, name '$($template.name)', node '$sourceNode'." SUCCESS
    Write-Log "Template runtime state: status='$(Get-SafePropertyValue $template 'status')', maxDisk=$(Get-SafePropertyValue $template 'maxdisk'), maxMemory=$(Get-SafePropertyValue $template 'maxmem')."

    Write-Step 'Allocate VM identity and create full clone'
    $vmId = [int](Invoke-Pve GET '/cluster/nextid')
    # Proxmox 9 validates SMBIOS serial values more strictly. Keep the value
    # purely alphanumeric so it is accepted by the smbios1 property schema.
    $serial = 'PROX' + [guid]::NewGuid().ToString('N').Substring(0, 12).ToUpperInvariant()
    $uuid = [guid]::NewGuid().ToString()
    $clone = @{newid = [string]$vmId; name = $serial; full = '1' }
    if ($targetNode) { $clone.target = $targetNode }
    if ($storage) { $clone.storage = $storage }

    Write-Log "Allocated identity: vmId=$vmId; vmName=$serial; smbiosUuid=$uuid."
    Write-Log "Clone request: sourceNode=$sourceNode; templateId=$templateId; targetNode=$targetNode; targetStorage='$(if ($storage) {$storage} else {'<default>'})'; full=1."
    Write-Log "Cloning template $templateId to VM $vmId ($serial) as full clone."
    $task = Invoke-Pve POST "/nodes/$sourceNode/qemu/$templateId/clone" -Attempts 1 -TimeoutSeconds 60 -Body $clone
    if (-not $task) { throw 'Clone request returned no task ID.' }
    Wait-PveTask $sourceNode $task 3600
    $createdVmId = $vmId
    Write-Log "Full clone VM $vmId was created successfully." SUCCESS

    Write-Step 'Wait for cloned VM to become available'
    $found = $false
    1..30 | ForEach-Object {
        if (-not $found) {
            Write-Log "VM availability check $_/30 for VM $vmId on node '$targetNode'."
            try { Invoke-Pve GET "/nodes/$targetNode/qemu/$vmId/config" -Attempts 1 | Out-Null; $found = $true }
            catch { Write-Log "VM $vmId configuration not visible yet: $($_.Exception.Message)" WARNING; Start-Sleep 2 }
        }
    }
    if (-not $found) { throw "VM $vmId is not available on node $targetNode." }

    Write-Step 'Resize cloned system disk'
    $clonedConfig = Invoke-Pve GET "/nodes/$targetNode/qemu/$vmId/config"
    $systemDisk = Get-PrimaryVmDisk -Config $clonedConfig
    $systemDiskConfig = [string]$clonedConfig.$systemDisk
    Write-Log "Detected primary system disk '$systemDisk': $systemDiskConfig"
    Write-Log "Boot configuration: $(Get-SafePropertyValue $clonedConfig 'boot')"

    $currentDiskSizeGB = $null
    if ($systemDiskConfig -match '(?:^|,)size=([0-9]+(?:\.[0-9]+)?)([KMGT])(?:,|$)') {
        $sizeValue = [double]$Matches[1]
        $sizeUnit = $Matches[2]
        $currentDiskSizeGB = switch ($sizeUnit) {
            'K' { $sizeValue / 1MB }
            'M' { $sizeValue / 1KB }
            'G' { $sizeValue }
            'T' { $sizeValue * 1024 }
        }
    }

    if ($null -ne $currentDiskSizeGB -and $DiskSizeGB -lt $currentDiskSizeGB) {
        throw "Requested disk size $DiskSizeGB GB is smaller than the cloned disk size $currentDiskSizeGB GB. Proxmox disks cannot be shrunk."
    }
    if ($null -ne $currentDiskSizeGB -and [math]::Abs($DiskSizeGB - $currentDiskSizeGB) -lt 0.01) {
        Write-Log "System disk already has the requested size of $DiskSizeGB GB; resize skipped."
    }
    else {
        if ($null -ne $currentDiskSizeGB) {
            $growByMB = [int][math]::Ceiling(($DiskSizeGB - $currentDiskSizeGB) * 1024)
            $resizeValue = "+$growByMB`M"
            Write-Log "Growing '$systemDisk' from $currentDiskSizeGB GB by $growByMB MB to approximately $DiskSizeGB GB."
        }
        else {
            $resizeValue = "$DiskSizeGB`G"
            Write-Log "Current disk size could not be parsed; requesting absolute size $resizeValue for '$systemDisk'." WARNING
        }
        Invoke-Pve PUT "/nodes/$targetNode/qemu/$vmId/resize" -Attempts 1 -TimeoutSeconds 30 -Body @{
            disk = $systemDisk
            size = $resizeValue
        } | Out-Null

        $resizeVerified = $false
        $resizedSizeGB = $null
        $resizedDiskValue = $systemDiskConfig
        for ($resizeCheck = 1; $resizeCheck -le 15; $resizeCheck++) {
            Start-Sleep -Seconds 2
            Write-Log "Disk resize verification $resizeCheck/15 for '$systemDisk'."
            $resizedConfig = Invoke-Pve GET "/nodes/$targetNode/qemu/$vmId/config"
            $resizedDiskValue = [string]$resizedConfig.$systemDisk
            if ($resizedDiskValue -match '(?:^|,)size=([0-9]+(?:\.[0-9]+)?)([KMGT])(?:,|$)') {
                $resizedValue = [double]$Matches[1]
                $resizedUnit = $Matches[2]
                $resizedSizeGB = switch ($resizedUnit) {
                    'K' { $resizedValue / 1MB }
                    'M' { $resizedValue / 1KB }
                    'G' { $resizedValue }
                    'T' { $resizedValue * 1024 }
                }
                Write-Log "Reported '$systemDisk' size after resize: $resizedSizeGB GB."
                if ($resizedSizeGB -ge ($DiskSizeGB - 0.01)) {
                    $resizeVerified = $true
                    break
                }
            }
        }
        if (-not $resizeVerified) {
            throw "Disk resize did not reach the requested $DiskSizeGB GB within 30 seconds. Current '$systemDisk' configuration: $resizedDiskValue"
        }
        Write-Log "System disk '$systemDisk' resized and verified at $resizedSizeGB GB." SUCCESS
    }

    Write-Step 'Configure and verify VM hardware identity'
    Write-Log "Applying $Cores cores, $MemoryGB GB RAM, UUID '$uuid' and serial '$serial'."
    Invoke-Pve PUT "/nodes/$targetNode/qemu/$vmId/config" -TimeoutSeconds 30 -Body @{
        cores   = $Cores
        memory  = ($MemoryGB * 1024)
        smbios1 = "uuid=$uuid,serial=$serial"
        agent   = 'enabled=1'
    } | Out-Null
    $cfg = Invoke-Pve GET "/nodes/$targetNode/qemu/$vmId/config"
    Write-Log "Verification values: name='$(Get-SafePropertyValue $cfg 'name')'; cores='$(Get-SafePropertyValue $cfg 'cores')'; memoryMiB='$(Get-SafePropertyValue $cfg 'memory')'; agent='$(Get-SafePropertyValue $cfg 'agent')'; smbios1='$(Get-SafePropertyValue $cfg 'smbios1')'."
    if ((Get-SafePropertyValue $cfg 'agent') -notmatch 'enabled=1|^1$') {
        throw "Proxmox QEMU Guest Agent option could not be enabled. Current value: '$(Get-SafePropertyValue $cfg 'agent')'."
    }
    if ($cfg.name -ne $serial -or $cfg.smbios1 -notmatch [regex]::Escape("serial=$serial")) {
        throw 'VM identity verification failed.'
    }
    Write-Log 'VM configuration and SMBIOS identity verified.' SUCCESS

    Write-Step 'Start virtual machine'
    $task = Invoke-Pve POST "/nodes/$targetNode/qemu/$vmId/status/start" -Attempts 1 -TimeoutSeconds 30
    if ($task) { Wait-PveTask $targetNode $task 600 }
    Write-Log "VM $vmId started successfully." SUCCESS

    Write-Step 'Wait for QEMU Guest Agent'
    Wait-GuestAgent $targetNode $vmId

    Write-Step 'Expand Windows system partition'
    Write-Log 'Checking whether Windows partition C: can use the enlarged virtual disk.'
    $partitionResizeCode = @'
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

$partition=Get-Partition -DriveLetter C -ErrorAction Stop
$beforeBytes=[uint64]$partition.Size
$disk=Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
$recoveryRemoved=$false
$recoveryCreated=$false
$winREDisabled=$false
$winREEnabled=$false
$supported=Get-PartitionSupportedSize `
    -DiskNumber $partition.DiskNumber `
    -PartitionNumber $partition.PartitionNumber `
    -ErrorAction Stop

$expanded=$false
$message='Partition C: already uses all directly available space.'

# First use the normal, non-destructive expansion path.
if ([uint64]$supported.SizeMax -gt ($beforeBytes + 64MB)) {
    Resize-Partition `
        -DiskNumber $partition.DiskNumber `
        -PartitionNumber $partition.PartitionNumber `
        -Size ([uint64]$supported.SizeMax) `
        -ErrorAction Stop
    $expanded=$true
    $message='Partition C: was expanded to the maximum supported size.'
}

# If C: is still much smaller than the virtual disk, inspect every partition
# behind it. Only a partition positively identified as Windows Recovery may be
# removed. EFI, MSR, data and unknown partitions are never touched.
$partition=Get-Partition -DriveLetter C -ErrorAction Stop
$remainingGap=[int64]$disk.Size-[int64]($partition.Offset+$partition.Size)
if (-not $expanded -and $remainingGap -gt 1GB) {
    $partitionsBehindC=@(Get-Partition -DiskNumber $partition.DiskNumber | Where-Object {
        $_.PartitionNumber -ne $partition.PartitionNumber -and
        [uint64]$_.Offset -gt [uint64]$partition.Offset
    })

    $recoveryGuid='DE94BBA4-06D1-4D40-A16A-BFD50179D6AC'
    $recoveryPartitions=@($partitionsBehindC | Where-Object {
        $_.Type -eq 'Recovery' -or ([string]$_.GptType).Trim('{}').ToUpperInvariant() -eq $recoveryGuid
    })
    $unsafePartitions=@($partitionsBehindC | Where-Object {
        -not ($_.Type -eq 'Recovery' -or ([string]$_.GptType).Trim('{}').ToUpperInvariant() -eq $recoveryGuid)
    })

    if ($unsafePartitions.Count -gt 0) {
        $description=($unsafePartitions | ForEach-Object {
            "partition=$($_.PartitionNumber),type=$($_.Type),gpt=$($_.GptType),sizeMB=$([math]::Round($_.Size/1MB,0))"
        }) -join '; '
        throw "C: cannot be expanded safely because a non-Recovery partition is located behind it: $description"
    }

    if ($recoveryPartitions.Count -eq 0) {
        throw 'C: cannot be expanded and no removable Windows Recovery partition was found behind it.'
    }
    if ($disk.PartitionStyle -ne 'GPT') {
        throw "Automatic WinRE recreation requires a GPT disk. Detected partition style: $($disk.PartitionStyle)."
    }

    & reagentc.exe /disable | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "reagentc /disable failed with exit code $LASTEXITCODE."
    }
    $winREDisabled=$true
    $winRESource=Join-Path $env:SystemRoot 'System32\Recovery\Winre.wim'
    if (-not (Test-Path -LiteralPath $winRESource)) {
        throw "WinRE image '$winRESource' was not available after reagentc /disable. The existing Recovery partition was preserved."
    }

    foreach ($recoveryPartition in $recoveryPartitions) {
        Remove-Partition `
            -DiskNumber $recoveryPartition.DiskNumber `
            -PartitionNumber $recoveryPartition.PartitionNumber `
            -Confirm:$false `
            -ErrorAction Stop
        $recoveryRemoved=$true
    }

    Update-HostStorageCache
    Start-Sleep -Seconds 2
    $partition=Get-Partition -DriveLetter C -ErrorAction Stop
    $supported=Get-PartitionSupportedSize `
        -DiskNumber $partition.DiskNumber `
        -PartitionNumber $partition.PartitionNumber `
        -ErrorAction Stop

    if ([uint64]$supported.SizeMax -le ([uint64]$partition.Size+64MB)) {
        throw 'Recovery partition was removed, but Windows still reports no expandable space behind C:.'
    }

    $recoverySizeBytes=[uint64](1GB)
    $targetCSize=[uint64]$supported.SizeMax-$recoverySizeBytes
    if ($targetCSize -le [uint64]$partition.Size) {
        throw 'There is not enough free space to expand C: and reserve 1 GB for a new Recovery partition.'
    }

    Resize-Partition `
        -DiskNumber $partition.DiskNumber `
        -PartitionNumber $partition.PartitionNumber `
        -Size $targetCSize `
        -ErrorAction Stop
    $expanded=$true

    Update-HostStorageCache
    $newRecovery=New-Partition `
        -DiskNumber $partition.DiskNumber `
        -UseMaximumSize `
        -AssignDriveLetter `
        -ErrorAction Stop
    $recoveryCreated=$true
    $recoveryDrive="$($newRecovery.DriveLetter):"
    Format-Volume `
        -DriveLetter $newRecovery.DriveLetter `
        -FileSystem NTFS `
        -NewFileSystemLabel 'Windows RE tools' `
        -Confirm:$false `
        -Force `
        -ErrorAction Stop | Out-Null

    $winRETarget=Join-Path $recoveryDrive 'Recovery\WindowsRE'
    New-Item -Path $winRETarget -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $winRESource -Destination (Join-Path $winRETarget 'Winre.wim') -Force

    & reagentc.exe /setreimage /path $winRETarget /target "$env:SystemDrive\Windows" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "reagentc /setreimage failed with exit code $LASTEXITCODE."
    }
    & reagentc.exe /enable | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "reagentc /enable failed with exit code $LASTEXITCODE."
    }
    $winREEnabled=$true

    Remove-PartitionAccessPath `
        -DiskNumber $newRecovery.DiskNumber `
        -PartitionNumber $newRecovery.PartitionNumber `
        -AccessPath "$recoveryDrive\" `
        -ErrorAction Stop
    Set-Partition `
        -DiskNumber $newRecovery.DiskNumber `
        -PartitionNumber $newRecovery.PartitionNumber `
        -GptType '{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}' `
        -NoDefaultDriveLetter $true `
        -ErrorAction Stop

    $message='C: was expanded and a new 1 GB Windows Recovery partition was created with WinRE enabled.'
}

$partition=Get-Partition -DriveLetter C -ErrorAction Stop
$disk=Get-Disk -Number $partition.DiskNumber -ErrorAction Stop

if ([uint64]$partition.Size -lt ([uint64]$disk.Size-2GB)) {
    throw "C: remains unexpectedly small after expansion. CBytes=$($partition.Size); DiskBytes=$($disk.Size)."
}

[pscustomobject]@{
    Expanded=$expanded
    RecoveryRemoved=$recoveryRemoved
    RecoveryCreated=$recoveryCreated
    WinREDisabled=$winREDisabled
    WinREEnabled=$winREEnabled
    BeforeGB=[math]::Round($beforeBytes/1GB,2)
    AfterGB=[math]::Round(([uint64]$partition.Size)/1GB,2)
    DiskGB=[math]::Round(([uint64]$disk.Size)/1GB,2)
    SupportedMaxGB=[math]::Round(([uint64]$supported.SizeMax)/1GB,2)
    Message=$message
} | ConvertTo-Json -Compress
'@
    $partitionResizeRaw = Invoke-GuestPowerShell $targetNode $vmId $partitionResizeCode
    try { $partitionResizeResult = $partitionResizeRaw.Trim() | ConvertFrom-Json }
    catch { throw "Invalid partition resize response from Windows: $partitionResizeRaw" }

    if ([bool]$partitionResizeResult.Expanded) {
        Write-Log "Windows C: expanded from $($partitionResizeResult.BeforeGB) GB to $($partitionResizeResult.AfterGB) GB (virtual disk: $($partitionResizeResult.DiskGB) GB)." SUCCESS
        if ([bool]$partitionResizeResult.RecoveryRemoved) {
            if ([bool]$partitionResizeResult.RecoveryCreated -and [bool]$partitionResizeResult.WinREEnabled) {
                Write-Log 'The blocking Recovery partition was replaced by a new 1 GB Recovery partition and Windows RE was enabled successfully.' SUCCESS
            }
            else {
                Write-Log 'The old Recovery partition was removed, but WinRE recreation did not complete.' WARNING
            }
        }
    }
    elseif ([double]$partitionResizeResult.AfterGB -lt ([double]$partitionResizeResult.DiskGB - 2)) {
        Write-Log "Windows C: could not be expanded beyond $($partitionResizeResult.AfterGB) GB although the virtual disk has $($partitionResizeResult.DiskGB) GB. Another partition, commonly WinRE/Recovery, is probably located behind C:." WARNING
    }
    else {
        Write-Log "Windows C: already uses the available disk space ($($partitionResizeResult.AfterGB) GB)." SUCCESS
    }

    Write-Step 'Collect Windows Autopilot hardware hash'
    Write-Log 'PHASE DEVICE-1/4: Initializing Windows device-management components.'
    $mdmInitCode = @'
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$dmService=Get-Service -Name 'dmwappushservice' -ErrorAction SilentlyContinue
if ($dmService -and $dmService.Status -ne 'Running') {
    Start-Service -Name 'dmwappushservice' -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}
[pscustomobject]@{
    ServiceExists=[bool]$dmService
    ServiceStatus=if ($dmService) {(Get-Service -Name 'dmwappushservice').Status.ToString()} else {'NotInstalled'}
    ComputerName=$env:COMPUTERNAME
    WindowsBuild=(Get-CimInstance Win32_OperatingSystem).BuildNumber
} | ConvertTo-Json -Compress
'@
    $mdmInitRaw = Invoke-GuestPowerShell $targetNode $vmId $mdmInitCode
    try { $mdmInit = $mdmInitRaw.Trim() | ConvertFrom-Json }
    catch { throw "Invalid MDM initialization response from Windows: $mdmInitRaw" }
    Write-Log "PHASE DEVICE-1/4 COMPLETE: computer='$($mdmInit.ComputerName)', WindowsBuild=$($mdmInit.WindowsBuild), dmwappushservice='$($mdmInit.ServiceStatus)'." SUCCESS

    Write-Log 'PHASE DEVICE-2/4: Waiting for the Windows MDM bridge and DeviceHardwareData. Maximum: 60 attempts / approximately 12 minutes including Guest Agent overhead.'
    $guest = $null
    $lastMdmError = $null
    for ($mdmAttempt = 1; $mdmAttempt -le 60; $mdmAttempt++) {
        Write-Log "PHASE DEVICE-2/4: Querying MDM bridge, attempt $mdmAttempt/60."
        $mdmQueryCode = @'
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
    $bios=Get-CimInstance Win32_BIOS -ErrorAction Stop
    $allDetails=@(Get-CimInstance `
            -Namespace 'root/cimv2/mdm/dmmap' `
            -ClassName 'MDM_DevDetail_Ext01' `
            -ErrorAction Stop)
    $detail=$allDetails | Where-Object {
        ([string]$_.InstanceID).Trim() -eq 'Ext' -and
        ([string]$_.ParentID).Trim().TrimEnd('/') -eq './DevDetail'
    } | Select-Object -First 1
    $available=($detail -and -not [string]::IsNullOrWhiteSpace($detail.DeviceHardwareData))
    $observedInstances=($allDetails | ForEach-Object {
        "InstanceID='$($_.InstanceID)', ParentID='$($_.ParentID)', HashLength=$(([string]$_.DeviceHardwareData).Length)"
    }) -join '; '
    [pscustomobject]@{
        Available=$available
        SerialNumber=$bios.SerialNumber.Trim()
        HardwareHash=if ($available) {[string]$detail.DeviceHardwareData} else {$null}
        Error=if ($available) {$null} elseif (-not $detail) {"No matching DevDetail instance. Observed: $observedInstances"} else {'MDM bridge responded, but DeviceHardwareData is still empty.'}
    } | ConvertTo-Json -Compress
}
catch {
    [pscustomobject]@{
        Available=$false
        SerialNumber=$null
        HardwareHash=$null
        Error=$_.Exception.Message
    } | ConvertTo-Json -Compress
}
'@
        $mdmQueryRaw = Invoke-GuestPowerShell $targetNode $vmId $mdmQueryCode
        try { $mdmQuery = $mdmQueryRaw.Trim() | ConvertFrom-Json }
        catch { throw "Invalid MDM query response from Windows: $mdmQueryRaw" }

        if ([bool]$mdmQuery.Available) {
            $guest = $mdmQuery
            Write-Log "PHASE DEVICE-2/4 COMPLETE: Hardware hash is available after attempt $mdmAttempt. Hash content is intentionally not logged." SUCCESS
            break
        }
        $lastMdmError = [string]$mdmQuery.Error
        Write-Log "PHASE DEVICE-2/4 WAITING: MDM data is not ready. Reason: $lastMdmError. Next attempt in 10 seconds." WARNING
        Start-Sleep -Seconds 10
    }

    if ($null -eq $guest) {
        throw "Autopilot hardware hash remained unavailable after 60 attempts. Last MDM response: $lastMdmError"
    }

    Write-Log 'PHASE DEVICE-3/4: Validating SMBIOS serial returned by Windows.'
    if ($guest.SerialNumber -cne $serial) {
        throw "Guest serial '$($guest.SerialNumber)' does not match '$serial'."
    }
    Write-Log "PHASE DEVICE-3/4 COMPLETE: Windows serial '$serial' matches the Proxmox configuration." SUCCESS
    Write-Log 'PHASE DEVICE-4/4 COMPLETE: Device inventory collection is finished; proceeding to Azure authentication.' SUCCESS

    Write-Step 'Authenticate to Azure with Managed Identity'
    Write-Log 'Requesting a Microsoft Graph token directly from the Azure Automation Managed Identity endpoint. No Az modules will be loaded.'
    $token = Get-AutomationManagedIdentityToken -Resource 'https://graph.microsoft.com/'
    Write-Log 'Automation Account system-assigned Managed Identity token acquired successfully.' SUCCESS

    Write-Step 'Submit device to Windows Autopilot'
    $headers = @{Authorization = "Bearer $token" }
    $body = @{
        '@odata.type' = '#microsoft.graph.importedWindowsAutopilotDeviceIdentity'
        serialNumber = $serial; hardwareIdentifier = $guest.HardwareHash
    }
    $uri = 'https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities'
    $import = Invoke-Graph POST $uri $headers $body
    if (-not $import.id) { throw 'Graph returned no Autopilot import ID.' }
    Write-Log "Autopilot import submitted. Import ID: $($import.id)." SUCCESS

    Write-Step 'Monitor Windows Autopilot import'
    Write-Log 'Waiting up to 20 minutes for Microsoft Graph to complete the import.'
    $end = (Get-Date).AddMinutes(20); $complete = $false
    while ((Get-Date) -lt $end) {
        Start-Sleep 15
        $state = Invoke-Graph GET "$uri/$($import.id)" $headers $null
        $status = [string]$state.state.deviceImportStatus
        Write-Log "Autopilot status: $status"
        if ($status -eq 'complete') { $complete = $true; break }
        if ($status -eq 'error') {
            throw "Autopilot failed: $($state.state.deviceErrorCode) $($state.state.deviceErrorName)"
        }
    }
    if (-not $complete) { Write-Log 'Autopilot is still processing after 20 minutes.' WARNING }

    $restartScheduled = $false
    if ($complete) {
        Write-Step 'Restart Windows to retrieve the Autopilot profile'
        Write-Log 'Autopilot import is complete. Waiting 30 seconds for service-side propagation before rebooting the VM through Proxmox.'
        Start-Sleep -Seconds 30
        Write-Log "Sending Proxmox reboot request for VM $vmId on node '$targetNode'."
        $rebootTask = Invoke-Pve POST "/nodes/$targetNode/qemu/$vmId/status/reboot" -Attempts 1 -TimeoutSeconds 30
        if ($rebootTask) {
            Write-Log "Proxmox accepted the reboot request. Waiting for task '$rebootTask'."
            Wait-PveTask $targetNode $rebootTask 600
        }
        else {
            Write-Log 'Proxmox accepted the reboot request without returning a task ID.' WARNING
        }
        $restartScheduled = $true
        Write-Log "VM $vmId was rebooted through Proxmox. Windows OOBE can now query the Autopilot service for its profile." SUCCESS
    }
    else {
        Write-Log 'Windows restart skipped because the Autopilot import did not reach status complete.' WARNING
    }

    Write-Step 'Finish and return provisioning result'
    $seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
    Write-Log "Provisioning completed for VM $vmId." SUCCESS
    if ($certificateCallbackChanged) {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCertificateCallback
    }
    [pscustomobject]@{
        Success = $true; VMName = $serial; VMID = $vmId; ProxmoxNode = $targetNode
        Cores = $Cores; MemoryGB = $MemoryGB; DiskSizeGB = $DiskSizeGB
        AutopilotImportID = $import.id; AutopilotCompleted = $complete
        RestartScheduled = $restartScheduled; RuntimeSeconds = $seconds
    }
}
catch {
    if ($certificateCallbackChanged) {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCertificateCallback
    }
    Write-Log "FAILED during step $script:StepNumber ('$script:CurrentStep'): $($_.Exception.Message)" ERROR
    Write-Log "Exception type: $($_.Exception.GetType().FullName)" ERROR
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-Log "Failure location: $($_.InvocationInfo.PositionMessage.Trim())" ERROR
    }
    if ($_.ScriptStackTrace) {
        Write-Log "PowerShell stack trace: $($_.ScriptStackTrace)" ERROR
    }
    if ($createdVmId) {
        Write-Log "VM $createdVmId remains in place for diagnosis." WARNING
    }
    throw
}