#Requires -Version 7.0
<#
.SYNOPSIS
    M365 Compromise Response Console full-featured, cross-platform SOC interface (macOS + Windows).

.DESCRIPTION
    Local mini web server (built-in .NET HttpListener, no extra modules) + modern SOC web GUI.
    Login via client credentials in the GUI; the secret stays server-side in RAM.

    FEATURES
      Identity   : Devices, device details, roles & groups, MFA methods, OAuth apps
      Data       : SharePoint/OneDrive sites, modified files, external sharing links
      Comm.      : Mail, external mail (exfil), inbox rules, mailbox settings, Teams
      Security   : Sign-ins, login anomalies, Identity Protection, Defender alerts,
                   Conditional Access posture, client/legacy-auth fingerprints,
                   actions by user, app credential changes, permission changes
      Analysis   : Auto-triage (top findings), MITRE ATT&CK mapping, entity graph,
                   graphical timeline, IOC bundle, risk gauge, live full scan (progress),
                   threat-intel (Tor/anonymizer), mail report, evidence snapshot
      Response   : Containment (revoke sessions / disable account / password reset / delete rule),
                   guided IR playbook (NIST 800-61) with action log, live monitoring
      Comfort    : Permission preflight (app roles from token JWT), sortable/filterable tables,
                   case management (save/load locally), CSV/JSON/STIX/MISP/Markdown export,
                   PDF (print), light/dark theme

    GRAPH APPLICATION PERMISSIONS (Admin Consent):
      Read:   User.Read.All, Directory.Read.All, Device.Read.All,
              DeviceManagementManagedDevices.Read.All, Sites.Read.All, Files.Read.All,
              Mail.Read, MailboxSettings.Read, Mail.Send, AuditLog.Read.All,
              UserAuthenticationMethod.Read.All, Chat.Read.All,
              IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All,
              Policy.Read.All, SecurityAlert.Read.All
      Containment (optional): User.ReadWrite.All, MailboxSettings.ReadWrite

.PARAMETER Port       Local port (default 8723).
.PARAMETER NoBrowser  Do not open the browser automatically.

.EXAMPLE
    pwsh ./m365CompromiseResponseConsole.ps1

.AUTHOR
    Maurice Flöthmann

.COPYRIGHT
    © 2026 mo-cloud.de Maurice Flöthmann
#>

[CmdletBinding()]
param([int]$Port = 8723, [switch]$NoBrowser)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------
#  Global state
# ---------------------------------------------------------------------
$script:Token        = $null
$script:TokenExpiry  = [datetime]::MinValue
$script:Creds        = $null
$script:Region       = ''
$script:GrantedRoles = @()
$script:BaseUrl      = 'https://graph.microsoft.com/v1.0'
$script:MaxRetries   = 5
$script:SessionToken = [guid]::NewGuid().ToString('N')
$script:SpCache      = @{}
$script:TorCache     = $null
$script:TorCacheTime = [datetime]::MinValue

# ---------------------------------------------------------------------
#  Logging
# ---------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level='INFO')
    $line = "[{0}] [{1,-5}] {2}" -f (Get-Date).ToString('HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line -ForegroundColor Gray }
    }
}

# ---------------------------------------------------------------------
#  StrictMode-safe accessors
# ---------------------------------------------------------------------
function PV { param($obj,$name,$default=$null)
    if ($null -ne $obj -and $obj.PSObject.Properties[$name]) { return $obj.$name }; return $default }
function DV { param($d,$n,$def=$null)
    if ($null -ne $d -and $d.PSObject.Properties[$n]) { return $d.$n }; return $def }
function Esc-Filter { param([string]$v) ($v -replace "'", "''") }
function HtmlEnc { param($v) if ($null -eq $v){return ''}; [System.Net.WebUtility]::HtmlEncode([string]$v) }

# ---------------------------------------------------------------------
#  Token (with real error cause) + JWT roles
# ---------------------------------------------------------------------
function Get-TokenRoles { param([string]$Jwt)
    try {
        $p = $Jwt.Split('.')[1].Replace('-','+').Replace('_','/')
        switch ($p.Length % 4) { 2 {$p+='=='} 3 {$p+='='} }
        $obj = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
        return @(PV $obj 'roles')
    } catch { return @() }
}

function Get-ValidToken {
    if (-not $script:Creds) { throw 'Not connected. Please sign in first.' }
    if ($script:Token -and (Get-Date) -lt $script:TokenExpiry.AddMinutes(-2)) { return $script:Token }
    $body = @{ grant_type='client_credentials'; client_id=$script:Creds.ClientId
               client_secret=$script:Creds.Secret; scope='https://graph.microsoft.com/.default' }
    $uri = "https://login.microsoftonline.com/$($script:Creds.TenantId)/oauth2/v2.0/token"
    $resp = Invoke-RestMethod -Method Post -Uri $uri -Body $body `
        -ContentType 'application/x-www-form-urlencoded' -SkipHttpErrorCheck -StatusCodeVariable tsc
    if ($tsc -ge 200 -and $tsc -lt 300 -and $null -ne $resp -and $resp.PSObject.Properties['access_token']) {
        $script:Token       = $resp.access_token
        $script:TokenExpiry = (Get-Date).AddSeconds([int]$resp.expires_in)
        $script:GrantedRoles = @(Get-TokenRoles $resp.access_token)
        return $script:Token
    }
    $err  = [string](PV $resp 'error'); $desc = [string](PV $resp 'error_description')
    $code = if ($desc -match 'AADSTS\d+') { $Matches[0] } else { '' }
    $hint = switch -Regex ($code) {
        'AADSTS7000215' { 'Invalid client secret (wrong, expired or rotated).'; break }
        'AADSTS7000222' { 'Client secret has expired. Create a new secret.'; break }
        'AADSTS700016'  { 'App/client ID not found in this tenant.'; break }
        'AADSTS90002'   { 'Tenant not found - check the tenant ID.'; break }
        'AADSTS900023'  { 'Tenant ID invalid.'; break }
        'AADSTS7000216' { 'Invalid request - usually a wrong client-ID/secret combination.'; break }
        'AADSTS50012'   { 'Authentication failed (secret/certificate).'; break }
        'AADSTS70011'   { 'Invalid scope.'; break }
        default         { '' }
    }
    $sd = if ($desc) { ($desc -split "`r?`n")[0] } elseif ($err) { $err } else { 'No detail message from Azure AD.' }
    throw (("Token request failed (HTTP $tsc). $code $hint" + [Environment]::NewLine + $sd).Trim())
}

function Invoke-GraphRequest {
    param([Parameter(Mandatory)][string]$Uri,
          [ValidateSet('GET','POST','PATCH','DELETE')][string]$Method='GET',
          [object]$Body, [switch]$All, [switch]$Raw)
    $items = [System.Collections.Generic.List[object]]::new()
    $next  = $Uri
    do {
        $attempt = 0; $resp = $null
        do {
            $attempt++
            $headers = @{ Authorization = "Bearer $(Get-ValidToken)" }
            $p = @{ Method=$Method; Uri=$next; Headers=$headers; SkipHttpErrorCheck=$true
                    StatusCodeVariable='sc'; ResponseHeadersVariable='rh' }
            if ($Body) { $p.Body=$Body; $p.ContentType='application/json' }
            try { $resp = Invoke-RestMethod @p }
            catch {
                if ($attempt -ge $script:MaxRetries) { throw }
                Start-Sleep -Seconds ([math]::Min(60,[math]::Pow(2,$attempt))); continue
            }
            if ($sc -ge 200 -and $sc -lt 300) { break }
            if ($sc -eq 429 -or $sc -ge 500) {
                if ($attempt -ge $script:MaxRetries) { throw "Graph error $sc after $attempt attempts." }
                $wait = if ($rh.'Retry-After') { [int]$rh.'Retry-After'[0] } else { [int][math]::Pow(2,$attempt) }
                Write-Log "Throttling ($sc), waiting $wait s." 'WARN'; Start-Sleep -Seconds $wait; continue
            }
            $detail = try { ($resp | ConvertTo-Json -Depth 4 -Compress) } catch { '' }
            throw "Graph request failed ($sc): $detail"
        } while ($true)
        if ($Raw) { return $resp }
        if ($null -ne $resp -and $null -ne $resp.PSObject.Properties['value']) {
            if ($resp.value) { $items.AddRange(@($resp.value)) }
            $next = if ($All -and $resp.PSObject.Properties['@odata.nextLink']) { $resp.'@odata.nextLink' } else { $null }
        } else { return $resp }
    } while ($next)
    return $items
}

function Get-SearchHits { param($Resp)
    try { $c = $Resp.value[0].hitsContainers[0]
          if ($c -and $c.PSObject.Properties['hits'] -and $c.hits) { return @($c.hits) } } catch {}
    return @()
}
function Get-TenantRegion {
    try { $root = Invoke-GraphRequest "$($script:BaseUrl)/sites/root?`$select=siteCollection" -Raw
          $code = PV (PV $root 'siteCollection') 'dataLocationCode'
          if ($code) { return [string]$code } } catch { Write-Log "Region auto-detection failed." 'WARN' }
    return ''
}
function Resolve-Sp { param([string]$Id)
    if (-not $Id) { return '' }
    if ($script:SpCache.ContainsKey($Id)) { return $script:SpCache[$Id] }
    $name = $Id
    try { $sp = Invoke-GraphRequest "$($script:BaseUrl)/servicePrincipals/$Id" -Raw; $name = [string](PV $sp 'displayName' $Id) } catch {}
    $script:SpCache[$Id] = $name; return $name
}
function New-RandomPassword {
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ','abcdefghijkmnpqrstuvwxyz','23456789','!@#%^&*-_=+')
    $chars = @(); foreach ($s in $sets) { $chars += $s[(Get-Random -Maximum $s.Length)] }
    $all = -join $sets; for ($i=0;$i -lt 12;$i++) { $chars += $all[(Get-Random -Maximum $all.Length)] }
    -join ($chars | Sort-Object { Get-Random })
}
function Get-Distance { param($lat1,$lon1,$lat2,$lon2)
    $R=6371.0; $dLat=([double]$lat2-[double]$lat1)*[math]::PI/180; $dLon=([double]$lon2-[double]$lon1)*[math]::PI/180
    $a=[math]::Sin($dLat/2)*[math]::Sin($dLat/2)+[math]::Cos([double]$lat1*[math]::PI/180)*[math]::Cos([double]$lat2*[math]::PI/180)*[math]::Sin($dLon/2)*[math]::Sin($dLon/2)
    $R*2*[math]::Atan2([math]::Sqrt($a),[math]::Sqrt(1-$a)) }

# =====================================================================
#  Collectors - Identity
# =====================================================================
function Get-UserDevices { param([string]$UPN)
    $list=[System.Collections.Generic.List[object]]::new()
    try { $f=[uri]::EscapeDataString("userPrincipalName eq '$(Esc-Filter $UPN)'")
        foreach ($d in (Invoke-GraphRequest "$($script:BaseUrl)/deviceManagement/managedDevices?`$filter=$f" -All)) {
            $list.Add([ordered]@{ Name=(PV $d 'deviceName'); OS=("$(PV $d 'operatingSystem') $(PV $d 'osVersion')").Trim()
                                  LastActivity=(PV $d 'lastSyncDateTime'); Source='Intune' }) }
    } catch { Write-Log "Intune devices: $($_.Exception.Message)" 'WARN' }
    try { foreach ($d in (Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/ownedDevices" -All)) {
            $list.Add([ordered]@{ Name=(PV $d 'displayName'); OS=("$(PV $d 'operatingSystem') $(PV $d 'operatingSystemVersion')").Trim()
                                  LastActivity=(PV $d 'approximateLastSignInDateTime'); Source='Azure AD' }) }
    } catch { Write-Log "Azure AD devices: $($_.Exception.Message)" 'WARN' }
    @($list | Sort-Object Name -Unique)
}
function Get-DeviceDeep { param([string]$UPN)
    $list=[System.Collections.Generic.List[object]]::new()
    try { $f=[uri]::EscapeDataString("userPrincipalName eq '$(Esc-Filter $UPN)'")
        foreach ($d in (Invoke-GraphRequest "$($script:BaseUrl)/deviceManagement/managedDevices?`$filter=$f" -All)) {
            $list.Add([ordered]@{ Name=(PV $d 'deviceName'); OS=("$(PV $d 'operatingSystem') $(PV $d 'osVersion')").Trim()
                Compliance=(PV $d 'complianceState'); Encrypted=(PV $d 'isEncrypted'); Jailbreak=(PV $d 'jailBroken')
                Owner=(PV $d 'managedDeviceOwnerType'); Model=("$(PV $d 'manufacturer') $(PV $d 'model')").Trim()
                LastSync=(PV $d 'lastSyncDateTime') }) }
    } catch { Write-Log "Device Details: $($_.Exception.Message)" 'WARN' }
    @($list)
}
function Get-RolesGroups { param([string]$UPN)
    $out=[System.Collections.Generic.List[object]]::new()
    try { foreach ($g in (Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/transitiveMemberOf" -All)) {
        $t=[string](PV $g '@odata.type' '')
        if     ($t -match 'directoryRole') { $out.Add([ordered]@{ Type='ROLE';  Name=(PV $g 'displayName'); Detail=(PV $g 'description') }) }
        elseif ($t -match 'group')         { $out.Add([ordered]@{ Type='Group'; Name=(PV $g 'displayName'); Detail=(PV $g 'visibility') }) } }
    } catch { Write-Log "Roles/groups: $($_.Exception.Message)" 'WARN' }
    @($out | Sort-Object Type -Descending)
}
function Get-AuthMethods { param([string]$UPN)
    $out=[System.Collections.Generic.List[object]]::new()
    try { foreach ($m in (Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/authentication/methods" -All)) {
        $t=([string](PV $m '@odata.type' '')).Replace('#microsoft.graph.','').Replace('AuthenticationMethod','')
        $detail=PV $m 'phoneNumber'; if(-not $detail){$detail=PV $m 'displayName'}; if(-not $detail){$detail=PV $m 'emailAddress'}
        $out.Add([ordered]@{ Method=$t; Detail=$detail; Created=(PV $m 'createdDateTime') }) }
    } catch { Write-Log "MFA Methods: $($_.Exception.Message)" 'WARN' }
    @($out)
}
function Get-OAuthGrants { param([string]$UPN)
    $out=[System.Collections.Generic.List[object]]::new()
    try { foreach ($g in (Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/oauth2PermissionGrants" -All)) {
        $out.Add([ordered]@{ App=(Resolve-Sp ([string](PV $g 'clientId'))); Resource=(Resolve-Sp ([string](PV $g 'resourceId')))
                             Scope=(PV $g 'scope'); Type=("Delegated/" + [string](PV $g 'consentType')) }) }
    } catch { Write-Log "OAuth grants: $($_.Exception.Message)" 'WARN' }
    try { foreach ($a in (Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/appRoleAssignments" -All)) {
        $out.Add([ordered]@{ App=(PV $a 'resourceDisplayName'); Resource='(app role)'; Scope=([string](PV $a 'appRoleId')); Type='AppRoleAssignment' }) }
    } catch { Write-Log "AppRoleAssignments: $($_.Exception.Message)" 'WARN' }
    @($out)
}

# =====================================================================
#  Collectors - Data
# =====================================================================
function Get-UserSites { param([string]$UPN,[string]$Region)
    $sites=[System.Collections.Generic.List[object]]::new()
    try { $req=@{ entityTypes=@('site'); query=@{ queryString="author:$UPN OR editor:$UPN OR owner:$UPN" }; size=100 }
        if ($Region) { $req.region=$Region }
        $r=Invoke-GraphRequest "$($script:BaseUrl)/search/query" -Method POST -Body (@{requests=@($req)}|ConvertTo-Json -Depth 6) -Raw
        foreach ($hit in (Get-SearchHits $r)) { if ($hit.resource.webUrl) { $sites.Add([ordered]@{ Name=(PV $hit.resource 'name'); Url=(PV $hit.resource 'webUrl') }) } }
    } catch { Write-Log "Site search: $($_.Exception.Message)" 'WARN' }
    try { $drive=Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/drive" -Raw
        if (PV $drive 'webUrl') { $sites.Add([ordered]@{ Name='OneDrive for Business'; Url=(PV $drive 'webUrl') }) }
    } catch { Write-Log "OneDrive: $($_.Exception.Message)" 'WARN' }
    @($sites | Sort-Object Url -Unique)
}
function Get-ModifiedFiles { param([string]$UPN,[datetime]$Since,[string]$Region)
    $files=[System.Collections.Generic.List[object]]::new()
    try { $d=$Since.ToString('yyyy-MM-dd')
        $kql="(ModifiedBy:`"$UPN`" OR Author:`"$UPN`") AND LastModifiedTime>=$d"
        $req=@{ entityTypes=@('driveItem'); query=@{ queryString=$kql }; size=200; fields=@('name','webUrl','lastModifiedDateTime') }
        if ($Region) { $req.region=$Region }
        $r=Invoke-GraphRequest "$($script:BaseUrl)/search/query" -Method POST -Body (@{requests=@($req)}|ConvertTo-Json -Depth 6) -Raw
        foreach ($hit in (Get-SearchHits $r)) { $i=$hit.resource
            if (PV $i 'name') { $files.Add([ordered]@{ FileName=(PV $i 'name'); Modified=(PV $i 'lastModifiedDateTime'); Url=(PV $i 'webUrl') }) } }
    } catch { Write-Log "File search: $($_.Exception.Message)" 'WARN' }
    @($files | Sort-Object Modified -Descending)
}
function Get-SharingLinks { param([string]$UPN)
    $out=[System.Collections.Generic.List[object]]::new()
    try {
        foreach ($it in (Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/drive/root/children?`$top=200" -All)) {
            $id=PV $it 'id'; if (-not $id) { continue }
            try { foreach ($pm in (Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/drive/items/$id/permissions" -All)) {
                $link=PV $pm 'link'
                if ($link) { $out.Add([ordered]@{ File=(PV $it 'name'); LinkType=(PV $link 'type'); Scope=(PV $link 'scope')
                                                  Url=(PV $link 'webUrl') }) }
                elseif (PV $pm 'grantedToIdentitiesV2') { $g=@($pm.grantedToIdentitiesV2 | ForEach-Object { PV (PV $_ 'user') 'displayName' }) -join ', '
                    if ($g) { $out.Add([ordered]@{ File=(PV $it 'name'); LinkType='direkt'; Scope=$g; Url=(PV $it 'webUrl') }) } }
            } } catch {} }
    } catch { Write-Log "Sharing links (Files.Read.All?): $($_.Exception.Message)" 'WARN' }
    @($out)
}

# =====================================================================
#  Collectors - Communication
# =====================================================================
function Get-MailActivity { param([string]$UPN,[datetime]$Since)
    $mails=[System.Collections.Generic.List[object]]::new()
    $iso=$Since.ToString('yyyy-MM-ddTHH:mm:ssZ'); $sel='subject,receivedDateTime,sentDateTime,from,toRecipients'
    try { $f=[uri]::EscapeDataString("receivedDateTime ge $iso")
        foreach ($m in (Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/messages?`$filter=$f&`$select=$sel&`$orderby=receivedDateTime desc&`$top=100" -All)) {
            $mails.Add([ordered]@{ Date=(PV $m 'receivedDateTime'); Direction='Received'; Subject=(PV $m 'subject')
                                   Peer=(PV (PV (PV $m 'from') 'emailAddress') 'address') }) }
    } catch { Write-Log "Received mail: $($_.Exception.Message)" 'WARN' }
    try { $f=[uri]::EscapeDataString("sentDateTime ge $iso")
        foreach ($m in (Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/mailFolders/SentItems/messages?`$filter=$f&`$select=$sel&`$orderby=sentDateTime desc&`$top=100" -All)) {
            $to=@((PV $m 'toRecipients') | ForEach-Object { PV (PV $_ 'emailAddress') 'address' }) -join ', '
            $mails.Add([ordered]@{ Date=(PV $m 'sentDateTime'); Direction='Sent'; Subject=(PV $m 'subject'); Peer=$to }) }
    } catch { Write-Log "Sent mail: $($_.Exception.Message)" 'WARN' }
    @($mails | Sort-Object Date -Descending)
}
function Get-ExternalMail { param($Mails,[string]$UPN)
    $domain=($UPN -split '@')[-1]; $out=[System.Collections.Generic.List[object]]::new()
    foreach ($m in @($Mails | Where-Object { $_ -and $_.Direction -eq 'Sent' })) {
        $ext=@(($m.Peer -split ',\s*') | Where-Object { $_ -and ($_ -notlike "*@$domain") })
        if ($ext.Count) { $out.Add([ordered]@{ Date=$m.Date; Subject=$m.Subject; ExternalRecipients=($ext -join ', '); Count=$ext.Count }) } }
    @($out)
}
function Get-InboxRules { param([string]$UPN)
    $rules=[System.Collections.Generic.List[object]]::new()
    try { foreach ($r in (Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/mailFolders/inbox/messageRules" -All)) {
        $act=PV $r 'actions'; $fwd=@()
        if (PV $act 'forwardTo')             { $fwd += @($act.forwardTo | ForEach-Object { PV (PV $_ 'emailAddress') 'address' }) }
        if (PV $act 'redirectTo')            { $fwd += @($act.redirectTo | ForEach-Object { PV (PV $_ 'emailAddress') 'address' }) }
        if (PV $act 'forwardAsAttachmentTo') { $fwd += @($act.forwardAsAttachmentTo | ForEach-Object { PV (PV $_ 'emailAddress') 'address' }) }
        $rules.Add([ordered]@{ Rule=(PV $r 'displayName'); Enabled=(PV $r 'isEnabled'); ForwardTo=($fwd -join ', ')
                               Deletes=[bool](PV $act 'delete'); Id=(PV $r 'id') }) }
    } catch { Write-Log "Inbox Rules: $($_.Exception.Message)" 'WARN' }
    @($rules)
}
function Get-MailboxInfo { param([string]$UPN)
    $out=[System.Collections.Generic.List[object]]::new()
    try { $s=Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/mailboxSettings" -Raw; $ar=PV $s 'automaticRepliesSetting'
        $out.Add([ordered]@{ Setting='Automatic reply'; Value=(PV $ar 'status'); Detail=("External audience: " + [string](PV $ar 'externalAudience')) })
        $out.Add([ordered]@{ Setting='Time zone'; Value=(PV $s 'timeZone'); Detail=([string](PV (PV $s 'language') 'displayName')) })
        $out.Add([ordered]@{ Setting='Note'; Value='SMTP forwarding/delegation'; Detail='only via Exchange Online PowerShell (not Graph app-only)' })
    } catch { Write-Log "Mailbox Settings: $($_.Exception.Message)" 'WARN' }
    @($out)
}
function Get-TeamsActivity { param([string]$UPN)
    $out=[System.Collections.Generic.List[object]]::new()
    try { foreach ($c in (Invoke-GraphRequest "$($script:BaseUrl)/users/$UPN/chats?`$top=30&`$expand=lastMessagePreview" -All)) {
        $pb=PV (PV $c 'lastMessagePreview') 'body'
        $out.Add([ordered]@{ Type=(PV $c 'chatType'); Topic=(PV $c 'topic'); Updated=(PV $c 'lastUpdatedDateTime'); Preview=([string](PV $pb 'content')) }) }
    } catch { Write-Log "Teams Activity: $($_.Exception.Message)" 'WARN' }
    @($out | Sort-Object Updated -Descending)
}

# =====================================================================
#  Collectors - Security
# =====================================================================
function Get-SignIns { param([string]$UPN,[int]$Days=30)
    $si=[System.Collections.Generic.List[object]]::new()
    try { $since=(Get-Date).AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $f=[uri]::EscapeDataString("userPrincipalName eq '$(Esc-Filter $UPN)' and createdDateTime ge $since")
        foreach ($s in (Invoke-GraphRequest "$($script:BaseUrl)/auditLogs/signIns?`$filter=$f&`$top=200" -All)) {
            $loc=PV $s 'location'; $geo=PV $loc 'geoCoordinates'; $st=PV $s 'status'; $ec=[int](PV $st 'errorCode' 0)
            $city=PV $loc 'city'; $country=PV $loc 'countryOrRegion'
            $si.Add([ordered]@{ Time=(PV $s 'createdDateTime'); IP=(PV $s 'ipAddress'); Location=((@($city,$country)|Where-Object{$_}) -join ', ')
                App=(PV $s 'appDisplayName'); Client=(PV $s 'clientAppUsed'); Status=$(if($ec -eq 0){'OK'}else{"Error $ec"})
                Risk=(PV $s 'riskLevelDuringSignIn'); Country=$country; ErrCode=$ec; Lat=(PV $geo 'latitude'); Lon=(PV $geo 'longitude') }) }
    } catch { Write-Log "Sign-in logs: $($_.Exception.Message)" 'WARN' }
    @($si | Sort-Object Time -Descending)
}
function Get-Anomalies { param($SignIns,[string[]]$HomeCountries)
    $out=[System.Collections.Generic.List[object]]::new()
    $ok=@($SignIns | Where-Object { $_ -and $_.ErrCode -eq 0 -and $_.Time } | Sort-Object Time); $prev=$null
    foreach ($s in $ok) {
        if ($s.Country -and $s.Country -notin $HomeCountries) { $out.Add([ordered]@{ Kind='Foreign Country'; Time=$s.Time; Detail=("$($s.Location) / $($s.IP) / $($s.App)") }) }
        if ($prev -and $prev.Country -and $s.Country -and $prev.Country -ne $s.Country) {
            try { $dt=([datetime]::Parse($s.Time)-[datetime]::Parse($prev.Time)).TotalHours; $speed=$null
                if ($prev.Lat -and $prev.Lon -and $s.Lat -and $s.Lon -and $dt -gt 0) { $speed=[int]((Get-Distance $prev.Lat $prev.Lon $s.Lat $s.Lon)/$dt) }
                if ($dt -ge 0 -and $dt -lt 6) { $d="from $($prev.Country) to $($s.Country) in $([math]::Round($dt,1)) h"; if ($speed){$d+=" (~$speed km/h)"}
                    $out.Add([ordered]@{ Kind='Impossible Travel'; Time=$s.Time; Detail=$d }) } } catch {} }
        $prev=$s }
    @($out | Sort-Object Time -Descending)
}
function Get-ClientFingerprints { param($SignIns)
    $legacy='IMAP|POP|SMTP|ActiveSync|Other clients|AutoDiscover|Exchange Web Services|MAPI|Offline Address Book|Authenticated SMTP'
    $groups=@($SignIns | Where-Object { $_ -and $_.Client } | Group-Object Client)
    $out=[System.Collections.Generic.List[object]]::new()
    foreach ($g in $groups) { $isLeg = [bool]($g.Name -match $legacy)
        $out.Add([ordered]@{ Client=$g.Name; Count=$g.Count; LegacyAuth=$(if($isLeg){'YES'}else{'no'}) }) }
    @($out | Sort-Object Count -Descending)
}
function Get-RiskInfo { param([string]$UPN)
    $out=[System.Collections.Generic.List[object]]::new()
    try { $f=[uri]::EscapeDataString("userPrincipalName eq '$(Esc-Filter $UPN)'")
        foreach ($u in (Invoke-GraphRequest "$($script:BaseUrl)/identityProtection/riskyUsers?`$filter=$f" -All)) {
            $out.Add([ordered]@{ Kind='RiskyUser'; Level=(PV $u 'riskLevel'); State=(PV $u 'riskState'); Time=(PV $u 'riskLastUpdatedDateTime'); Detail=(PV $u 'riskDetail') }) }
    } catch { Write-Log "RiskyUsers: $($_.Exception.Message)" 'WARN' }
    try { $f=[uri]::EscapeDataString("userPrincipalName eq '$(Esc-Filter $UPN)'")
        foreach ($d in (Invoke-GraphRequest "$($script:BaseUrl)/identityProtection/riskDetections?`$filter=$f&`$top=100" -All)) {
            $loc=PV $d 'location'
            $out.Add([ordered]@{ Kind=([string](PV $d 'riskEventType')); Level=(PV $d 'riskLevel'); State=(PV $d 'riskState')
                                 Time=(PV $d 'activityDateTime'); Detail=("$(PV $d 'ipAddress') $(PV $loc 'countryOrRegion')") }) }
    } catch { Write-Log "RiskDetections: $($_.Exception.Message)" 'WARN' }
    @($out | Sort-Object Time -Descending)
}
function Get-SecurityAlerts { param([string]$UPN)
    $out=[System.Collections.Generic.List[object]]::new()
    try { foreach ($a in (Invoke-GraphRequest "$($script:BaseUrl)/security/alerts_v2?`$top=50&`$orderby=createdDateTime desc" -All)) {
        $blob=try{ $a | ConvertTo-Json -Depth 6 -Compress }catch{''}
        if ($blob -like "*$UPN*") { $out.Add([ordered]@{ Titel=(PV $a 'title'); Severity=(PV $a 'severity'); Status=(PV $a 'status')
                                                          Category=(PV $a 'category'); Created=(PV $a 'createdDateTime') }) } }
    } catch { Write-Log "Defender Alerts (SecurityAlert.Read.All?): $($_.Exception.Message)" 'WARN' }
    @($out)
}
function Get-CAPolicies {
    $out=[System.Collections.Generic.List[object]]::new()
    try { foreach ($p in (Invoke-GraphRequest "$($script:BaseUrl)/identity/conditionalAccess/policies" -All)) {
        $gc=PV $p 'grantControls'; $ctrl=@(PV $gc 'builtInControls') -join ', '
        $out.Add([ordered]@{ Name=(PV $p 'displayName'); Status=(PV $p 'state'); Controls=$ctrl }) }
    } catch { Write-Log "Conditional Access (Policy.Read.All?): $($_.Exception.Message)" 'WARN' }
    @($out)
}
function Get-ActionsBy { param([string]$UPN,[datetime]$Since)
    $out=[System.Collections.Generic.List[object]]::new()
    try { $iso=$Since.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $f=[uri]::EscapeDataString("activityDateTime ge $iso and initiatedBy/user/userPrincipalName eq '$(Esc-Filter $UPN)'")
        foreach ($a in (Invoke-GraphRequest "$($script:BaseUrl)/auditLogs/directoryAudits?`$filter=$f&`$top=200" -All)) {
            $tgt=@((PV $a 'targetResources') | ForEach-Object { PV $_ 'displayName' } | Where-Object { $_ }) -join ', '
            $out.Add([ordered]@{ Time=(PV $a 'activityDateTime'); Activity=(PV $a 'activityDisplayName'); Target=$tgt; Result=(PV $a 'result') }) }
    } catch { Write-Log "Actions by user: $($_.Exception.Message)" 'WARN' }
    @($out | Sort-Object Time -Descending)
}
function Get-AppCredChanges { param([datetime]$Since)
    $out=[System.Collections.Generic.List[object]]::new()
    try { $iso=$Since.ToString('yyyy-MM-ddTHH:mm:ssZ'); $f=[uri]::EscapeDataString("activityDateTime ge $iso")
        foreach ($a in (Invoke-GraphRequest "$($script:BaseUrl)/auditLogs/directoryAudits?`$filter=$f&`$top=500" -All)) {
            $act=[string](PV $a 'activityDisplayName' '')
            if ($act -match 'credential|secret|certificate|password|Add application|Update application|service principal|Consent|OAuth') {
                $by=PV (PV (PV $a 'initiatedBy') 'user') 'userPrincipalName'; if (-not $by) { $by=PV (PV (PV $a 'initiatedBy') 'app') 'displayName' }
                $tgt=@((PV $a 'targetResources') | ForEach-Object { PV $_ 'displayName' } | Where-Object { $_ }) -join ', '
                $out.Add([ordered]@{ Time=(PV $a 'activityDateTime'); Activity=$act; By=$by; Target=$tgt; Result=(PV $a 'result') }) } }
    } catch { Write-Log "App Credential Changes: $($_.Exception.Message)" 'WARN' }
    @($out | Sort-Object Time -Descending)
}
function Get-PermissionChanges { param([string]$UPN,[datetime]$Since)
    $audits=[System.Collections.Generic.List[object]]::new()
    try { $iso=$Since.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $f=[uri]::EscapeDataString("activityDateTime ge $iso and targetResources/any(t:t/userPrincipalName eq '$(Esc-Filter $UPN)')")
        foreach ($a in (Invoke-GraphRequest "$($script:BaseUrl)/auditLogs/directoryAudits?`$filter=$f&`$top=100" -All)) {
            $by=PV (PV (PV $a 'initiatedBy') 'user') 'userPrincipalName'; if (-not $by) { $by=PV (PV (PV $a 'initiatedBy') 'app') 'displayName' }
            $audits.Add([ordered]@{ Time=(PV $a 'activityDateTime'); Activity=(PV $a 'activityDisplayName'); By=$by; Result=(PV $a 'result') }) }
    } catch { Write-Log "Audit logs: $($_.Exception.Message)" 'WARN' }
    @($audits | Sort-Object Time -Descending)
}

# =====================================================================
#  Analysis
# =====================================================================
function Build-Timeline { param($SignIns,$Mails,$Files,$Audits,$ActionsBy)
    $ev=[System.Collections.Generic.List[object]]::new()
    foreach ($s in @($SignIns))   { if ($s) { $ev.Add([ordered]@{ Time=$s.Time; Type='Sign-In'; Description=("$($s.App) / $($s.IP) / $($s.Location) [$($s.Status)]") }) } }
    foreach ($m in @($Mails))     { if ($m) { $ev.Add([ordered]@{ Time=$m.Date; Type=("Mail-$($m.Direction)"); Description=("$($m.Subject)  ->  $($m.Peer)") }) } }
    foreach ($f in @($Files))     { if ($f) { $ev.Add([ordered]@{ Time=$f.Modified; Type='File'; Description=$f.FileName }) } }
    foreach ($a in @($Audits))    { if ($a) { $ev.Add([ordered]@{ Time=$a.Time; Type='Audit'; Description=("$($a.Activity)  ($($a.By))") }) } }
    foreach ($a in @($ActionsBy)) { if ($a) { $ev.Add([ordered]@{ Time=$a.Time; Type='User-Action'; Description=("$($a.Activity)  ->  $($a.Target)") }) } }
    @($ev | Sort-Object { try { [datetime]::Parse($_.Time) } catch { [datetime]::MinValue } } -Descending)
}
function Build-IOCs { param($SignIns,$Mails,$OAuth,$Rules,[string]$UPN,[string[]]$HomeCountries)
    $out=[System.Collections.Generic.List[object]]::new()
    foreach ($s in @($SignIns)) { if ($s -and ($s.ErrCode -ne 0 -or ($s.Country -and $s.Country -notin $HomeCountries))) { if ($s.IP) { $out.Add([ordered]@{ Type='IP'; Value=$s.IP; Context=("$($s.Location) [$($s.Status)]") }) } } }
    foreach ($g in @($OAuth)) { if ($g -and $g.App) { $out.Add([ordered]@{ Type='OAuth-App'; Value=$g.App; Context=$g.Scope }) } }
    foreach ($r in @($Rules)) { if ($r -and $r.ForwardTo) { foreach ($t in ($r.ForwardTo -split ',\s*')) { if ($t) { $out.Add([ordered]@{ Type='Forwarding-Target'; Value=$t; Context=$r.Rule }) } } } }
    $domain=($UPN -split '@')[-1]
    foreach ($m in @($Mails | Where-Object { $_ -and $_.Direction -eq 'Sent' })) { foreach ($t in ($m.Peer -split ',\s*')) { if ($t -and $t -notlike "*@$domain") { $out.Add([ordered]@{ Type='External-Recipient'; Value=$t; Context=$m.Subject }) } } }
    @($out | Sort-Object Type,Value -Unique)
}
function Count-Suspicious { param([object[]]$SignIns,[string[]]$HomeCountries)
    if (-not $SignIns) { return 0 }
    @($SignIns | Where-Object { $_ -and ($_.ErrCode -ne 0 -or ($_.Risk -and $_.Risk -notin @('none','hidden')) -or ($_.Country -and $_.Country -notin $HomeCountries)) }).Count
}
function Get-RiskAssessment {
    param([int]$Files,[int]$SentMails,[int]$Suspicious,[int]$ForwardRules,[int]$AuditChanges,
          [int]$OAuthApps=0,[int]$Anomalies=0,[bool]$RiskyUser=$false,[int]$ExternalMails=0,
          [int]$ActionsByUser=0,[int]$Alerts=0,[int]$AnonShares=0)
    $score=0; $f=[System.Collections.Generic.List[string]]::new()
    if ($Files -gt 0)        { $score+=[math]::Min(20,[int]($Files/5)); $f.Add("$Files modified file(s)") }
    if ($SentMails -gt 0)    { $score+=[math]::Min(20,$SentMails);       $f.Add("$SentMails sent mail(s)") }
    if ($ExternalMails -gt 0){ $score+=[math]::Min(20,$ExternalMails*2);  $f.Add("$ExternalMails Mail(s) to external recipients") }
    if ($Suspicious -gt 0)   { $score+=[math]::Min(30,$Suspicious*6);    $f.Add("$Suspicious suspicious sign-in(s)") }
    if ($Anomalies -gt 0)    { $score+=[math]::Min(40,$Anomalies*15);    $f.Add("$Anomalies login anomaly(ies)") }
    if ($ForwardRules -gt 0) { $score+=40;                               $f.Add("$ForwardRules forwarding rule(s)") }
    if ($OAuthApps -gt 0)    { $score+=[math]::Min(25,$OAuthApps*5);     $f.Add("$OAuthApps OAuth app access(es)") }
    if ($ActionsByUser -gt 0){ $score+=[math]::Min(20,$ActionsByUser*2); $f.Add("$ActionsByUser action(s) by the account") }
    if ($AuditChanges -gt 0) { $score+=[math]::Min(15,$AuditChanges*5);  $f.Add("$AuditChanges permission change(s)") }
    if ($Alerts -gt 0)       { $score+=[math]::Min(45,$Alerts*15);       $f.Add("$Alerts Defender alert(s)") }
    if ($AnonShares -gt 0)   { $score+=[math]::Min(30,$AnonShares*10);   $f.Add("$AnonShares anonymous sharing link(s)") }
    if ($RiskyUser)          { $score+=40;                               $f.Add("Flagged as risky by Identity Protection") }
    $level = if ($score -ge 60){'HIGH'} elseif ($score -ge 25){'MEDIUM'} else {'LOW'}
    [pscustomobject]@{ Score=$score; Level=$level; Factors=@($f) }
}

# =====================================================================
#  MITRE ATT&CK Mapping
# =====================================================================
function Get-Sec { param($S,$n) if ($null -ne $S -and $S.Contains($n)) { @($S[$n]) } else { @() } }
function Build-AttackMapping { param($Sections,[datetime]$CompDate,[string[]]$HomeCountries)
    $rows=[System.Collections.Generic.List[object]]::new()
    $si    = Get-Sec $Sections 'Sign-In Logs'
    $rul   = Get-Sec $Sections 'Inbox Rules'
    $mfa   = Get-Sec $Sections 'MFA Methods'
    $appc  = Get-Sec $Sections 'App Credential Changes'
    $oauth = Get-Sec $Sections 'OAuth-Apps'
    $sit   = Get-Sec $Sections 'SharePoint / OneDrive'
    $fil   = Get-Sec $Sections 'Modified Files'
    $share = Get-Sec $Sections 'External Sharing Links'
    $mext  = Get-Sec $Sections 'External Mail'
    $fp    = Get-Sec $Sections 'Client/Legacy-Auth'
    $roles = Get-Sec $Sections 'Roles & Groups'
    $failed  = @($si | Where-Object { $_ -and $_.ErrCode -ne 0 }).Count
    $foreign = @($si | Where-Object { $_ -and $_.Country -and ($_.Country -notin $HomeCountries) }).Count
    $fwd     = @($rul | Where-Object { $_ -and [string]$_.ForwardTo -ne '' }).Count
    $del     = @($rul | Where-Object { $_ -and $_.Deletes }).Count
    $newMfa  = @($mfa | Where-Object { $_ -and $_.Created -and $CompDate -ne [datetime]::MinValue -and (($_.Created -as [datetime]) -ne $null) -and (($_.Created -as [datetime]) -gt $CompDate) }).Count
    $legacy  = @($fp | Where-Object { $_ -and $_.LegacyAuth -eq 'YES' }).Count
    $anon    = @($share | Where-Object { $_ -and $_.Scope -eq 'anonymous' }).Count
    $priv    = @($roles | Where-Object { $_ -and $_.Type -eq 'ROLE' }).Count
    $add = { param($tac,$id,$tech,$found,$sev) $rows.Add([ordered]@{ Tactic=$tac; TechniqueId=$id; Technique=$tech; Finding=$found; Severity=$sev }) }
    if ($foreign -gt 0)     { & $add 'Initial Access'       'T1078.004' 'Valid Accounts: Cloud Accounts'       "$foreign login(s) from non-home country" 'HIGH' }
    if ($failed  -gt 5)     { & $add 'Credential Access'    'T1110'     'Brute Force'                          "$failed failed sign-in(s)" 'MEDIUM' }
    if ($fwd     -gt 0)     { & $add 'Collection'           'T1114.003' 'Email Collection: Forwarding Rule'    "$fwd forwarding rule(s)" 'CRITICAL' }
    if ($del     -gt 0)     { & $add 'Defense Evasion'      'T1564.008' 'Hide Artifacts: Email Hiding Rules'   "$del deleting inbox rule(s)" 'HIGH' }
    if ($newMfa  -gt 0)     { & $add 'Persistence'          'T1556'     'Modify Authentication Process (MFA)'  "$newMfa new MFA method(s) after compromise" 'CRITICAL' }
    if ($appc.Count -gt 0)  { & $add 'Persistence'          'T1098.001' 'Additional Cloud Credentials'         "$($appc.Count) app credential change(s)" 'HIGH' }
    if ($oauth.Count -gt 0) { & $add 'Persistence'          'T1550.001' 'Use Alternate Auth: App Access Token' "$($oauth.Count) OAuth app access(es)" 'MEDIUM' }
    if ($legacy  -gt 0)     { & $add 'Defense Evasion'      'T1562'     'Impair Defenses: Legacy Auth'         "$legacy legacy auth client(s)" 'MEDIUM' }
    if (($sit.Count + $fil.Count) -gt 0) { & $add 'Collection' 'T1213' 'Data from Information Repositories'    "$($sit.Count) Site(s), $($fil.Count) file(s)" 'MEDIUM' }
    if ($anon -gt 0)        { & $add 'Exfiltration'         'T1537'     'Transfer Data to Cloud Account'       "$anon anonymous sharing link(s)" 'HIGH' }
    if ($mext.Count -gt 0)  { & $add 'Exfiltration'         'T1567'     'Exfiltration Over Web Service'        "$($mext.Count) Mail(s) to external recipients" 'HIGH' }
    if ($priv -gt 0)        { & $add 'Privilege Escalation' 'T1078'     'Valid Accounts (privileged)'        "Account holds $priv directory role(s)" 'HIGH' }
    @($rows)
}

# =====================================================================
#  Threat-Intel (Tor-Exit / Anonymizer)
# =====================================================================
function Get-TorExitNodes {
    if ($null -ne $script:TorCache -and ((Get-Date) - $script:TorCacheTime).TotalHours -lt 6) { return $script:TorCache }
    $set=[System.Collections.Generic.HashSet[string]]::new()
    foreach ($u in @('https://check.torproject.org/torbulkexitlist','https://www.dan.me.uk/torlist/?exit')) {
        try { $r=Invoke-RestMethod -Uri $u -TimeoutSec 12 -SkipHttpErrorCheck -StatusCodeVariable tsc
              if ($tsc -ge 200 -and $tsc -lt 300 -and $r) {
                  foreach ($ip in ([string]$r -split "`r?`n")) { $t=$ip.Trim(); if ($t -match '^\d{1,3}(\.\d{1,3}){3}$') { [void]$set.Add($t) } }
                  if ($set.Count -gt 0) { break } } }
        catch { Write-Log "Tor list $u unreachable." 'WARN' }
    }
    $script:TorCache=$set; $script:TorCacheTime=Get-Date
    Write-Log "Tor exit list: $($set.Count) nodes loaded." 'INFO'
    return $set
}
function Get-IpThreatIntel { param([string]$UPN,[int]$Days=30,[string[]]$HomeCountries)
    $si=@(Get-SignIns $UPN $Days)
    $tor=Get-TorExitNodes
    $byIp=@{}
    foreach ($s in $si) { if (-not $s -or -not $s.IP) { continue }
        if (-not $byIp.ContainsKey($s.IP)) { $byIp[$s.IP]=[ordered]@{ Count=0; Location=(PV $s 'Location'); Country=(PV $s 'Country'); Errors=0 } }
        $byIp[$s.IP].Count++; if ((PV $s 'ErrCode' 0) -ne 0) { $byIp[$s.IP].Errors++ } }
    $out=[System.Collections.Generic.List[object]]::new()
    foreach ($ip in $byIp.Keys) { $e=$byIp[$ip]
        $isTor = $tor.Contains($ip)
        $foreign = $e.Country -and ($e.Country -notin $HomeCountries)
        $flags=@(); if ($isTor){$flags+='TOR-Exit'}; if ($foreign){$flags+='Foreign'}; if ($e.Errors -gt 0){$flags+="$($e.Errors) errors"}
        $sev = if ($isTor) {'HIGH'} elseif ($foreign) {'MEDIUM'} else {'LOW'}
        $out.Add([ordered]@{ IP=$ip; Count=$e.Count; Location=$e.Location; TorExit=$(if($isTor){'YES'}else{'no'}); Rating=$sev; Flags=($flags -join ', ') }) }
    @($out | Sort-Object @{e={ switch($_.Rating){'HIGH'{0} 'MEDIUM'{1} default{2}} }}, IP)
}

# =====================================================================
#  Case management (local persistence)
# =====================================================================
function Get-CaseDir { $d=Join-Path $PWD 'cases'; if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }; $d }
function Test-CaseId { param([string]$Id)
    # Reject anything but the charset used when saving cases; blocks path traversal (../, \, /, etc.)
    if (-not $Id -or $Id -notmatch '^[a-zA-Z0-9._-]+$' -or $Id.Contains('..')) { throw 'Invalid case ID.' }
    return $Id
}

# =====================================================================
#  HTML report (mail) - generic renderer
# =====================================================================
function Build-HtmlTable { param($Rows)
    $rows=@($Rows)
    if ($rows.Count -eq 0) { return "<p style='color:#8b97a7;font-style:italic'>No data.</p>" }
    $hidden=@('ErrCode','Country','Lat','Lon','Id')
    $cols=@($rows[0].Keys | Where-Object { $_ -notin $hidden })
    $th=($cols | ForEach-Object { "<th>$(HtmlEnc $_)</th>" }) -join ''
    $body=($rows | ForEach-Object { $r=$_
        $hot=($r.Contains('ErrCode') -and $r.ErrCode -ne 0) -or ($r.Contains('Direction') -and $r.Direction -eq 'Sent') -or `
             ($r.Contains('ForwardTo') -and [string]$r.ForwardTo -ne '') -or ($r.Contains('Type') -and $r.Type -in @('ROLE','Impossible Travel')) -or `
             ($r.Contains('Scope') -and $r.Scope -eq 'anonymous') -or ($r.Contains('LegacyAuth') -and $r.LegacyAuth -eq 'YES')
        $cls=if ($hot){" style='background:#3a1d1d'"}else{''}
        $tds=($cols | ForEach-Object { $v=$r[$_]
            if ($v -is [string] -and $v -match '^https?://') { "<td><a href='$(HtmlEnc $v)'>$(HtmlEnc $v)</a></td>" } else { "<td>$(HtmlEnc $v)</td>" } }) -join ''
        "<tr$cls>$tds</tr>" }) -join "`n"
    "<table><thead><tr>$th</tr></thead><tbody>$body</tbody></table>"
}
function Build-HtmlReport { param([hashtable]$B)
    $m=$B.metrics; $risk=$B.risk
    $rc=switch ($risk.Level){ 'HIGH'{'#f85149'} 'MEDIUM'{'#d29922'} default{'#3fb950'} }
    $cards=''
    foreach ($kv in @(@('Devices',$m.devices),@('Sites',$m.sites),@('Files',$m.files),@('Sent',$m.sent),@('External Mail',$m.external),@('Susp. Logins',$m.suspicious),@('Anomalies',$m.anomalies),@('OAuth-Apps',$m.oauth),@('Alerts',$m.alerts))) {
        $cards+="<div class='card'><div class='n'>$($kv[1])</div><div class='l'>$($kv[0])</div></div>" }
    $facL=($risk.Factors | ForEach-Object { "<li>$(HtmlEnc $_)</li>" }) -join ''
    if (-not $facL) { $facL='<li>No notable factors.</li>' }
    $secHtml=''
    foreach ($name in $B.sections.Keys) { $secHtml+="<h2>$(HtmlEnc $name)</h2>" + (Build-HtmlTable $B.sections[$name]) }
@"
<!DOCTYPE html><html lang="de"><head><meta charset="utf-8"><title>Compromise Report - $(HtmlEnc $B.upn)</title>
<style>body{font-family:'Segoe UI',Arial,sans-serif;background:#0f1419;color:#e6edf3;margin:0;padding:24px}
.wrap{max-width:1100px;margin:auto}h1{font-size:22px}h2{color:#3ba9f4;border-bottom:1px solid #222d3a;padding-bottom:6px;margin-top:28px;font-size:16px}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:8px}th{background:#161d26;text-align:left;padding:7px;color:#8b97a7}
td{padding:6px 7px;border-bottom:1px solid #222d3a;font-family:ui-monospace,Consolas,monospace}a{color:#3ba9f4}
.badge{display:inline-block;padding:5px 14px;border-radius:999px;color:#04121f;font-weight:700;background:$rc}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}.card{background:#161d26;border:1px solid #222d3a;border-radius:10px;padding:12px 16px;min-width:104px}
.card .n{font-size:24px;font-weight:800;color:#3ba9f4;font-family:ui-monospace,monospace}.card .l{font-size:10px;color:#8b97a7;text-transform:uppercase}
footer{color:#8b97a7;font-size:11px;text-align:center;margin-top:30px}</style></head><body><div class="wrap">
<h1>&#128737; Compromised User Impact Report</h1>
<p>User: <b>$(HtmlEnc $B.upn)</b> &middot; Compromised since: <b>$($B.compDate.ToString('dd.MM.yyyy HH:mm'))</b> &middot; Created: $((Get-Date).ToString('dd.MM.yyyy HH:mm')) &middot; <span class="badge">Risk: $($risk.Level) ($($risk.Score))</span></p>
<div class="cards">$cards</div><h2>Risk Factors</h2><ul>$facL</ul>$secHtml
<footer>Generated by M365 Compromise Response Script &middot; $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))</footer>
</div></body></html>
"@
}
function Send-ReportMail { param([string]$Html,[string]$Subject,[string]$Recipient,[string]$Sender)
    $payload=@{ message=@{ subject=$Subject; body=@{ contentType='HTML'; content=$Html }
                toRecipients=@(@{ emailAddress=@{ address=$Recipient } }) }; saveToSentItems=$true } | ConvertTo-Json -Depth 10
    Invoke-GraphRequest "$($script:BaseUrl)/users/$Sender/sendMail" -Method POST -Body $payload | Out-Null
}

# =====================================================================
#  Full collection (report + snapshot)
# =====================================================================
function Invoke-FullCollection { param([string]$UPN,[datetime]$Since,[int]$Days,[string]$Region,[string[]]$HomeCountries)
    $dev=@(Get-UserDevices $UPN); $devd=@(Get-DeviceDeep $UPN); $sit=@(Get-UserSites $UPN $Region); $fil=@(Get-ModifiedFiles $UPN $Since $Region)
    $share=@(Get-SharingLinks $UPN); $mai=@(Get-MailActivity $UPN $Since); $mext=@(Get-ExternalMail $mai $UPN)
    $rul=@(Get-InboxRules $UPN); $mbx=@(Get-MailboxInfo $UPN); $teams=@(Get-TeamsActivity $UPN)
    $sig=@(Get-SignIns $UPN $Days); $anom=@(Get-Anomalies $sig $HomeCountries); $fp=@(Get-ClientFingerprints $sig)
    $risk2=@(Get-RiskInfo $UPN); $alerts=@(Get-SecurityAlerts $UPN); $ca=@(Get-CAPolicies)
    $roles=@(Get-RolesGroups $UPN); $mfa=@(Get-AuthMethods $UPN); $oauth=@(Get-OAuthGrants $UPN)
    $actby=@(Get-ActionsBy $UPN $Since); $appc=@(Get-AppCredChanges $Since); $aud=@(Get-PermissionChanges $UPN $Since)
    $tl=@(Build-Timeline $sig $mai $fil $aud $actby); $ioc=@(Build-IOCs $sig $mai $oauth $rul $UPN $HomeCountries)
    $sent=@($mai | Where-Object { $_ -and $_.Direction -eq 'Sent' }).Count
    $susp=Count-Suspicious -SignIns $sig -HomeCountries $HomeCountries
    $fwd=@($rul | Where-Object { $_ -and [string]$_.ForwardTo -ne '' }).Count
    $anonShare=@($share | Where-Object { $_ -and $_.Scope -eq 'anonymous' }).Count
    $risky=[bool](@($risk2 | Where-Object { $_ -and $_.Kind -eq 'RiskyUser' -and $_.State -in @('atRisk','confirmedCompromised') }).Count)
    $risk=Get-RiskAssessment -Files $fil.Count -SentMails $sent -Suspicious $susp -ForwardRules $fwd -AuditChanges $aud.Count `
            -OAuthApps $oauth.Count -Anomalies $anom.Count -RiskyUser $risky -ExternalMails $mext.Count -ActionsByUser $actby.Count `
            -Alerts $alerts.Count -AnonShares $anonShare
    $attack=@(Build-AttackMapping ([ordered]@{
        'Sign-In Logs'=$sig; 'Inbox Rules'=$rul; 'MFA Methods'=$mfa; 'App Credential Changes'=$appc
        'OAuth-Apps'=$oauth; 'SharePoint / OneDrive'=$sit; 'Modified Files'=$fil; 'External Sharing Links'=$share
        'External Mail'=$mext; 'Client/Legacy-Auth'=$fp; 'Roles & Groups'=$roles }) $Since $HomeCountries)
    [ordered]@{
        upn=$UPN; compDate=$Since
        metrics=@{ devices=$dev.Count; sites=$sit.Count; files=$fil.Count; sent=$sent; received=($mai.Count-$sent)
                   external=$mext.Count; suspicious=$susp; anomalies=$anom.Count; oauth=$oauth.Count; alerts=$alerts.Count; shares=$share.Count }
        risk=@{ level=$risk.Level; score=$risk.Score; factors=$risk.Factors }
        sections=[ordered]@{
            'Devices'=$dev; 'Device Details'=$devd; 'Roles & Groups'=$roles; 'MFA Methods'=$mfa; 'OAuth-Apps'=$oauth
            'SharePoint / OneDrive'=$sit; 'Modified Files'=$fil; 'External Sharing Links'=$share
            'Email Activity'=$mai; 'External Mail'=$mext; 'Inbox Rules'=$rul; 'Mailbox Settings'=$mbx; 'Teams Activity'=$teams
            'Sign-In Logs'=$sig; 'Login Anomalies'=$anom; 'Client/Legacy-Auth'=$fp; 'Identity Protection'=$risk2
            'Defender Alerts'=$alerts; 'Conditional Access'=$ca
            'Actions by User'=$actby; 'App Credential Changes'=$appc; 'Permission Changes'=$aud
            'Timeline'=$tl; 'IOC-Bundle'=$ioc; 'MITRE ATT&CK'=$attack }
    }
}

# =====================================================================
#  API-Dispatch
# =====================================================================
function Invoke-ApiAction { param([string]$Path,$Data)
    $upn   = DV $Data 'upn'
    $since = if (DV $Data 'compromiseDate') { [datetime]::Parse((DV $Data 'compromiseDate')) } else { (Get-Date).AddDays(-30) }
    $days  = if (DV $Data 'signInDays') { [int](DV $Data 'signInDays') } else { 30 }
    $homeCountries = if (DV $Data 'homeCountries') { @((DV $Data 'homeCountries') -split '\s*,\s*') } else { @('DE') }
    $region = if (DV $Data 'region') { [string](DV $Data 'region') } else { $script:Region }

    switch ($Path) {
        '/api/connect' {
            $script:Creds=@{ TenantId=(DV $Data 'tenantId'); ClientId=(DV $Data 'clientId'); Secret=(DV $Data 'clientSecret') }
            $script:Token=$null; Get-ValidToken | Out-Null
            $org=try{ [string](PV (Invoke-GraphRequest "$($script:BaseUrl)/organization" -Raw).value[0] 'displayName') }catch{ '' }
            $script:Region=Get-TenantRegion
            Write-Log "Connected to $org. Region: $(if($script:Region){$script:Region}else{'unknown'}). Roles: $(@($script:GrantedRoles).Count)." 'OK'
            return @{ ok=$true; tenant=(DV $Data 'tenantId'); org=$org; region=$script:Region; roles=@($script:GrantedRoles) }
        }
        '/api/disconnect' { $script:Creds=$null; $script:Token=$null; $script:GrantedRoles=@(); Write-Log 'Disconnected.' 'INFO'; return @{ ok=$true } }

        '/api/run' {
            if (-not $upn) { throw 'No User Principal Name provided.' }
            $action=DV $Data 'action'; Write-Log "Probe '$action' for $upn ..." 'INFO'
            switch ($action) {
                'devices'     { return @{ ok=$true; title='Devices';                    data=@(Get-UserDevices $upn) } }
                'devicedeep'  { return @{ ok=$true; title='Device Details';            data=@(Get-DeviceDeep $upn) } }
                'roles'       { return @{ ok=$true; title='Roles & Groups';           data=@(Get-RolesGroups $upn) } }
                'mfa'         { return @{ ok=$true; title='MFA Methods';               data=@(Get-AuthMethods $upn) } }
                'oauth'       { return @{ ok=$true; title='OAuth-Apps';                 data=@(Get-OAuthGrants $upn) } }
                'sites'       { return @{ ok=$true; title='SharePoint / OneDrive';      data=@(Get-UserSites $upn $region) } }
                'files'       { return @{ ok=$true; title='Modified Files';         data=@(Get-ModifiedFiles $upn $since $region) } }
                'sharing'     { return @{ ok=$true; title='External Sharing Links';      data=@(Get-SharingLinks $upn) } }
                'mail'        { return @{ ok=$true; title='Email Activity';          data=@(Get-MailActivity $upn $since) } }
                'mailext'     { return @{ ok=$true; title='External Mail (Exfil)';      data=@(Get-ExternalMail (Get-MailActivity $upn $since) $upn) } }
                'rules'       { return @{ ok=$true; title='Inbox Rules';         data=@(Get-InboxRules $upn) } }
                'mailbox'     { return @{ ok=$true; title='Mailbox Settings';          data=@(Get-MailboxInfo $upn) } }
                'teams'       { return @{ ok=$true; title='Teams Activity';           data=@(Get-TeamsActivity $upn) } }
                'signins'     { return @{ ok=$true; title='Sign-In Logs';               data=@(Get-SignIns $upn $days) } }
                'anomaly'     { return @{ ok=$true; title='Login Anomalies';            data=@(Get-Anomalies (Get-SignIns $upn $days) $homeCountries) } }
                'fingerprint' { return @{ ok=$true; title='Client/Legacy-Auth';         data=@(Get-ClientFingerprints (Get-SignIns $upn $days)) } }
                'risk'        { return @{ ok=$true; title='Identity Protection';        data=@(Get-RiskInfo $upn) } }
                'alerts'      { return @{ ok=$true; title='Defender Alerts';            data=@(Get-SecurityAlerts $upn) } }
                'capolicies'  { return @{ ok=$true; title='Conditional Access';         data=@(Get-CAPolicies) } }
                'actionsby'   { return @{ ok=$true; title='Actions by User';        data=@(Get-ActionsBy $upn $since) } }
                'appcreds'    { return @{ ok=$true; title='App Credential Changes'; data=@(Get-AppCredChanges $since) } }
                'audits'      { return @{ ok=$true; title='Permission Changes';  data=@(Get-PermissionChanges $upn $since) } }
                'threatintel' { return @{ ok=$true; title='Threat Intel (Tor/Anonymizer)'; data=@(Get-IpThreatIntel $upn $days $homeCountries) } }
                'timeline'    {
                    $sig=@(Get-SignIns $upn $days); $mai=@(Get-MailActivity $upn $since); $fil=@(Get-ModifiedFiles $upn $since $region)
                    $aud=@(Get-PermissionChanges $upn $since); $act=@(Get-ActionsBy $upn $since)
                    return @{ ok=$true; title='Timeline'; data=@(Build-Timeline $sig $mai $fil $aud $act) } }
                'ioc'         {
                    $sig=@(Get-SignIns $upn $days); $mai=@(Get-MailActivity $upn $since); $oauth=@(Get-OAuthGrants $upn); $rul=@(Get-InboxRules $upn)
                    return @{ ok=$true; title='IOC-Bundle'; data=@(Build-IOCs $sig $mai $oauth $rul $upn $homeCountries) } }
                'full'        {
                    $B=Invoke-FullCollection -UPN $upn -Since $since -Days $days -Region $region -HomeCountries $homeCountries
                    return @{ ok=$true; full=$true; metrics=$B.metrics; risk=$B.risk; sections=$B.sections } }
                default { throw "Unknown action: $action" }
            }
        }

        '/api/report' {
            if (-not $upn) { throw 'No User Principal Name provided.' }
            $recipient=DV $Data 'recipient'; $sender=DV $Data 'sender'
            if (-not $recipient -or -not $sender) { throw 'Recipient and sender are required.' }
            Write-Log "Building mail report for $upn ..." 'INFO'
            $B=Invoke-FullCollection -UPN $upn -Since $since -Days $days -Region $region -HomeCountries $homeCountries
            Send-ReportMail -Html (Build-HtmlReport -B $B) -Subject "[$($B.risk.level)] Compromised User Report - $upn" -Recipient $recipient -Sender $sender
            Write-Log "Report sent to $recipient." 'OK'
            return @{ ok=$true; risk=$B.risk.level; recipient=$recipient }
        }

        '/api/snapshot' {
            if (-not $upn) { throw 'No User Principal Name provided.' }
            Write-Log "Building evidence snapshot for $upn ..." 'INFO'
            $B=Invoke-FullCollection -UPN $upn -Since $since -Days $days -Region $region -HomeCountries $homeCountries
            $notes=DV $Data 'notes'; if ($notes) { $B['caseNotes']=$notes }
            $dir=if (DV $Data 'path') { DV $Data 'path' } else { Join-Path $PWD 'evidence' }
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $safe=($upn -replace '[^a-zA-Z0-9._-]','_'); $stamp=(Get-Date).ToString('yyyyMMdd-HHmmss')
            $file=Join-Path $dir "$safe-$stamp.json"
            ($B | ConvertTo-Json -Depth 12) | Out-File -FilePath $file -Encoding utf8
            $hash=(Get-FileHash -Path $file -Algorithm SHA256).Hash
            "File: $file`r`nSHA256: $hash`r`nGenerated: $(Get-Date -Format o)`r`nUser: $upn" | Out-File -FilePath (Join-Path $dir "$safe-$stamp.manifest.txt") -Encoding utf8
            Write-Log "Snapshot saved: $file (SHA256 $hash)" 'OK'
            return @{ ok=$true; file=$file; sha256=$hash }
        }

        '/api/cases' {
            $d=Get-CaseDir; $list=[System.Collections.Generic.List[object]]::new()
            foreach ($f in (Get-ChildItem -Path $d -Filter '*.json' -File | Sort-Object LastWriteTime -Descending)) {
                $meta=[ordered]@{ id=$f.BaseName; upn=''; created=$f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'); risk=''; score=''; notes='' }
                try { $j=Get-Content $f.FullName -Raw | ConvertFrom-Json
                      $meta.upn=[string](PV $j 'upn'); $meta.notes=[string](PV $j 'notes')
                      $r=PV $j 'risk'; $meta.risk=[string](PV $r 'level'); $meta.score=[string](PV $r 'score') } catch {}
                $list.Add($meta) }
            return @{ ok=$true; cases=@($list) }
        }
        '/api/case' {
            $op=DV $Data 'op'; $d=Get-CaseDir
            switch ($op) {
                'save' {
                    if (-not $upn) { throw 'No User Principal Name for case.' }
                    $safe=($upn -replace '[^a-zA-Z0-9._-]','_'); $stamp=(Get-Date).ToString('yyyyMMdd-HHmmss'); $id="$safe-$stamp"
                    $payload=[ordered]@{ id=$id; upn=$upn; created=(Get-Date -Format o); notes=(DV $Data 'notes')
                        risk=(DV $Data 'risk'); metrics=(DV $Data 'metrics'); results=(DV $Data 'results')
                        attack=(DV $Data 'attack'); playbook=(DV $Data 'playbook') }
                    ($payload | ConvertTo-Json -Depth 16) | Out-File -FilePath (Join-Path $d "$id.json") -Encoding utf8
                    Write-Log "Case saved: $id" 'OK'; return @{ ok=$true; id=$id }
                }
                'load' {
                    $id=Test-CaseId ([string](DV $Data 'id'))
                    $f=Join-Path $d "$id.json"
                    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($f)) -ne [IO.Path]::GetFullPath($d)) { throw 'Invalid case ID.' }
                    if (-not (Test-Path $f)) { throw "Case not found: $id" }
                    $j=Get-Content $f -Raw | ConvertFrom-Json; return @{ ok=$true; case=$j }
                }
                'delete' {
                    $id=Test-CaseId ([string](DV $Data 'id'))
                    $f=Join-Path $d "$id.json"
                    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($f)) -ne [IO.Path]::GetFullPath($d)) { throw 'Invalid case ID.' }
                    if (Test-Path $f) { Remove-Item $f -Force }
                    Write-Log "Case deleted: $id" 'INFO'; return @{ ok=$true }
                }
                default { throw "Unknown case operation: $op" }
            }
        }

        '/api/contain' {
            if (-not ($Data -and (DV $Data 'confirm') -eq $true)) { throw 'Confirmation missing - containment not executed.' }
            if (-not $upn) { throw 'No User Principal Name provided.' }
            $op=DV $Data 'op'; Write-Log "CONTAINMENT '$op' for $upn ..." 'WARN'
            switch ($op) {
                'revoke'    { Invoke-GraphRequest "$($script:BaseUrl)/users/$upn/revokeSignInSessions" -Method POST -Raw | Out-Null
                              Write-Log "Sessions revoked: $upn" 'OK'; return @{ ok=$true; msg="All active sessions/tokens for $upn have been revoked." } }
                'disable'   { Invoke-GraphRequest "$($script:BaseUrl)/users/$upn" -Method PATCH -Body (@{accountEnabled=$false}|ConvertTo-Json) -Raw | Out-Null
                              Write-Log "Account disabled: $upn" 'OK'; return @{ ok=$true; msg="Account $upn has been disabled (sign-in blocked)." } }
                'enable'    { Invoke-GraphRequest "$($script:BaseUrl)/users/$upn" -Method PATCH -Body (@{accountEnabled=$true}|ConvertTo-Json) -Raw | Out-Null
                              Write-Log "Account re-enabled: $upn" 'OK'; return @{ ok=$true; msg="Account $upn has been re-enabled (rollback)." } }
                'resetpw'   { $pw=New-RandomPassword
                              Invoke-GraphRequest "$($script:BaseUrl)/users/$upn" -Method PATCH -Body (@{passwordProfile=@{password=$pw;forceChangePasswordNextSignIn=$true}}|ConvertTo-Json) -Raw | Out-Null
                              Write-Log "Password reset: $upn" 'OK'; return @{ ok=$true; msg="Password for $upn reset (change forced at next sign-in)."; password=$pw } }
                'deleterule'{ $rid=DV $Data 'ruleId'; if (-not $rid) { throw 'No rule ID provided.' }
                              Invoke-GraphRequest "$($script:BaseUrl)/users/$upn/mailFolders/inbox/messageRules/$rid" -Method DELETE -Raw | Out-Null
                              Write-Log "Inbox rule deleted: $rid ($upn)" 'OK'; return @{ ok=$true; msg="Inbox rule $rid has been deleted." } }
                default     { throw "Unknown containment operation: $op" }
            }
        }
        default { throw "Unknown endpoint: $Path" }
    }
}
# =====================================================================
#  Web interface (SOC UI)
# =====================================================================
$indexHtml = @'
<!DOCTYPE html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>M365 Compromise Response Console</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c232d;--line:#243040;--ink:#e6edf3;--muted:#8b97a7;
  --accent:#3ba9f4;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--purple:#a371f7;}
body[data-theme="light"]{--bg:#f4f6fa;--panel:#fff;--panel2:#eef1f6;--line:#d4dae3;--ink:#1a2030;--muted:#5a6678;--accent:#1f6feb;}
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',system-ui,Arial,sans-serif;background:var(--bg);color:var(--ink);font-size:14px;display:flex;flex-direction:column;height:100vh;overflow:hidden}
code,.mono,td,input,th{font-family:ui-monospace,'SF Mono','Cascadia Code',Consolas,monospace}
header{display:flex;align-items:center;gap:12px;padding:11px 18px;border-bottom:1px solid var(--line);background:var(--panel)}
header .dot{width:9px;height:9px;border-radius:50%;background:var(--bad);box-shadow:0 0 8px var(--bad)}
header.on .dot{background:var(--ok);box-shadow:0 0 8px var(--ok)}
header h1{font-size:13px;letter-spacing:.14em;text-transform:uppercase;margin:0;font-weight:600}
header .right{margin-left:auto;display:flex;align-items:center;gap:14px}
header .tenant{color:var(--muted);font-size:12px} header .perm{color:var(--muted);font-size:11px;cursor:pointer}
header .perm b{color:var(--ok)} .iconbtn{background:transparent;border:1px solid var(--line);color:var(--muted);border-radius:6px;padding:5px 9px;cursor:pointer;font-size:12px}
.iconbtn:hover{border-color:var(--accent);color:var(--ink)}
.main{display:flex;flex:1;min-height:0}
aside{width:312px;background:var(--panel);border-right:1px solid var(--line);padding:16px;overflow:auto}
.eyebrow{font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin:16px 0 6px}.eyebrow:first-child{margin-top:0}
label{display:block;font-size:11px;color:var(--muted);margin:9px 0 3px;text-transform:uppercase;letter-spacing:.04em}
input{width:100%;background:var(--bg);border:1px solid var(--line);color:var(--ink);border-radius:7px;padding:8px 9px;font-size:13px}
input:focus{outline:none;border-color:var(--accent)}
button{cursor:pointer;border:none;border-radius:7px;font-size:13px;font-weight:600;font-family:inherit}
.btn-accent{background:var(--accent);color:#04121f;padding:10px;width:100%;margin-top:12px}.btn-accent:hover{filter:brightness(1.1)}
.btn-ghost{background:transparent;border:1px solid var(--line);color:var(--muted);padding:7px;width:100%;margin-top:7px}.btn-ghost:hover{border-color:var(--accent);color:var(--ink)}
.btn-danger{background:transparent;border:1px solid var(--bad);color:var(--bad);padding:8px;width:100%;margin-top:7px}.btn-danger:hover{background:var(--bad);color:#04121f}
.btn-rollback{background:transparent;border:1px solid var(--ok);color:var(--ok);padding:8px;width:100%;margin-top:7px}.btn-rollback:hover{background:var(--ok);color:#04121f}
.danger-box{border:1px solid var(--bad);border-radius:8px;padding:10px;margin-top:6px;background:rgba(248,81,73,.06)}
.danger-box .warn{font-size:11px;color:var(--bad);margin-bottom:4px}
section.work{flex:1;display:flex;flex-direction:column;min-width:0}
.probes{padding:11px 18px;border-bottom:1px solid var(--line);background:var(--panel2);max-height:188px;overflow:auto}
.pgroup{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:7px}
.pglabel{font-size:9px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);width:74px;flex-shrink:0}
.probe{display:flex;align-items:center;gap:7px;background:var(--panel);border:1px solid var(--line);color:var(--ink);padding:6px 11px;border-radius:7px;transition:.15s;font-size:12px}
.probe:hover:not(:disabled){border-color:var(--accent)}.probe:disabled{opacity:.4;cursor:not-allowed}
.probe .led{width:7px;height:7px;border-radius:50%;background:var(--muted)}
.probe.run .led{background:var(--warn);animation:pulse 1s infinite}.probe.ok .led{background:var(--ok)}.probe.err .led{background:var(--bad)}
@keyframes pulse{50%{opacity:.3}}
.probe.full{background:var(--accent);color:#04121f;border-color:var(--accent)}.probe.full .led{background:#04121f}
.toolbar{padding:8px 18px;border-bottom:1px solid var(--line);display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.toolbar button{background:var(--panel);border:1px solid var(--line);color:var(--ink);padding:6px 12px;font-size:12px}
.toolbar button:hover{border-color:var(--accent)}.toolbar .ttl{color:var(--muted);font-size:12px;margin-left:auto}
.progress{height:4px;background:var(--line);border-radius:3px;overflow:hidden;flex:1;min-width:120px;display:none}
.progress.show{display:block}.progress .bar{height:100%;width:0;background:var(--accent);transition:width .25s}
.canvas{flex:1;overflow:auto;padding:18px}
.placeholder{color:var(--muted);text-align:center;margin-top:70px;font-size:13px;line-height:1.7}
.empty{color:var(--muted);font-style:italic;padding:10px 0}
.dashtop{display:flex;gap:18px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
.gauge{width:200px;height:120px}
.cards{display:flex;gap:9px;flex-wrap:wrap}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:11px 14px;min-width:92px}
.card .n{font-size:22px;font-weight:800;color:var(--accent)}.card .l{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.triage{display:flex;flex-direction:column;gap:7px;margin:14px 0}
.find{display:flex;align-items:center;gap:11px;padding:10px 13px;border-radius:9px;border:1px solid var(--line);background:var(--panel);cursor:pointer}
.find:hover{border-color:var(--accent)}.find .sv{font-size:10px;font-weight:800;padding:3px 8px;border-radius:5px;letter-spacing:.05em}
.find.CRITICAL{border-left:4px solid var(--bad)}.find.CRITICAL .sv{background:var(--bad);color:#04121f}
.find.HIGH{border-left:4px solid var(--warn)}.find.HIGH .sv{background:var(--warn);color:#04121f}
.find.MEDIUM{border-left:4px solid var(--accent)}.find.MEDIUM .sv{background:var(--accent);color:#04121f}
.find .ft{font-weight:600}.find .fd{color:var(--muted);font-size:12px}
.risk{display:inline-block;padding:6px 16px;border-radius:999px;font-weight:700;color:#04121f}
.risk.HIGH{background:var(--bad)}.risk.MEDIUM{background:var(--warn)}.risk.LOW{background:var(--ok)}
h2.sec{font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:var(--accent);margin:22px 0 7px;border-bottom:1px solid var(--line);padding-bottom:5px;scroll-margin-top:10px}
.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{position:sticky;top:0;background:var(--panel);text-align:left;padding:7px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line);cursor:default;white-space:nowrap}
th[onclick]{cursor:pointer}th[onclick]:hover{color:var(--ink)}.sortarr{color:var(--accent)}
td{padding:6px 7px;border-bottom:1px solid var(--line);word-break:break-word}tr.hot td{background:rgba(248,81,73,.10)}td a{color:var(--accent)}
.tfilter{max-width:280px;margin-bottom:8px}
.count{color:var(--muted);font-size:12px;margin-left:8px}
.tlsvg{width:100%;height:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px;margin-top:6px}
.permgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:8px}
.perm{display:flex;align-items:center;gap:10px;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
.perm .pled{width:9px;height:9px;border-radius:50%}.perm.ok .pled{background:var(--ok)}.perm.miss .pled{background:var(--bad)}.perm.opt .pled{background:var(--muted)}
.perm .pp{font-size:12px}.perm .pf{font-size:10px;color:var(--muted)}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);padding:12px 18px;border-radius:8px;opacity:0;transition:.3s;pointer-events:none;max-width:90%;z-index:50}
.toast.show{opacity:1}.toast.ok{border-left-color:var(--ok)}.toast.err{border-left-color:var(--bad)}
.spin{display:inline-block;width:16px;height:16px;border:2px solid var(--line);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
@media(max-width:860px){.main{flex-direction:column}aside{width:auto;border-right:none;border-bottom:1px solid var(--line)}}
@media print{aside,header .right,.probes,.toolbar{display:none!important}.canvas{overflow:visible;height:auto}body{height:auto;display:block}}
/* ATT&CK matrix */
.attgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin-top:8px}
.attcol{border:1px solid var(--line);border-radius:9px;background:var(--panel);overflow:hidden}
.attcol h4{margin:0;padding:8px 10px;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink);background:var(--panel2);border-bottom:1px solid var(--line)}
.attcell{padding:8px 10px;border-bottom:1px solid var(--line);cursor:default}
.attcell:last-child{border-bottom:none}
.attcell .tid{font-size:10px;color:var(--muted);font-family:ui-monospace,monospace}
.attcell .tn{font-size:11.5px;font-weight:600;margin:2px 0}
.attcell .tb{font-size:10.5px;color:var(--muted)}
.attcell.CRITICAL{border-left:4px solid var(--bad)}.attcell.HIGH{border-left:4px solid var(--warn)}
.attcell.MEDIUM{border-left:4px solid var(--accent)}.attcell.LOW{border-left:4px solid var(--muted)}
.graphsvg{width:100%;height:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px;margin-top:6px}
/* Playbook */
.pbphase{border:1px solid var(--line);border-radius:9px;margin:10px 0;overflow:hidden}
.pbphase h3{margin:0;padding:10px 12px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;background:var(--panel2);color:var(--accent);display:flex;align-items:center;gap:10px}
.pbphase h3 .pc{margin-left:auto;font-size:11px;color:var(--muted)}
.pbstep{display:flex;align-items:flex-start;gap:10px;padding:9px 12px;border-top:1px solid var(--line)}
.pbstep input{width:auto;margin-top:2px}
.pbstep .s{flex:1}.pbstep .st{font-size:13px}.pbstep .sd{font-size:11px;color:var(--muted)}
.pbstep.done .st{text-decoration:line-through;color:var(--muted)}
.pbstep button{background:var(--panel2);border:1px solid var(--line);color:var(--ink);padding:5px 10px;font-size:11px;white-space:nowrap}
.pbstep button:hover{border-color:var(--accent)}
.pbbar{height:6px;border-radius:4px;background:var(--line);overflow:hidden;margin:6px 0 14px}.pbbar>div{height:100%;background:var(--ok);width:0;transition:width .3s}
.actionlog{border:1px solid var(--line);border-radius:8px;background:var(--panel);margin-top:10px;font-size:12px}
.actionlog .al{padding:7px 11px;border-bottom:1px solid var(--line);font-family:ui-monospace,monospace}.actionlog .al:last-child{border:none}
/* Cases */
.caselist{display:flex;flex-direction:column;gap:8px;margin-top:8px}
.caseitem{display:flex;align-items:center;gap:12px;padding:11px 13px;border:1px solid var(--line);border-radius:9px;background:var(--panel)}
.caseitem .ci{flex:1}.caseitem .cu{font-weight:600}.caseitem .cm{font-size:11px;color:var(--muted)}
.caseitem button{padding:6px 11px;font-size:11px;border:1px solid var(--line);background:var(--panel2);color:var(--ink)}
.caseitem button:hover{border-color:var(--accent)}
.rfbar{display:flex;align-items:center;gap:8px;margin:3px 0;font-size:11px}
.rfbar .rl{width:230px;color:var(--muted)}.rfbar .rt{flex:1;height:10px;background:var(--line);border-radius:5px;overflow:hidden}.rfbar .rt>div{height:100%;background:var(--accent)}
</style></head>
<body data-theme="dark">
<header id="hdr"><span class="dot"></span><h1>M365 Compromise Response Console</h1>
 <div class="right">
   <span class="perm" id="permLabel" onclick="showPreflight()" style="display:none"></span>
   <span class="tenant" id="tenant">not connected</span>
   <button class="iconbtn" onclick="toggleTheme()" id="themeBtn">&#9788; Theme</button>
 </div></header>
<div class="main">
  <aside>
    <div class="eyebrow">Connection</div>
    <label>Tenant ID</label><input id="tenantId" placeholder="00000000-0000-...">
    <label>App (Client) ID</label><input id="clientId" placeholder="00000000-0000-...">
    <label>Client Secret</label><input id="clientSecret" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;">
    <button class="btn-accent" id="btnConnect" onclick="connect()">Connect</button>
    <button class="btn-ghost" id="btnDisconnect" onclick="disconnect()" style="display:none">Disconnect</button>

    <div class="eyebrow">Target</div>
    <label>User Principal Name</label><input id="upn" placeholder="user@domain.de">
    <label>Compromised since</label><input id="compromiseDate" type="datetime-local">
    <label>Sign-in period (days)</label><input id="signInDays" value="30">
    <label>Home countries (comma)</label><input id="homeCountries" value="DE">
    <label>Search-Region (auto)</label><input id="region" placeholder="z.B. EUR / NAM / GBR">

    <div class="eyebrow">Report &amp; Evidence</div>
    <label>Report recipient</label><input id="recipient" placeholder="soc@domain.de">
    <label>Sender mailbox</label><input id="sender" placeholder="reporting@domain.de">
    <button class="btn-accent" id="btnReport" onclick="sendReport()" disabled>Send mail report</button>
    <label>Case notes (in snapshot)</label><input id="notes" placeholder="z.B. Ticket #1234">
    <button class="btn-ghost" id="btnSnapshot" onclick="snapshot()" disabled>Evidence snapshot (JSON+SHA256)</button>

    <div class="eyebrow">Containment &ndash; takes active action!</div>
    <div class="danger-box">
      <div class="warn">&#9888; These actions modify the tenant. Confirmation required.</div>
      <button class="btn-danger" id="c1" onclick="contain('revoke')" disabled>Revoke sessions/tokens</button>
      <button class="btn-danger" id="c2" onclick="contain('disable')" disabled>Disable account</button>
      <button class="btn-danger" id="c3" onclick="contain('resetpw')" disabled>Reset password</button>
      <label>Inbox rule ID (to delete)</label><input id="ruleId" placeholder="Rule ID from inbox rules">
      <button class="btn-danger" id="c4" onclick="contain('deleterule')" disabled>Delete inbox rule</button>
      <button class="btn-rollback" id="c5" onclick="contain('enable')" disabled>Rollback: re-enable account</button>
    </div>
    <button class="btn-ghost" onclick="shutdown()">Quit application</button>
    <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--line);font-size:11px;line-height:1.7;color:var(--muted);text-align:center">
      Developed by <b>Maurice Fl&ouml;thmann</b><br>
      <a href="mailto:ask-maurice@mo-cloud.de" style="color:var(--accent);text-decoration:none">ask-maurice@mo-cloud.de</a>
    </div>
  </aside>

  <section class="work">
    <div class="probes" id="probes"></div>
    <div class="toolbar">
      <button onclick="exportCsv()">&#11015; CSV</button>
      <button onclick="exportJson()">&#11015; JSON</button>
      <button onclick="exportStix()" title="STIX 2.1 IOC bundle">&#11015; STIX</button>
      <button onclick="exportMisp()" title="MISP event JSON">&#11015; MISP</button>
      <button onclick="exportMarkdown()" title="Markdown report">&#11015; MD</button>
      <button onclick="window.print()">&#128424; PDF/Print</button>
      <button onclick="showPlaybook()" title="Guided IR runbook">&#128203; Playbook</button>
      <button onclick="showCases()" title="Manage cases">&#128193; Cases</button>
      <button onclick="toggleMonitor()" id="btnMonitor" title="Periodic re-scan">&#128276; Monitor: off</button>
      <div class="progress" id="prog"><div class="bar" id="progbar"></div></div>
      <span class="ttl" id="curTitle"></span>
    </div>
    <div class="canvas" id="canvas">
      <div class="placeholder">Connect &rarr; UPN + compromise time &rarr; single probe or <b>live full scan</b>.<br>On connecting you first see the permission preflight matrix.</div>
    </div>
  </section>
</div>
<div class="toast" id="toast"></div>

<script>
const TOKEN="__SESSION_TOKEN__";
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function toast(m,t){const x=$('toast');x.textContent=m;x.className='toast show '+(t||'');setTimeout(()=>x.className='toast',3800);}
function toggleTheme(){document.body.dataset.theme=document.body.dataset.theme==='dark'?'light':'dark';}

const PERMS=[
 {p:'User.Read.All',f:'Basis-Userdaten'},{p:'Directory.Read.All',f:'Rollen, Gruppen, OAuth'},
 {p:'AuditLog.Read.All',f:'Sign-Ins, Audits'},{p:'Mail.Read',f:'E-Mail-Analysis'},
 {p:'MailboxSettings.Read',f:'Inbox rules, mailbox'},{p:'Mail.Send',f:'Report sending'},
 {p:'Files.Read.All',f:'Files, Sharing'},{p:'Sites.Read.All',f:'SharePoint/OneDrive'},
 {p:'Device.Read.All',f:'Devices (Azure AD)'},{p:'DeviceManagementManagedDevices.Read.All',f:'Devices (Intune)'},
 {p:'UserAuthenticationMethod.Read.All',f:'MFA Methods'},{p:'Chat.Read.All',f:'Teams Activity'},
 {p:'IdentityRiskyUser.Read.All',f:'Identity Protection'},{p:'IdentityRiskEvent.Read.All',f:'Risk-Detections'},
 {p:'Policy.Read.All',f:'Conditional Access'},{p:'SecurityAlert.Read.All',f:'Defender Alerts'},
 {p:'User.ReadWrite.All',f:'Containment: disable/PW',w:1},{p:'MailboxSettings.ReadWrite',f:'Containment: delete rule',w:1}];
let grantedRoles=[];

const PROBES=[
 {g:'Identity',id:'devices',label:'Devices'},{g:'Identity',id:'devicedeep',label:'Device Details'},
 {g:'Identity',id:'roles',label:'Roles & Groups'},{g:'Identity',id:'mfa',label:'MFA Methods'},{g:'Identity',id:'oauth',label:'OAuth-Apps'},
 {g:'Data',id:'sites',label:'Sites'},{g:'Data',id:'files',label:'Files',date:1},{g:'Data',id:'sharing',label:'Sharing links'},
 {g:'Comm.',id:'mail',label:'Mail',date:1},{g:'Comm.',id:'mailext',label:'External Mail',date:1},
 {g:'Comm.',id:'rules',label:'Inbox rules'},{g:'Comm.',id:'mailbox',label:'Mailbox'},{g:'Comm.',id:'teams',label:'Teams'},
 {g:'Security',id:'signins',label:'Sign-Ins'},{g:'Security',id:'anomaly',label:'Anomalies'},{g:'Security',id:'fingerprint',label:'Client/Legacy'},
 {g:'Security',id:'risk',label:'Identity Prot.'},{g:'Security',id:'alerts',label:'Defender Alerts'},{g:'Security',id:'capolicies',label:'Cond. Access'},
 {g:'Security',id:'actionsby',label:'Actions/User',date:1},{g:'Security',id:'appcreds',label:'App-Cred-Chg.',date:1},{g:'Security',id:'audits',label:'Perm.-Chg.',date:1},
 {g:'Security',id:'threatintel',label:'Threat-Intel'},
 {g:'Analysis',id:'timeline',label:'Timeline',date:1},{g:'Analysis',id:'ioc',label:'IOC-Bundle',date:1}];

// Live scan: base calls on the server, composites derived client-side (no double fetch)
const SCAN_BASE=['devices','devicedeep','roles','mfa','oauth','sites','files','sharing','mail','rules','mailbox','teams','signins','risk','alerts','capolicies','actionsby','appcreds','audits'];
const SECTION_ORDER=[
 ['devices','Devices'],['devicedeep','Device Details'],['roles','Roles & Groups'],['mfa','MFA Methods'],['oauth','OAuth-Apps'],
 ['sites','SharePoint / OneDrive'],['files','Modified Files'],['sharing','External Sharing Links'],
 ['mail','Email Activity'],['external','External Mail'],['rules','Inbox Rules'],['mailbox','Mailbox Settings'],['teams','Teams Activity'],
 ['signins','Sign-In Logs'],['anomaly','Login Anomalies'],['fingerprint','Client/Legacy-Auth'],['risk','Identity Protection'],
 ['alerts','Defender Alerts'],['capolicies','Conditional Access'],
 ['actionsby','Actions by User'],['appcreds','App Credential Changes'],['audits','Permission Changes'],
 ['timeline','Timeline'],['ioc','IOC-Bundle']];

let results={}, focusRows=null, focusTitle='';
const TABLES={}; let tableSeq=0;

function buildProbes(){
 const box=$('probes');box.innerHTML='';
 [...new Set(PROBES.map(p=>p.g))].forEach(g=>{
   const row=document.createElement('div');row.className='pgroup';
   const lab=document.createElement('span');lab.className='pglabel';lab.textContent=g;row.appendChild(lab);
   PROBES.filter(p=>p.g===g).forEach(p=>{const b=document.createElement('button');b.className='probe';b.id='pb_'+p.id;b.disabled=true;
     b.innerHTML='<span class="led"></span>'+esc(p.label);b.onclick=()=>runProbe(p);row.appendChild(b);});
   box.appendChild(row);});
 const row=document.createElement('div');row.className='pgroup';
 const lab=document.createElement('span');lab.className='pglabel';lab.textContent='Full';row.appendChild(lab);
 const f=document.createElement('button');f.className='probe full';f.id='pb_full';f.disabled=true;
 f.innerHTML='<span class="led"></span>Live full scan (Dashboard)';f.onclick=runFull;row.appendChild(f);
 box.appendChild(row);
}
function setEnabled(on){
 document.querySelectorAll('.probe').forEach(b=>b.disabled=!on);
 ['btnReport','btnSnapshot','c1','c2','c3','c4','c5'].forEach(id=>$(id).disabled=!on);
 $('hdr').className=on?'on':'';$('btnConnect').style.display=on?'none':'';$('btnDisconnect').style.display=on?'':'none';
 $('permLabel').style.display=on?'':'none';
}
async function api(path,body){
 const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-CRP-Token':TOKEN},body:JSON.stringify(body||{})});
 const j=await r.json();if(!r.ok||j.error)throw new Error(j.error||('HTTP '+r.status));return j;}
function params(){return{upn:$('upn').value.trim(),compromiseDate:$('compromiseDate').value,signInDays:$('signInDays').value,homeCountries:$('homeCountries').value,region:$('region').value.trim()};}
function homeArr(){return $('homeCountries').value.split(',').map(s=>s.trim()).filter(Boolean);}
function domainOf(upn){return(upn.split("@").pop()||'').toLowerCase();}

// ---------- Tables (sortable / filterable) ----------
const HIDE=['ErrCode','Country','Lat','Lon','Id'];
function isHot(r){return r.Direction==='Sent'||(r.ErrCode&&r.ErrCode!==0)||(r.Risk&&!['none','hidden',''].includes(r.Risk))||r.ForwardTo||r.Type==='ROLE'||r.Type==='Impossible Travel'||r.Scope==='anonymous'||r.LegacyAuth==='YES';}
function rowsHtml(rows,cols){return rows.map(r=>'<tr'+(isHot(r)?' class="hot"':'')+'>'+cols.map(c=>{let v=r[c];if(typeof v==='string'&&/^https?:\/\//.test(v))return'<td><a href="'+esc(v)+'" target="_blank">'+esc(v)+'</a></td>';return'<td>'+esc(v)+'</td>';}).join('')+'</tr>').join('');}
function makeTable(rows,interactive){
 rows=Array.isArray(rows)?rows:(rows?[rows]:[]);
 if(!rows.length)return'<div class="empty">No data.</div>';
 const cols=Object.keys(rows[0]).filter(c=>!HIDE.includes(c));
 const tid='t'+(tableSeq++);TABLES[tid]={rows:rows.slice(),cols,view:rows.slice(),sc:-1,sd:1};
 let h=interactive?'<input class="tfilter" placeholder="Filter..." oninput="filterTable(\''+tid+'\',this.value)">':'';
 h+='<div class="tablewrap"><table id="'+tid+'"><thead><tr>'+cols.map((c,i)=>interactive?'<th onclick="sortTable(\''+tid+'\','+i+')">'+esc(c)+' <span class="sortarr" id="'+tid+'_a'+i+'"></span></th>':'<th>'+esc(c)+'</th>').join('')+'</tr></thead><tbody id="'+tid+'_b">'+rowsHtml(rows,cols)+'</tbody></table></div>';
 return h;
}
function filterTable(tid,q){const t=TABLES[tid];if(!t)return;q=q.toLowerCase();t.view=t.rows.filter(r=>t.cols.some(c=>String(r[c]==null?'':r[c]).toLowerCase().includes(q)));$(tid+'_b').innerHTML=rowsHtml(t.view,t.cols);}
function sortTable(tid,i){const t=TABLES[tid];if(!t)return;const c=t.cols[i];if(t.sc===i)t.sd*=-1;else{t.sc=i;t.sd=1;}
 t.cols.forEach((_,j)=>{const a=$(tid+'_a'+j);if(a)a.textContent='';});const ar=$(tid+'_a'+i);if(ar)ar.textContent=t.sd>0?'\u25B2':'\u25BC';
 t.view.sort((x,y)=>{let a=x[c],b=y[c];const na=parseFloat(a),nb=parseFloat(b);
   if(!isNaN(na)&&!isNaN(nb)&&String(a).match(/^[\d.\s]+$/)){return(na-nb)*t.sd;}
   const da=Date.parse(a),db=Date.parse(b);if(!isNaN(da)&&!isNaN(db))return(da-db)*t.sd;
   return String(a==null?'':a).localeCompare(String(b==null?'':b))*t.sd;});
 $(tid+'_b').innerHTML=rowsHtml(t.view,t.cols);}

function loading(label){$('canvas').innerHTML='<div class="placeholder"><span class="spin"></span><br><br>'+esc(label)+' running...</div>';}

// ---------- Connect + preflight ----------
async function connect(){
 const b=$('btnConnect');b.disabled=true;b.textContent='Connecting...';
 try{const j=await api('/api/connect',{tenantId:$('tenantId').value.trim(),clientId:$('clientId').value.trim(),clientSecret:$('clientSecret').value});
   grantedRoles=j.roles||[];$('tenant').textContent=(j.org?j.org+' \u00B7 ':'')+j.tenant;
   if(j.region&&!$('region').value)$('region').value=j.region;
   setEnabled(true);updatePermLabel();showPreflight();
   toast('Connected'+(j.region?' (Region '+j.region+')':''),'ok');
 }catch(e){toast('Connection failed: '+e.message,'err');b.disabled=false;}
 b.textContent='Connect';
}
async function disconnect(){try{await api('/api/disconnect',{});}catch{}; setEnabled(false);grantedRoles=[];$('tenant').textContent='not connected';toast('Getrennt');}
function updatePermLabel(){const set=new Set(grantedRoles);const read=PERMS.filter(p=>!p.w);const have=read.filter(p=>set.has(p.p)).length;$('permLabel').innerHTML='Permissions <b>'+have+'</b>/'+read.length;}
function showPreflight(){
 const set=new Set(grantedRoles);focusRows=null;
 let h='<h2 class="sec">Permission preflight</h2><div class="permgrid">';
 PERMS.forEach(p=>{const ok=set.has(p.p);const cls=ok?'ok':(p.w?'opt':'miss');
   h+='<div class="perm '+cls+'"><span class="pled"></span><div><div class="pp">'+esc(p.p)+'</div><div class="pf">'+esc(p.f)+(p.w?' (containment only)':'')+'</div></div></div>';});
 h+='</div><div class="placeholder" style="margin-top:24px">Green = present \u00B7 Red = missing (admin consent needed) \u00B7 Grey = optional for containment.<br>Now enter a UPN and start a probe or the live full scan.</div>';
 $('canvas').innerHTML=h;$('curTitle').textContent='Preflight';
}

// ---------- Single probe ----------
async function runProbe(p){
 if(!$('upn').value.trim()){toast('Please enter a UPN','err');return;}
 if(p.date&&!$('compromiseDate').value){toast('Please choose a compromise time','err');return;}
 const btn=$('pb_'+p.id);btn.className='probe run';loading(p.label);
 try{const j=await api('/api/run',{action:p.id,...params()});
   focusRows=Array.isArray(j.data)?j.data:[];focusTitle=j.title;$('curTitle').textContent=j.title;
   let h='<h2 class="sec">'+esc(j.title)+'<span class="count">'+focusRows.length+' hits</span></h2>';
   if(p.id==='timeline')h+=timelineSvg(focusRows);
   h+=makeTable(focusRows,true);
   $('canvas').innerHTML=h;btn.className='probe ok';
 }catch(e){btn.className='probe err';$('canvas').innerHTML='<div class="placeholder">Error: '+esc(e.message)+'</div>';toast(e.message,'err');}
}

// ---------- Composites client-side ----------
function deriveExternal(mail,upn){const dom=domainOf(upn);const out=[];(mail||[]).filter(m=>m.Direction==='Sent').forEach(m=>{const ext=String(m.Peer||'').split(/,\s*/).filter(x=>x&&!x.toLowerCase().endsWith('@'+dom));if(ext.length)out.push({Date:m.Date,Subject:m.Subject,ExternalRecipients:ext.join(', '),Count:ext.length});});return out;}
function deriveFingerprint(si){const leg=/IMAP|POP|SMTP|ActiveSync|Other clients|AutoDiscover|Exchange Web Services|MAPI|Offline Address Book/i;const m={};(si||[]).forEach(s=>{if(!s.Client)return;m[s.Client]=(m[s.Client]||0)+1;});return Object.entries(m).map(([k,v])=>({Client:k,Count:v,LegacyAuth:leg.test(k)?'YES':'no'})).sort((a,b)=>b.Count-a.Count);}
function hav(a,b,c,d){const R=6371,r=x=>x*Math.PI/180;const dl=r(c-a),dn=r(d-b);const u=Math.sin(dl/2)**2+Math.cos(r(a))*Math.cos(r(c))*Math.sin(dn/2)**2;return R*2*Math.atan2(Math.sqrt(u),Math.sqrt(1-u));}
function deriveAnomaly(si,home){const ok=(si||[]).filter(s=>s.ErrCode===0&&s.Time).slice().sort((a,b)=>Date.parse(a.Time)-Date.parse(b.Time));const out=[];let prev=null;
 ok.forEach(s=>{if(s.Country&&!home.includes(s.Country))out.push({Kind:'Foreign Country',Time:s.Time,Detail:(s.Location||'')+' / '+(s.IP||'')+' / '+(s.App||'')});
  if(prev&&prev.Country&&s.Country&&prev.Country!==s.Country){const dt=(Date.parse(s.Time)-Date.parse(prev.Time))/3.6e6;let sp=null;if(prev.Lat&&prev.Lon&&s.Lat&&s.Lon&&dt>0)sp=Math.round(hav(prev.Lat,prev.Lon,s.Lat,s.Lon)/dt);if(dt>=0&&dt<6){let d='from '+prev.Country+' to '+s.Country+' in '+dt.toFixed(1)+' h';if(sp)d+=' (~'+sp+' km/h)';out.push({Kind:'Impossible Travel',Time:s.Time,Detail:d});}}prev=s;});
 return out.sort((a,b)=>Date.parse(b.Time)-Date.parse(a.Time));}
function deriveTimeline(si,mail,files,audits,actby){const ev=[];(si||[]).forEach(s=>ev.push({Time:s.Time,Type:'Sign-In',Description:(s.App||'')+' / '+(s.IP||'')+' / '+(s.Location||'')+' ['+(s.Status||'')+']'}));
 (mail||[]).forEach(m=>ev.push({Time:m.Date,Type:'Mail-'+m.Direction,Description:(m.Subject||'')+'  ->  '+(m.Peer||'')}));
 (files||[]).forEach(f=>ev.push({Time:f.Modified,Type:'File',Description:f.FileName}));
 (audits||[]).forEach(a=>ev.push({Time:a.Time,Type:'Audit',Description:(a.Activity||'')+' ('+(a.By||'')+')'}));
 (actby||[]).forEach(a=>ev.push({Time:a.Time,Type:'User-Action',Description:(a.Activity||'')+'  ->  '+(a.Target||'')}));
 return ev.filter(e=>e.Time).sort((a,b)=>Date.parse(b.Time)-Date.parse(a.Time));}
function deriveIoc(si,mail,oauth,rules,upn,home){const dom=domainOf(upn);const out=[];const seen=new Set();const add=(T,W,K)=>{const k=T+'|'+W;if(W&&!seen.has(k)){seen.add(k);out.push({Type:T,Value:W,Context:K});}};
 (si||[]).forEach(s=>{if(s.ErrCode!==0||(s.Country&&!home.includes(s.Country)))add('IP',s.IP,(s.Location||'')+' ['+(s.Status||'')+']');});
 (oauth||[]).forEach(g=>add('OAuth-App',g.App,g.Scope));
 (rules||[]).forEach(r=>{if(r.ForwardTo)String(r.ForwardTo).split(/,\s*/).forEach(t=>add('Forwarding-Target',t,r.Rule));});
 (mail||[]).filter(m=>m.Direction==='Sent').forEach(m=>String(m.Peer||'').split(/,\s*/).forEach(t=>{if(t&&!t.toLowerCase().endsWith('@'+dom))add('External-Recipient',t,m.Subject);}));
 return out;}

// ---------- Risk + triage (client-side) ----------
function countSuspicious(si,home){return(si||[]).filter(s=>s.ErrCode!==0||(s.Risk&&!['none','hidden'].includes(s.Risk))||(s.Country&&!home.includes(s.Country))).length;}
function computeRisk(m){let s=0;const f=[];const add=(v,t)=>{if(v>0){s+=v;f.push(t);}};
 add(Math.min(20,Math.floor(m.files/5)),m.files+' modified file(s)');
 add(Math.min(20,m.sent),m.sent+' sent mail(s)');
 add(Math.min(20,m.external*2),m.external+' Mail(s) to external recipients');
 add(Math.min(30,m.suspicious*6),m.suspicious+' suspicious sign-in(s)');
 add(Math.min(40,m.anomalies*15),m.anomalies+' login anomaly(ies)');
 if(m.forward>0){s+=40;f.push(m.forward+' forwarding rule(s)');}
 add(Math.min(25,m.oauth*5),m.oauth+' OAuth app access(es)');
 add(Math.min(20,m.actionsby*2),m.actionsby+' action(s) by the account');
 add(Math.min(45,m.alerts*15),m.alerts+' Defender alert(s)');
 add(Math.min(30,m.anonshares*10),m.anonshares+' anonymous sharing link(s)');
 if(m.risky){s+=40;f.push('Flagged as risky by Identity Protection');}
 const level=s>=60?'HIGH':s>=25?'MEDIUM':'LOW';return{score:s,level,factors:f};}
function computeTriage(R,compDate,home){const out=[];const cd=compDate?Date.parse(compDate):0;
 const push=(sev,title,detail,jump)=>out.push({sev,title,detail,jump});
 if((R.alerts||[]).length)push('CRITICAL','Defender alerts present',(R.alerts.length)+' alert(s) affecting the user','alerts');
 (R.rules||[]).forEach(r=>{if(r.ForwardTo)push('CRITICAL','Active mailbox forwarding','-> '+r.ForwardTo+' (Rule: '+r.Rule+')','rules');});
 const it=(R.anomaly||[]).filter(a=>a.Kind==='Impossible Travel');if(it.length)push('HIGH','Impossible-travel logins',it.length+' case(s)','anomaly');
 if((R.roles||[]).some(x=>x.Type==='ROLE'))push('HIGH','Privileged account','Account holds directory role(s)','roles');
 (R.mfa||[]).forEach(m=>{if(m.Created&&cd&&Date.parse(m.Created)>cd)push('HIGH','New MFA method after compromise',m.Method+' ('+m.Created+')','mfa');});
 if((R.sharing||[]).some(s=>s.Scope==='anonymous'))push('HIGH','Anonymous sharing links','Files shared publicly via link','sharing');
 if((R.appcreds||[]).length)push('HIGH','App Credential Changes',R.appcreds.length+' change(s) to app secrets/certificates','appcreds');
 if((R.oauth||[]).length)push('MEDIUM','OAuth app access',R.oauth.length+' app(s) with access','oauth');
 if((R.fingerprint||[]).some(x=>x.LegacyAuth==='YES'))push('MEDIUM','Legacy-auth sign-ins','Legacy protocols in use','fingerprint');
 if((R.external||[]).length)push('MEDIUM','Mail to external recipients',R.external.length+' external send operations','external');
 const ord={CRITICAL:0,HIGH:1,MEDIUM:2};return out.sort((a,b)=>ord[a.sev]-ord[b.sev]);}

// ---------- Visuals ----------
function gaugeSvg(score){const s=Math.max(0,Math.min(100,score)),ang=Math.PI*(1-s/100),cx=100,cy=100,r=80;
 const x=cx+r*Math.cos(ang),y=cy-r*Math.sin(ang);const col=s>=60?'var(--bad)':s>=25?'var(--warn)':'var(--ok)';
 return '<svg viewBox="0 0 200 120" class="gauge"><path d="M '+(cx-r)+' '+cy+' A '+r+' '+r+' 0 0 1 '+(cx+r)+' '+cy+'" fill="none" stroke="var(--line)" stroke-width="14"/><path d="M '+(cx-r)+' '+cy+' A '+r+' '+r+' 0 0 1 '+x.toFixed(1)+' '+y.toFixed(1)+'" fill="none" stroke="'+col+'" stroke-width="14" stroke-linecap="round"/><text x="'+cx+'" y="'+(cy-8)+'" text-anchor="middle" font-size="34" font-weight="800" fill="'+col+'">'+score+'</text><text x="'+cx+'" y="'+(cy+12)+'" text-anchor="middle" font-size="10" fill="var(--muted)">RISK SCORE</text></svg>';}
function timelineSvg(events){const ev=(events||[]).filter(e=>e.Time).map(e=>({t:Date.parse(e.Time),typ:e.Type,d:e.Description})).filter(e=>!isNaN(e.t)).sort((a,b)=>a.t-b.t);
 if(ev.length<2)return'';const min=ev[0].t,max=ev[ev.length-1].t,span=(max-min)||1,W=1000,H=160,padX=45,padTop=34,axisY=H-42;
 const colors={'Sign-In':'#3ba9f4','Mail-Sent':'#f85149','Mail-Received':'#7d8590','File':'#d29922','Audit':'#a371f7','User-Action':'#3fb950'};
 const lane={'Sign-In':0,'Mail-Sent':1,'Mail-Received':1,'File':2,'Audit':3,'User-Action':3};
 let dots='';ev.forEach(e=>{const x=padX+((e.t-min)/span)*(W-2*padX),y=padTop+(lane[e.typ]||0)*20,c=colors[e.typ]||'#8b97a7';
   dots+='<circle cx="'+x.toFixed(1)+'" cy="'+y+'" r="5" fill="'+c+'"><title>'+esc(new Date(e.t).toLocaleString())+' \u2014 '+esc(e.typ)+': '+esc(e.d)+'</title></circle>';});
 let ticks='';for(let i=0;i<=5;i++){const x=padX+i/5*(W-2*padX),t=new Date(min+span*i/5);ticks+='<line x1="'+x+'" y1="'+axisY+'" x2="'+x+'" y2="'+(axisY+5)+'" stroke="var(--muted)"/><text x="'+x+'" y="'+(axisY+18)+'" font-size="10" fill="var(--muted)" text-anchor="middle">'+t.toLocaleDateString()+'</text>';}
 let leg='';Object.entries(colors).forEach((kv,i)=>{leg+='<circle cx="'+(padX+i*155)+'" cy="14" r="5" fill="'+kv[1]+'"/><text x="'+(padX+i*155+10)+'" y="18" font-size="10" fill="var(--ink)">'+kv[0]+'</text>';});
 return'<svg viewBox="0 0 '+W+' '+H+'" class="tlsvg"><line x1="'+padX+'" y1="'+axisY+'" x2="'+(W-padX)+'" y2="'+axisY+'" stroke="var(--line)"/>'+ticks+dots+'<g>'+leg+'</g></svg>';}

// ---------- Live full scan ----------
async function runFull(){
 const p=params();if(!p.upn){toast('Please enter a UPN','err');return;}
 if(!p.compromiseDate){toast('Please choose a compromise time','err');return;}
 const btn=$('pb_full');btn.className='probe full run';results={};focusRows=null;
 $('prog').classList.add('show');$('progbar').style.width='0';$('curTitle').textContent='Live full scan';
 $('canvas').innerHTML='<div id="dash"></div>';const dash=$('dash');
 const home=homeArr();
 let done=0;const total=SCAN_BASE.length;
 for(const act of SCAN_BASE){
   try{const j=await api('/api/run',{action:act,...p});results[act]=Array.isArray(j.data)?j.data:[];}
   catch(e){results[act]=[];}
   done++;$('progbar').style.width=Math.round(done/total*100)+'%';
   renderDash(dash,home,p.compromiseDate,false);
 }
 // Composites ableiten
 results.external=deriveExternal(results.mail,p.upn);
 results.anomaly=deriveAnomaly(results.signins,home);
 results.fingerprint=deriveFingerprint(results.signins);
 results.timeline=deriveTimeline(results.signins,results.mail,results.files,results.audits,results.actionsby);
 results.ioc=deriveIoc(results.signins,results.mail,results.oauth,results.rules,p.upn,home);
 renderDash(dash,home,p.compromiseDate,true);
 $('prog').classList.remove('show');btn.className='probe full ok';toast('Full scan complete','ok');
}
function metricsFrom(home){const si=results.signins||[];return{
 devices:(results.devices||[]).length,sites:(results.sites||[]).length,files:(results.files||[]).length,
 sent:(results.mail||[]).filter(m=>m.Direction==='Sent').length,received:(results.mail||[]).filter(m=>m.Direction==='Received').length,
 external:(results.external||deriveExternal(results.mail,$('upn').value.trim())).length,
 suspicious:countSuspicious(si,home),anomalies:(results.anomaly||[]).length,oauth:(results.oauth||[]).length,
 alerts:(results.alerts||[]).length,forward:(results.rules||[]).filter(r=>r.ForwardTo).length,
 actionsby:(results.actionsby||[]).length,anonshares:(results.sharing||[]).filter(s=>s.Scope==='anonymous').length,
 risky:(results.risk||[]).some(r=>r.Kind==='RiskyUser'&&['atRisk','confirmedCompromised'].includes(r.State))};}
function renderDash(dash,home,compDate,fin){
 const m=metricsFrom(home);const R=computeRisk(m);
 let h='<div class="dashtop">'+gaugeSvg(R.score)+'<div><div class="risk '+R.level+'">Risk: '+R.level+'</div>';
 h+='<div class="cards" style="margin-top:10px">'+[['Devices',m.devices],['Sites',m.sites],['Files',m.files],['Sent',m.sent],['External',m.external],['Susp. Logins',m.suspicious],['Anomalies',m.anomalies],['OAuth',m.oauth],['Alerts',m.alerts]].map(x=>'<div class="card"><div class="n">'+x[1]+'</div><div class="l">'+x[0]+'</div></div>').join('')+'</div></div></div>';
 if(fin){const tri=computeTriage(results,compDate,home);
   if(tri.length){h+='<h2 class="sec">Auto-triage &ndash; top findings</h2><div class="triage">';
     tri.forEach(t=>{h+='<div class="find '+t.sev+'" onclick="document.getElementById(\'sec_'+t.jump+'\')&&document.getElementById(\'sec_'+t.jump+'\').scrollIntoView({behavior:\'smooth\'})"><span class="sv">'+t.sev+'</span><div><div class="ft">'+esc(t.title)+'</div><div class="fd">'+esc(t.detail)+'</div></div></div>';});
     h+='</div>';}
   else h+='<h2 class="sec">Auto-triage</h2><div class="empty">No high-value indicators detected automatically.</div>';
   if(R.factors.length)h+='<ul>'+R.factors.map(f=>'<li>'+esc(f)+'</li>').join('')+'</ul>';
   const atk=computeAttack(results,compDate,home);
   h+='<h2 class="sec" id="sec_attack">MITRE ATT&amp;CK &middot; Technique-Mapping<span class="count">'+atk.length+'</span></h2>'+attackMatrixHtml(atk);
   const eg=entityGraphSvg(results,$('upn').value.trim());
   if(eg)h+='<h2 class="sec" id="sec_graph">Entity graph &middot; lateral view</h2>'+eg;
 }else{h+='<div class="placeholder" style="margin-top:0"><span class="spin"></span> Collecting data...</div>';}
 // sections
 const src=fin?SECTION_ORDER:SECTION_ORDER.filter(s=>results[s[0]]!==undefined);
 src.forEach(([key,label])=>{const rows=results[key];if(rows===undefined)return;
   h+='<h2 class="sec" id="sec_'+key+'">'+esc(label)+'<span class="count">'+rows.length+'</span></h2>';
   if(key==='timeline')h+=timelineSvg(rows);
   h+=makeTable(rows,false);});
 dash.innerHTML=h;
}

// ---------- Report / Snapshot / Containment ----------
async function sendReport(){const p=params();if(!p.upn){toast('Please enter a UPN','err');return;}
 if(!$('recipient').value.trim()||!$('sender').value.trim()){toast('Recipient and sender required','err');return;}
 const b=$('btnReport');b.disabled=true;b.textContent='Sending...';
 try{const j=await api('/api/report',{...p,recipient:$('recipient').value.trim(),sender:$('sender').value.trim()});toast('Report ('+j.risk+') sent to '+j.recipient,'ok');}
 catch(e){toast('Report failed: '+e.message,'err');}b.disabled=false;b.textContent='Send mail report';}
async function snapshot(){if(!$('upn').value.trim()){toast('Please enter a UPN','err');return;}
 const b=$('btnSnapshot');b.disabled=true;b.textContent='Saving...';loading('Evidence snapshot');
 try{const j=await api('/api/snapshot',{...params(),notes:$('notes').value.trim()});
   $('canvas').innerHTML='<div class="placeholder">Evidence snapshot saved:<br><b>'+esc(j.file)+'</b><br>SHA256: '+esc(j.sha256)+'</div>';toast('Snapshot saved','ok');}
 catch(e){$('canvas').innerHTML='<div class="placeholder">Error: '+esc(e.message)+'</div>';toast('Snapshot failed: '+e.message,'err');}
 b.disabled=false;b.textContent='Evidence snapshot (JSON+SHA256)';}
async function contain(op){const upn=$('upn').value.trim();if(!upn){toast('Please enter a UPN','err');return;}
 let extra={};if(op==='deleterule'){const id=$('ruleId').value.trim();if(!id){toast('Rule ID missing','err');return;}extra.ruleId=id;}
 const labels={revoke:'REVOKE ALL sessions/tokens',disable:'DISABLE the account',resetpw:'RESET the password',deleterule:'DELETE the inbox rule',enable:'RE-ENABLE the account'};
 if(!confirm('Really '+labels[op]+' for '+upn+' ?\n\nThis action actively modifies the tenant.'))return;
 try{const j=await api('/api/contain',{op,upn,confirm:true,...extra});let msg=j.msg;if(j.password)msg+='\nNew temporary password: '+j.password;
   $('canvas').innerHTML='<div class="placeholder">'+esc(msg).replace(/\n/g,'<br>')+'</div>';toast('Containment executed','ok');}
 catch(e){toast('Containment failed: '+e.message,'err');}}

// ---------- Export ----------
function toCsv(rows){const cols=Object.keys(rows[0]);const q=v=>'"'+String(v==null?'':v).replace(/"/g,'""')+'"';
 return[cols.map(q).join(';')].concat(rows.map(r=>cols.map(c=>q(r[c])).join(';'))).join('\r\n');}
function dl(content,name,type){const blob=new Blob([content],{type});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();a.remove();}
function exportCsv(){if(focusRows&&focusRows.length){dl('\ufeff'+toCsv(focusRows),(focusTitle||'export').replace(/[^a-z0-9]+/gi,'_')+'.csv','text/csv;charset=utf-8');toast('CSV exported','ok');}
 else if(Object.keys(results).length){toast('Dashboard: use JSON export','err');}else toast('No data','err');}
function exportJson(){let data,name;if(Object.keys(results).length){data=results;name='fullscan';}else if(focusRows){data=focusRows;name=focusTitle||'export';}else{toast('No data','err');return;}
 dl(JSON.stringify(data,null,2),name.replace(/[^a-z0-9]+/gi,'_')+'.json','application/json');toast('JSON exported','ok');}

async function shutdown(){try{await api('/api/shutdown',{});}catch{}; document.body.innerHTML='<div class="placeholder" style="margin-top:120px">Application stopped. You can close this window.</div>';}

// ================= MITRE ATT&CK (client-side, mirror of the server) =================
function computeAttack(R,compDate,home){const cd=compDate?Date.parse(compDate):0;const rows=[];
 const si=R.signins||[],rul=R.rules||[],mfa=R.mfa||[],appc=R.appcreds||[],oauth=R.oauth||[],sit=R.sites||[],fil=R.files||[],share=R.sharing||[],mext=R.external||[],fp=R.fingerprint||[],roles=R.roles||[];
 const failed=si.filter(s=>s.ErrCode!==0).length;
 const foreign=si.filter(s=>s.Country&&!home.includes(s.Country)).length;
 const fwd=rul.filter(r=>r.ForwardTo).length;
 const del=rul.filter(r=>r.Deletes).length;
 const newMfa=mfa.filter(x=>x.Created&&cd&&Date.parse(x.Created)>cd).length;
 const legacy=fp.filter(x=>x.LegacyAuth==='YES').length;
 const anon=share.filter(s=>s.Scope==='anonymous').length;
 const priv=roles.filter(x=>x.Type==='ROLE').length;
 const add=(t,i,n,b,s)=>rows.push({Tactic:t,TechniqueId:i,Technique:n,Finding:b,Severity:s});
 if(foreign>0)add('Initial Access','T1078.004','Valid Accounts: Cloud Accounts',foreign+' login(s) from non-home country','HIGH');
 if(failed>5)add('Credential Access','T1110','Brute Force',failed+' failed sign-in(s)','MEDIUM');
 if(fwd>0)add('Collection','T1114.003','Email Collection: Forwarding Rule',fwd+' forwarding rule(s)','CRITICAL');
 if(del>0)add('Defense Evasion','T1564.008','Hide Artifacts: Email Hiding Rules',del+' deleting inbox rule(s)','HIGH');
 if(newMfa>0)add('Persistence','T1556','Modify Authentication Process (MFA)',newMfa+' new MFA method(s) after compromise','CRITICAL');
 if(appc.length>0)add('Persistence','T1098.001','Additional Cloud Credentials',appc.length+' app credential change(s)','HIGH');
 if(oauth.length>0)add('Persistence','T1550.001','Use Alternate Auth: App Access Token',oauth.length+' OAuth app access(es)','MEDIUM');
 if(legacy>0)add('Defense Evasion','T1562','Impair Defenses: Legacy Auth',legacy+' legacy auth client(s)','MEDIUM');
 if(sit.length+fil.length>0)add('Collection','T1213','Data from Information Repositories',sit.length+' Site(s), '+fil.length+' file(s)','MEDIUM');
 if(anon>0)add('Exfiltration','T1537','Transfer Data to Cloud Account',anon+' anonymous sharing link(s)','HIGH');
 if(mext.length>0)add('Exfiltration','T1567','Exfiltration Over Web Service',mext.length+' Mail(s) to external recipients','HIGH');
 if(priv>0)add('Privilege Escalation','T1078','Valid Accounts (privileged)','Account holds '+priv+' directory role(s)','HIGH');
 return rows;}
function attackMatrixHtml(rows){if(!rows.length)return'<div class="empty">No ATT&CK techniques derived from the current findings.</div>';
 const tac=[];const by={};rows.forEach(r=>{if(!by[r.Tactic]){by[r.Tactic]=[];tac.push(r.Tactic);}by[r.Tactic].push(r);});
 let h='<div class="attgrid">';
 tac.forEach(t=>{h+='<div class="attcol"><h4>'+esc(t)+'</h4>';
   by[t].forEach(r=>{h+='<div class="attcell '+r.Severity+'"><div class="tid">'+esc(r.TechniqueId)+'</div><div class="tn">'+esc(r.Technique)+'</div><div class="tb">'+esc(r.Finding)+'</div></div>';});
   h+='</div>';});
 return h+'</div>';}
// ================= Entity graph (radial node-link SVG) =================
function entityGraphSvg(R,upn){const home=homeArr();const groups=[];
 const ipset=[...new Set((R.signins||[]).filter(s=>s.IP&&(s.ErrCode!==0||(s.Country&&!home.includes(s.Country)))).map(s=>s.IP))].slice(0,8);
 const cset=[...new Set((R.signins||[]).filter(s=>s.Country).map(s=>s.Country))].slice(0,8);
 const oset=[...new Set((R.oauth||[]).map(o=>o.App).filter(Boolean))].slice(0,8);
 const fset=[];(R.rules||[]).forEach(r=>{if(r.ForwardTo)String(r.ForwardTo).split(/,\s*/).forEach(t=>{if(t)fset.push(t);});});
 const dset=[...new Set((R.devices||[]).map(d=>d.Device||d.Name||d.DisplayName).filter(Boolean))].slice(0,8);
 if(ipset.length)groups.push({label:'Verd. IPs',color:'#f85149',nodes:ipset});
 if(cset.length)groups.push({label:'Laender',color:'#3ba9f4',nodes:cset});
 if(oset.length)groups.push({label:'OAuth-Apps',color:'#a371f7',nodes:oset});
 if(fset.length)groups.push({label:'Weiterleitung',color:'#d29922',nodes:[...new Set(fset)].slice(0,8)});
 if(dset.length)groups.push({label:'Devices',color:'#3fb950',nodes:dset});
 const all=[];groups.forEach(g=>g.nodes.forEach(n=>all.push({g:g,n:n})));
 if(!all.length)return'';
 const W=920,H=540,cx=W/2,cy=H/2+10,r=Math.min(W,H)/2-70;
 let lines='',dots='',cxt='';
 all.forEach((it,i)=>{const a=(i/all.length)*Math.PI*2-Math.PI/2;const x=cx+r*Math.cos(a),y=cy+r*Math.sin(a);
   lines+='<line x1="'+cx+'" y1="'+cy+'" x2="'+x.toFixed(1)+'" y2="'+y.toFixed(1)+'" stroke="var(--line)" stroke-width="1"/>';
   dots+='<circle cx="'+x.toFixed(1)+'" cy="'+y.toFixed(1)+'" r="6" fill="'+it.g.color+'"><title>'+esc(it.g.label+': '+it.n)+'</title></circle>';
   const anchor=x<cx-12?'end':(x>cx+12?'start':'middle');const lx=x+(x<cx-12?-9:(x>cx+12?9:0));
   cxt+='<text x="'+lx.toFixed(1)+'" y="'+(y+3).toFixed(1)+'" font-size="9.5" fill="var(--ink)" text-anchor="'+anchor+'">'+esc(String(it.n).slice(0,28))+'</text>';});
 let leg='';groups.forEach((g,i)=>{leg+='<circle cx="'+(20+i*168)+'" cy="18" r="5" fill="'+g.color+'"/><text x="'+(30+i*168)+'" y="22" font-size="10" fill="var(--ink)">'+esc(g.label)+' ('+g.nodes.length+')</text>';});
 return'<svg viewBox="0 0 '+W+' '+H+'" class="graphsvg">'+lines+'<circle cx="'+cx+'" cy="'+cy+'" r="36" fill="var(--accent)"/><text x="'+cx+'" y="'+(cy-2)+'" text-anchor="middle" font-size="12" font-weight="700" fill="#fff">USER</text><text x="'+cx+'" y="'+(cy+13)+'" text-anchor="middle" font-size="8" fill="#fff">'+esc(String(upn).split("@")[0].slice(0,18))+'</text>'+dots+cxt+'<g>'+leg+'</g></svg>';}
function reRenderDash(){if(!Object.keys(results).length)return;$('canvas').innerHTML='<div id="dash"></div>';renderDash($('dash'),homeArr(),$('compromiseDate').value,true);}
// ================= Threat-Intel-Export: STIX 2.1 =================
function uuid(){try{return crypto.randomUUID();}catch(e){return 'id-'+Date.now()+'-'+Math.floor(Math.random()*1e9);}}
function exportStix(){const ioc=results.ioc||[];if(!ioc.length){toast('No IOCs available (run a live full scan first)','err');return;}
 const now=new Date().toISOString();const objs=[];
 const idobj={type:'identity','spec_version':'2.1',id:'identity--'+uuid(),created:now,modified:now,name:'M365 Compromise Response Console',identity_class:'system'};objs.push(idobj);
 ioc.forEach(i=>{let patt=null;const nm=i.Type+': '+i.Value;
   if(i.Type==='IP')patt="[ipv4-addr:value = '"+i.Value+"']";
   else if(i.Type==='Forwarding-Target'||i.Type==='External-Recipient')patt="[email-addr:value = '"+i.Value+"']";
   else if(i.Type==='OAuth-App')patt="[software:name = '"+String(i.Value).replace(/'/g,'')+"']";
   if(!patt)return;
   objs.push({type:'indicator','spec_version':'2.1',id:'indicator--'+uuid(),created:now,modified:now,name:nm,description:i.Context||'',pattern:patt,'pattern_type':'stix','valid_from':now,'created_by_ref':idobj.id,labels:['malicious-activity']});});
 const bundle={type:'bundle',id:'bundle--'+uuid(),objects:objs};
 dl(JSON.stringify(bundle,null,2),'stix-bundle.json','application/json');toast('STIX 2.1 bundle exported ('+(objs.length-1)+' indicators)','ok');}
// ================= Threat-Intel-Export: MISP =================
function exportMisp(){const ioc=results.ioc||[];if(!ioc.length){toast('No IOCs available (run a live full scan first)','err');return;}
 const attrs=[];ioc.forEach(i=>{let type=null,cat='Network activity';
  if(i.Type==='IP'){type='ip-dst';}
  else if(i.Type==='Forwarding-Target'||i.Type==='External-Recipient'){type='email-dst';cat='Payload delivery';}
  else if(i.Type==='OAuth-App'){type='text';cat='External analysis';}
  if(!type)return;
  attrs.push({type:type,category:cat,'to_ids':type!=='text',value:i.Value,comment:i.Context||''});});
 const ev={Event:{info:'M365 Compromise '+($('upn').value.trim()||''),date:new Date().toISOString().slice(0,10),'threat_level_id':'2',analysis:'1',distribution:'0',Attribute:attrs}};
 dl(JSON.stringify(ev,null,2),'misp-event.json','application/json');toast('MISP event exported ('+attrs.length+' attributes)','ok');}
// ================= Markdown-Report =================
function exportMarkdown(){if(!Object.keys(results).length){toast('Run a live full scan first','err');return;}
 const home=homeArr();const m=metricsFrom(home);const R=computeRisk(m);const atk=computeAttack(results,$('compromiseDate').value,home);const tri=computeTriage(results,$('compromiseDate').value,home);
 const upn=$('upn').value.trim();const nl='\n';let md='# M365 Compromise Report'+nl+nl;
 md+='**User:** '+upn+nl+'**Created:** '+new Date().toLocaleString()+nl+'**Compromised since:** '+($('compromiseDate').value||'-')+nl+nl;
 md+='## Risk: '+R.level+' (Score '+R.score+')'+nl+nl;
 if(R.factors.length){R.factors.forEach(f=>{md+='- '+f+nl;});md+=nl;}
 md+='## Metrics'+nl+nl+'| Metric | Value |'+nl+'| --- | --- |'+nl;
 [['Devices',m.devices],['Sites',m.sites],['Files',m.files],['Sent',m.sent],['External Recipients',m.external],['Susp. Logins',m.suspicious],['Anomalies',m.anomalies],['OAuth-Apps',m.oauth],['Alerts',m.alerts],['Forwards',m.forward],['Anon. shares',m.anonshares]].forEach(x=>{md+='| '+x[0]+' | '+x[1]+' |'+nl;});
 md+=nl+'## Auto-triage'+nl+nl;
 if(tri.length)tri.forEach(t=>{md+='- **['+t.sev+']** '+t.title+' \u2014 '+t.detail+nl;});else md+='_No high-value indicators._'+nl;
 md+=nl+'## MITRE ATT&CK'+nl+nl;
 if(atk.length){md+='| Tactic | Technique | ID | Finding | Severity |'+nl+'| --- | --- | --- | --- | --- |'+nl;atk.forEach(a=>{md+='| '+a.Tactic+' | '+a.Technique+' | '+a.TechniqueId+' | '+a.Finding+' | '+a.Severity+' |'+nl;});}
 else md+='_No techniques derived._'+nl;
 const ioc=results.ioc||[];md+=nl+'## IOCs'+nl+nl;
 if(ioc.length){md+='| Type | Value | Context |'+nl+'| --- | --- | --- |'+nl;ioc.forEach(i=>{md+='| '+i.Type+' | '+i.Value+' | '+(i.Context||'')+' |'+nl;});}
 else md+='_No IOCs._'+nl;
 dl(md,'compromise-report-'+(upn.split("@")[0]||'user')+'.md','text/markdown;charset=utf-8');toast('Markdown report exported','ok');}
// ================= Incident-Response-Playbook (NIST 800-61) =================
let playbook={steps:{},log:[]};let monTimer=null,monBase=null;
const PB=[
 {ph:'1. Identify',id:'i1',t:'Confirm suspicion',d:'Review auto-triage and MITRE ATT&CK mapping',jump:'attack'},
 {ph:'1. Identify',id:'i2',t:'Assess scope',d:'Review sign-ins, anomalies and threat intel',jump:'anomaly'},
 {ph:'1. Identify',id:'i3',t:'Preserve forensic evidence',d:'Create a snapshot with JSON + SHA256',act:'snapshot'},
 {ph:'2. Contain',id:'c1',t:'Revoke active sessions',d:'Invalidate all tokens and refresh tokens',act:'revoke'},
 {ph:'2. Contain',id:'c2',t:'Disable account',d:'Set accountEnabled to false',act:'disable'},
 {ph:'2. Contain',id:'c3',t:'Reset password',d:'Temporary password, change at sign-in',act:'resetpw'},
 {ph:'3. Eradicate',id:'e1',t:'Remove malicious forwarding',d:'Delete suspicious inbox rules by ID',jump:'rules'},
 {ph:'3. Eradicate',id:'e2',t:'Revoke OAuth grants',d:'Revoke unknown app permissions',jump:'oauth'},
 {ph:'3. Eradicate',id:'e3',t:'Clean up MFA methods',d:'Remove attacker-registered methods',jump:'mfa'},
 {ph:'4. Recover',id:'r1',t:'Re-enable account in a controlled way',d:'After cleanup set accountEnabled to true',act:'enable'},
 {ph:'4. Recover',id:'r2',t:'Enable monitoring',d:'Start a periodic re-scan',act:'monitor'},
 {ph:'4. Recover',id:'r3',t:'Send final report',d:'Mail report to SOC or management',act:'report'}];
function pblog(msg){playbook.log.unshift(new Date().toLocaleTimeString()+'  '+msg);if(playbook.log.length>60)playbook.log.length=60;}
function showPlaybook(){focusRows=null;const phs=[];const by={};PB.forEach(s=>{if(!by[s.ph]){by[s.ph]=[];phs.push(s.ph);}by[s.ph].push(s);});
 const done=PB.filter(s=>playbook.steps[s.id]).length;const pct=Math.round(done/PB.length*100);
 let h='<h2 class="sec">Incident-Response-Playbook &middot; NIST 800-61<span class="count">'+done+'/'+PB.length+'</span></h2>';
 h+='<div class="pbbar"><div style="width:'+pct+'%"></div></div>';
 phs.forEach(p=>{const d=by[p].filter(s=>playbook.steps[s.id]).length;
   h+='<div class="pbphase"><h3>'+esc(p)+'<span class="pc">'+d+'/'+by[p].length+'</span></h3>';
   by[p].forEach(s=>{const ck=playbook.steps[s.id]?'checked':'';
     h+='<div class="pbstep '+(playbook.steps[s.id]?'done':'')+'"><input type="checkbox" '+ck+' onclick="pbToggle(\''+s.id+'\',this.checked)"><div class="s"><div class="st">'+esc(s.t)+'</div><div class="sd">'+esc(s.d)+'</div></div>';
     if(s.act)h+='<button onclick="pbDo(\''+s.act+'\')">Run</button>';
     else if(s.jump)h+='<button onclick="pbJump(\''+s.jump+'\')">Show</button>';
     h+='</div>';});
   h+='</div>';});
 h+='<div class="actionlog" id="pblog">'+(playbook.log.length?playbook.log.map(l=>'<div class="al">'+esc(l)+'</div>').join(''):'<div class="al" style="color:var(--muted)">No actions logged yet.</div>')+'</div>';
 $('canvas').innerHTML=h;$('curTitle').textContent='Playbook';}
function pbToggle(id,on){playbook.steps[id]=on;pblog((on?'done: ':'open: ')+id);showPlaybook();}
function pbJump(key){if(!Object.keys(results).length){toast('Run a live full scan first','err');return;}
 reRenderDash();setTimeout(()=>{const el=$('sec_'+key);if(el)el.scrollIntoView({behavior:'smooth'});else toast('Section not in dashboard','err');},80);}
function pbDo(act){
 if(act==='snapshot'){pblog('Snapshot triggered');snapshot();}
 else if(act==='report'){pblog('Mail report triggered');sendReport();}
 else if(act==='monitor'){toggleMonitor();pblog('Monitoring toggled: '+(monTimer?'an':'aus'));showPlaybook();}
 else if(['revoke','disable','resetpw','enable'].includes(act)){pblog('Containment "'+act+'" triggered');contain(act);}
}
// ================= Case management =================
async function showCases(){focusRows=null;loading('Cases');
 try{const j=await api('/api/cases',{});const cs=j.cases||[];
   let h='<h2 class="sec">Case management<span class="count">'+cs.length+'</span></h2>';
   h+='<div style="margin:6px 0 14px;display:flex;gap:8px"><button class="primary" onclick="saveCase()">&#128190; Save current case</button><button onclick="showCases()">&#8635; Refresh</button></div>';
   if(!cs.length)h+='<div class="empty">No saved cases yet. Run a full scan and save the case.</div>';
   else{h+='<div class="caselist">';cs.forEach(c=>{const rc=c.risk==='HIGH'?'HIGH':(c.risk==='MEDIUM'?'MEDIUM':'LOW');
     h+='<div class="caseitem"><span class="risk '+rc+'" style="padding:3px 9px;font-size:11px">'+esc(c.risk||'?')+' '+esc(String(c.score||''))+'</span><div class="ci"><div class="cu">'+esc(c.upn||c.id)+'</div><div class="cm">'+esc(c.created)+(c.notes?' \u00B7 '+esc(c.notes):'')+'</div></div><button onclick="loadCase(\''+esc(c.id)+'\')">Load</button><button onclick="delCase(\''+esc(c.id)+'\')">Delete</button></div>';});
     h+='</div>';}
   $('canvas').innerHTML=h;$('curTitle').textContent='Cases';
 }catch(e){$('canvas').innerHTML='<div class="placeholder">Error: '+esc(e.message)+'</div>';toast(e.message,'err');}}
async function saveCase(){const upn=$('upn').value.trim();if(!upn){toast('Please enter a UPN','err');return;}
 if(!Object.keys(results).length){toast('Run a live full scan first','err');return;}
 const home=homeArr();const m=metricsFrom(home);const R=computeRisk(m);const atk=computeAttack(results,$('compromiseDate').value,home);
 try{const j=await api('/api/case',{op:'save',upn:upn,notes:$('notes').value.trim(),results:results,risk:{level:R.level,score:R.score},metrics:m,attack:atk,playbook:playbook});
   toast('Case saved: '+j.id,'ok');showCases();}
 catch(e){toast('Save failed: '+e.message,'err');}}
async function loadCase(id){loading('Load case');
 try{const j=await api('/api/case',{op:'load',id:id});const c=j.case;results=c.results||{};
   if(c.playbook&&c.playbook.steps)playbook=c.playbook;if(!playbook.log)playbook.log=[];if(c.upn)$('upn').value=c.upn;
   reRenderDash();toast('Case loaded: '+(c.upn||id),'ok');}
 catch(e){$('canvas').innerHTML='<div class="placeholder">Error: '+esc(e.message)+'</div>';toast(e.message,'err');}}
async function delCase(id){if(!confirm('Really delete case '+id+'?'))return;
 try{await api('/api/case',{op:'delete',id:id});toast('Case deleted','ok');showCases();}
 catch(e){toast('Delete failed: '+e.message,'err');}}
// ================= Live monitoring (periodic re-scan) =================
function toggleMonitor(){const btn=$('btnMonitor');
 if(monTimer){clearInterval(monTimer);monTimer=null;monBase=null;btn.innerHTML='&#128276; Monitor: off';toast('Monitoring stopped');return;}
 const p=params();if(!p.upn){toast('Please enter a UPN','err');return;}
 if(!p.compromiseDate){toast('Please choose a compromise time','err');return;}
 const keys=['signins','rules','oauth','alerts','sharing','mfa'];monBase={};
 const scan=async()=>{for(const k of keys){try{const j=await api('/api/run',{action:k,...p});const arr=Array.isArray(j.data)?j.data:[];
    if(monBase[k]!==undefined&&arr.length>monBase[k]){const dn=arr.length-monBase[k];toast('Monitor: NEW findings in "'+k+'" (+'+dn+')','err');pblog('MONITOR +'+dn+' in '+k);}
    monBase[k]=arr.length;results[k]=arr;}catch(e){}}};
 btn.innerHTML='&#128277; Monitor: on';toast('Monitoring active (every 90s)','ok');scan();monTimer=setInterval(scan,90000);}
buildProbes();
</script></body></html>
'@

# =====================================================================
#  Webserver
# =====================================================================
function Open-Browser { param([string]$Url)
    try { if ($IsWindows) { Start-Process $Url } elseif ($IsMacOS) { & open $Url } else { & xdg-open $Url } }
    catch { Write-Log "Please open the browser manually: $Url" 'WARN' }
}

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$Port/")
try { $listener.Start() } catch { Write-Log "Could not bind port ${Port}: $($_.Exception.Message)" 'ERROR'; throw }

$url = "http://localhost:$Port/"
Write-Host ''
Write-Log "M365 Compromise Response Console is running." 'OK'
Write-Log "URL: $url" 'OK'
Write-Log "(Stop with Ctrl+C or the 'Quit application' button.)" 'INFO'
Write-Host ''
if (-not $NoBrowser) { Open-Browser $url }

$running = $true
try {
    while ($running -and $listener.IsListening) {
        $ctx = $listener.GetContext()
        $req = $ctx.Request; $res = $ctx.Response
        try {
            $path = $req.Url.AbsolutePath
            if ($req.HttpMethod -eq 'GET' -and ($path -eq '/' -or $path -eq '/index.html')) {
                $page = $indexHtml.Replace('__SESSION_TOKEN__', $script:SessionToken)
                $buf  = [Text.Encoding]::UTF8.GetBytes($page)
                $res.ContentType = 'text/html; charset=utf-8'
                $res.OutputStream.Write($buf,0,$buf.Length); $res.Close(); continue
            }
            if ($path -like '/api/*') {
                $reqHost = $req.UserHostName
                # Exact match only - a prefix match ('localhost*') would let a DNS-rebinding
                # domain like 'localhost-evil.com' pass as same-origin.
                $allowedHosts = @("localhost:$Port","127.0.0.1:$Port","[::1]:$Port",'localhost','127.0.0.1','[::1]')
                if ($reqHost -notin $allowedHosts) { $res.StatusCode=403; $res.Close(); continue }
                if ($req.Headers['X-CRP-Token'] -ne $script:SessionToken) {
                    $res.StatusCode=403
                    $b=[Text.Encoding]::UTF8.GetBytes('{"error":"Invalid session token."}')
                    $res.ContentType='application/json'; $res.OutputStream.Write($b,0,$b.Length); $res.Close(); continue
                }
                $bodyText=''
                if ($req.HasEntityBody) {
                    $reader=[System.IO.StreamReader]::new($req.InputStream,$req.ContentEncoding)
                    $bodyText=$reader.ReadToEnd(); $reader.Dispose()
                }
                $data = if ($bodyText) { $bodyText | ConvertFrom-Json } else { $null }

                if ($path -eq '/api/shutdown') {
                    $b=[Text.Encoding]::UTF8.GetBytes('{"ok":true}')
                    $res.ContentType='application/json'; $res.OutputStream.Write($b,0,$b.Length); $res.Close()
                    Write-Log 'Shutdown requested.' 'INFO'; $running=$false; break
                }
                try {
                    $result = Invoke-ApiAction -Path $path -Data $data
                    $json = $result | ConvertTo-Json -Depth 12 -Compress
                    $res.StatusCode = 200
                } catch {
                    Write-Log "API error: $($_.Exception.Message)" 'ERROR'
                    $json = @{ error = $_.Exception.Message } | ConvertTo-Json -Compress
                    $res.StatusCode = 400
                }
                $b=[Text.Encoding]::UTF8.GetBytes($json)
                $res.ContentType='application/json; charset=utf-8'
                $res.OutputStream.Write($b,0,$b.Length); $res.Close(); continue
            }
            $res.StatusCode=404; $res.Close()
        }
        catch {
            Write-Log "Request error: $($_.Exception.Message)" 'ERROR'
            try { $res.StatusCode=500; $res.Close() } catch {}
        }
    }
}
finally {
    if ($listener.IsListening) { $listener.Stop() }
    $listener.Close()
    $script:Creds=$null; $script:Token=$null; [GC]::Collect()
    Write-Log 'Server stopped.' 'INFO'
}
