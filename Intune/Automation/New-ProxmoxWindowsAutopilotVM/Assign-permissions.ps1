Connect-MgGraph -Scopes `
    "Application.Read.All",
    "AppRoleAssignment.ReadWrite.All"

$ManagedIdentityObjectId = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

$Permissions = @(
    "DeviceManagementServiceConfig.ReadWrite.All"
)

$GraphAppId = "00000003-0000-0000-c000-000000000000"

$GraphSP = Invoke-MgGraphRequest `
    -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$GraphAppId'"

$GraphSP = $GraphSP.value[0]

foreach ($Permission in $Permissions) {
    $AppRole = $GraphSP.appRoles |
        Where-Object {
            $_.value -eq $Permission -and
            $_.allowedMemberTypes -contains "Application"
        }

    if (-not $AppRole) {
        Write-Warning "Berechtigung nicht gefunden: $Permission"
        continue
    }

    $Body = @{
        principalId = $ManagedIdentityObjectId
        resourceId  = $GraphSP.id
        appRoleId   = $AppRole.id
    }

    try {
        Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ManagedIdentityObjectId/appRoleAssignments" `
            -Body ($Body | ConvertTo-Json) `
            -ContentType "application/json"

        Write-Host "Zugewiesen: $Permission" -ForegroundColor Green
    }
    catch {
        if ($_.Exception.Message -match "Permission being assigned already exists") {
            Write-Host "Bereits vorhanden: $Permission" -ForegroundColor Yellow
        }
        else {
            Write-Error "Fehler bei $Permission`: $($_.Exception.Message)"
        }
    }
}

Disconnect-MgGraph