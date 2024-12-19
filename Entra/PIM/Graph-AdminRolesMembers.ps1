# Description: Retrieve all Azure AD roles and their members
# Compliments the Graph-PIMGroupReport script
# Can be used to show which users/groups are assigned to which roles. Useful to find Admins with direct assignments outside of PIM.

# Script01: Graph-AdminRolesMembers.ps1
# Script02: Graph-AdminRolesMembers-EC.ps1 - Same with basic Debug and Error Checking.

# Created by: uniQuk 2024

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$getAdminRoles = "/v1.0/directoryRoles/"
try {
    $roleRequest = Invoke-MgGraphRequest -Method GET -Uri $getAdminRoles -OutputType PSObject | select -ExpandProperty value
} catch {
    Write-Error "Failed to retrieve admin roles: $_"
    exit
}

$roleResult = $roleRequest | ForEach-Object {
    # Debug output
    Write-Debug "Role ID: $($_.id)"
    Write-Debug "Display Name: $($_.displayName)"
    
    [PSCustomObject]@{
        displayName = $_.displayName
        id = $_.id
    }
}

$roleUserResult = $roleResult | ForEach-Object {
    # Validate ID exists
    if ([string]::IsNullOrEmpty($_.id)) {
        Write-Error "No ID found for role $($_.displayName)"
        return
    }
    
    # Use -f operator for string formatting
    $getRoleMembers = "/v1.0/directoryRoles/{0}/members" -f $_.id
    
    Write-Debug "Requesting URL: $getRoleMembers"
    
    try {
        $roleMembers = Invoke-MgGraphRequest -Method GET -Uri $getRoleMembers -OutputType PSObject | select -ExpandProperty value
    } catch {
        Write-Error "Failed to retrieve members for role $($_.displayName): $_"
        return
    }

    $members = $roleMembers | ForEach-Object { $_.displayName }

    [PSCustomObject][ordered]@{
        AdminRole = $_.displayName    
        RoleID = $_.id
        Members = $members -join ","
    }
}

# Performance metrics
$stopwatch.Stop()
Write-Host "Total execution time: $($stopwatch.Elapsed.TotalSeconds) seconds"

$roleUserResult | Out-ConsoleGridView

