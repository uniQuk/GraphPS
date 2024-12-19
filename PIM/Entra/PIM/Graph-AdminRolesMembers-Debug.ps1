# Description: Retrieve all Azure AD roles and their members
# Compliments the Graph-PIMGroupReport script
# Can be used to show which users/groups are assigned to which roles. Useful to find Admins with direct assignments outside of PIM.

# Script01: Graph-AdminRolesMembers.ps1
# Script02: Graph-AdminRolesMembers-EC.ps1 - Same output with basic Debug and Error Checking.

param (
    [switch]$DebugMode
)

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Get-AdminRoles {
    param (
        [string]$Uri
    )
    
    try {
        $response = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        return $response.value
    } catch {
        Write-Error "Failed to retrieve admin roles: $_"
        exit
    }
}

function Get-RoleMembers {
    param (
        [string]$RoleId,
        [string]$UriTemplate
    )
    
    $uri = $UriTemplate -f $roleId
    try {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        return $response.value | ForEach-Object { $_.displayName }
    } catch {
        Write-Error "Failed to retrieve members for role ID $RoleId : $_"
        return @()
    }
}

$adminRoles = Get-AdminRoles -Uri "/v1.0/directoryRoles/"
$roleUserResults = foreach ($role in $adminRoles) {
    if ([string]::IsNullOrEmpty($role.id)) {
        Write-Error "No ID found for role $($role.displayName)"
        continue
    }

    $members = Get-RoleMembers -RoleId $role.id -UriTemplate "/v1.0/directoryRoles/{0}/members"
    
    [PSCustomObject][ordered]@{
        AdminRole = $role.displayName    
        RoleID = $role.id
        Members = $members -join ","
    }
}

$stopwatch.Stop()
Write-Host "Total execution time: $($stopwatch.Elapsed.TotalSeconds) seconds"

if ($DebugMode) {
    Write-Output $roleUserResults
} else {
    $roleUserResults | Out-ConsoleGridView
}
