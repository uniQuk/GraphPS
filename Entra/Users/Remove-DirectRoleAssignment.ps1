# Remove-DirectRoleAssignment.ps1
# Script to check for direct role assignments and optionally remove them
# Requires Microsoft.Graph PowerShell module

param(
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory=$true)]
    [string]$RoleName,
    
    [Parameter(Mandatory=$false)]
    [switch]$RemoveAssignment = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force = $false
)

# Function to ensure Graph connection
function Ensure-GraphConnection {
    try {
        $context = Get-MgContext -ErrorAction Stop
        if ($null -eq $context) {
            throw "Not connected to Microsoft Graph"
        }
        
        Write-Host "Connected to Microsoft Graph as $($context.Account)" -ForegroundColor Green
        
        # Check for required permissions
        $requiredScopes = @("Directory.Read.All", "RoleManagement.ReadWrite.Directory")
        $missingScopes = $requiredScopes | Where-Object { $context.Scopes -notcontains $_ }
        
        if ($missingScopes.Count -gt 0) {
            Write-Warning "Missing required permissions: $($missingScopes -join ', ')"
            Write-Host "Please reconnect with these scopes: $($requiredScopes -join ', ')" -ForegroundColor Yellow
            return $false
        }
        
        return $true
    }
    catch {
        Write-Host "Not connected to Microsoft Graph. Connecting now..." -ForegroundColor Yellow
        try {
            Connect-MgGraph -Scopes "Directory.Read.All", "RoleManagement.ReadWrite.Directory" -ErrorAction Stop
            Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph: $_"
            return $false
        }
    }
}

# Function to get user information
function Get-UserInfo {
    param (
        [string]$UserPrincipalName
    )
    
    try {
        $user = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
        return $user
    }
    catch {
        Write-Error "Failed to find user '$UserPrincipalName': $_"
        return $null
    }
}

# Function to get directory role by name
function Get-DirectoryRoleByName {
    param (
        [string]$RoleName
    )
    
    try {
        # First try active directory roles
        $directoryRoles = Get-MgDirectoryRole -All
        $role = $directoryRoles | Where-Object { $_.DisplayName -eq $RoleName }
        
        if ($null -eq $role) {
            # If not found, check role templates
            Write-Host "Role not found in active directory roles. Checking role templates..." -ForegroundColor Yellow
            $roleTemplates = Get-MgDirectoryRoleTemplate
            $roleTemplate = $roleTemplates | Where-Object { $_.DisplayName -eq $RoleName }
            
            if ($null -ne $roleTemplate) {
                Write-Host "Found role template for '$RoleName'. Activating role..." -ForegroundColor Yellow
                # Activate the role
                $params = @{
                    RoleTemplateId = $roleTemplate.Id
                }
                $role = New-MgDirectoryRole -BodyParameter $params
            }
        }
        
        return $role
    }
    catch {
        Write-Error "Failed to find role '$RoleName': $_"
        return $null
    }
}

# Function to check if user is a direct member of role
function Test-UserInDirectoryRole {
    param (
        [string]$UserId,
        [string]$RoleId
    )
    
    try {
        $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId
        $isMember = $roleMembers | Where-Object { $_.Id -eq $UserId }
        
        return ($null -ne $isMember)
    }
    catch {
        Write-Error "Failed to check role membership: $_"
        return $false
    }
}

# Function to remove user from directory role
function Remove-UserFromDirectoryRole {
    param (
        [string]$UserId,
        [string]$RoleId,
        [string]$UserPrincipalName,
        [string]$RoleName
    )
    
    try {
        Write-Host "Attempting to remove user '$UserPrincipalName' from role '$RoleName'..." -ForegroundColor Yellow
        Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $RoleId -DirectoryObjectId $UserId
        Write-Host "Successfully removed user '$UserPrincipalName' from role '$RoleName'" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to remove user from role: $_"
        return $false
    }
}

# Main script execution
if (-not (Ensure-GraphConnection)) {
    Write-Error "Failed to establish Graph connection. Exiting script."
    exit 1
}

Write-Host "Checking direct role assignment for user '$UserPrincipalName' in role '$RoleName'..." -ForegroundColor Cyan

# Get user information
$user = Get-UserInfo -UserPrincipalName $UserPrincipalName
if ($null -eq $user) {
    Write-Error "User not found. Exiting script."
    exit 1
}

# Get directory role
$role = Get-DirectoryRoleByName -RoleName $RoleName
if ($null -eq $role) {
    Write-Error "Role not found. Exiting script."
    exit 1
}

Write-Host "User: $($user.DisplayName) ($($user.Id))" -ForegroundColor Cyan
Write-Host "Role: $($role.DisplayName) ($($role.Id))" -ForegroundColor Cyan

# Check if user is a direct member of the role
$isMember = Test-UserInDirectoryRole -UserId $user.Id -RoleId $role.Id

if ($isMember) {
    Write-Host "User '$($user.DisplayName)' is directly assigned to role '$($role.DisplayName)'" -ForegroundColor Yellow
    
    if ($RemoveAssignment) {
        if (-not $Force) {
            $confirmation = Read-Host "Are you sure you want to remove this role assignment? (y/n)"
            if ($confirmation -ne "y") {
                Write-Host "Operation cancelled by user." -ForegroundColor Yellow
                exit 0
            }
        }
        
        $result = Remove-UserFromDirectoryRole -UserId $user.Id -RoleId $role.Id -UserPrincipalName $UserPrincipalName -RoleName $RoleName
        if ($result) {
            Write-Host "Role assignment removal completed successfully." -ForegroundColor Green
        }
        else {
            Write-Error "Failed to remove role assignment."
            exit 1
        }
    }
    else {
        Write-Host "To remove this assignment, run the script with -RemoveAssignment parameter" -ForegroundColor Yellow
    }
}
else {
    Write-Host "User '$($user.DisplayName)' is NOT directly assigned to role '$($role.DisplayName)'" -ForegroundColor Green
    Write-Host "The user may have the role through group membership or PIM eligibility" -ForegroundColor Yellow
}

# Check PIM eligible assignments if available
Write-Host "`nChecking for PIM eligibility..." -ForegroundColor Cyan
try {
    # This requires the PIM module or additional permissions
    # This is a simplified check and may need to be expanded based on your environment
    $roleDefinitionId = $role.RoleTemplateId
    if ($null -ne $roleDefinitionId) {
        Write-Host "To check PIM eligibility, use the following command:" -ForegroundColor Yellow
        Write-Host "Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter `"principalId eq '$($user.Id)' and roleDefinitionId eq '$roleDefinitionId'`"" -ForegroundColor Gray
        Write-Host "Note: PIM management requires additional permissions and may need different commands." -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Unable to check PIM eligibility: $_"
}

Write-Host "`nScript execution completed." -ForegroundColor Cyan 
