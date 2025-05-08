#Requires -Modules @{ ModuleName="Microsoft.Graph.Applications"; ModuleVersion="2.0.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="2.0.0" }

<#
.SYNOPSIS
    Creates a single app registration with flexible API permission selection.
.DESCRIPTION
    This script creates a single app registration with custom API permissions.
    It supports multiple API types:
    - Microsoft Graph API
    - Rights Management Services API
    - Exchange Online API
    Any combination of permissions across these APIs can be specified.
.PARAMETER AppName
    Display name for the app registration
.PARAMETER GraphPermissions
    Array of Microsoft Graph API permissions
.PARAMETER RmsPermissions
    Array of Rights Management Services API permissions
.PARAMETER ExchangePermissions
    Array of Exchange Online API permissions
.EXAMPLE
    # Create an app with only Graph permissions
    .\New-SingleAppRegistration.ps1 -AppName "MyGraphApp" -GraphPermissions @("Directory.Read.All", "User.Read.All")
.EXAMPLE
    # Create an app with Graph and RMS permissions
    .\New-SingleAppRegistration.ps1 -AppName "MyApp" -GraphPermissions @("Directory.Read.All") -RmsPermissions @("Content.SuperUser")
.EXAMPLE
    # Create an app with all types of permissions
    .\New-SingleAppRegistration.ps1 -AppName "MyCompleteApp" -GraphPermissions @("Directory.Read.All") -RmsPermissions @("Content.SuperUser") -ExchangePermissions @("full_access_as_app")
.NOTES
    Author: Josh
    Date: May 8, 2025
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppName,
    
    [Parameter(Mandatory = $false)]
    [string[]]$GraphPermissions = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$RmsPermissions = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExchangePermissions = @()
)

# Well-known service principal AppIds
$KnownAppIds = @{
    MicrosoftGraph = "00000003-0000-0000-c000-000000000000"
    ExchangeOnline = "00000002-0000-0ff1-ce00-000000000000"
    RightsManagement = "00000012-0000-0000-c000-000000000000"
    MIPSyncService = "870c4f2e-85b6-4d43-bdda-6ed9a579b725"
}

# Function to find a service principal by display name
function Get-ServicePrincipalByName {
    param (
        [string]$Name
    )
    
    Write-Verbose "Searching for service principal: $Name..."
    $servicePrincipals = Get-MgServicePrincipal -Filter "displayName eq '$Name'" -All
    
    if ($servicePrincipals -and $servicePrincipals.Count -gt 0) {
        Write-Verbose "Found service principal: $Name"
        return $servicePrincipals[0]
    }
    
    # If exact match not found, try a broader search
    $servicePrincipals = Get-MgServicePrincipal -Filter "startsWith(displayName, '$Name')" -All
    
    if ($servicePrincipals -and $servicePrincipals.Count -gt 0) {
        Write-Verbose "Found service principal starting with: $Name"
        return $servicePrincipals[0]
    }
    
    Write-Warning "No service principal found with name: $Name"
    return $null
}

# Function to find and add an app role to required resource access
function Add-AppRoleToRequiredAccess {
    param (
        $ServicePrincipal,
        [string]$RoleName,
        [ref]$RequiredResourceAccess
    )
    
    $appRole = $ServicePrincipal.AppRoles | Where-Object { $_.Value -eq $RoleName }
    
    if ($appRole) {
        Write-Verbose "Found role '$RoleName' in $($ServicePrincipal.DisplayName)"
        
        # Find or create resource access entry
        $resourceAccess = $RequiredResourceAccess.Value | Where-Object { $_.ResourceAppId -eq $ServicePrincipal.AppId }
        
        if (-not $resourceAccess) {
            $resourceAccess = @{
                ResourceAppId  = $ServicePrincipal.AppId
                ResourceAccess = @()
            }
            $RequiredResourceAccess.Value += $resourceAccess
        }
        
        # Add the app role to resource access
        $resourceAccess.ResourceAccess += @{
            Id   = $appRole.Id
            Type = "Role"
        }
        
        Write-Verbose "Added role '$RoleName' to required resource access"
        return $true
    }
    else {
        Write-Warning "Role '$RoleName' not found in $($ServicePrincipal.DisplayName)"
        return $false
    }
}

# Function to get Rights Management and MIP Sync service principals
function Get-RightsManagementServicePrincipals {
    Write-Verbose "Searching for Rights Management service principals..."
    
    # Initialize service principal variables
    $rmsServicePrincipal = $null
    $mipServicePrincipal = $null
    
    # Try multiple possible names for the Azure Rights Management Service
    $possibleRmsNames = @(
        "Azure Rights Management Services",
        "Microsoft Rights Management Services",
        "Rights Management Services",
        "Azure Information Protection"
    )
    
    $possibleMipNames = @(
        "Microsoft Information Protection Sync Service"
    )
    
    # Find RMS service principal
    foreach ($name in $possibleRmsNames) {
        $sp = Get-ServicePrincipalByName -Name $name
        if ($sp) {
            $rmsServicePrincipal = $sp
            Write-Verbose "Found Rights Management Service: $($sp.DisplayName) (AppId: $($sp.AppId))"
            break
        }
    }
    
    # Find MIP service principal
    foreach ($name in $possibleMipNames) {
        $sp = Get-ServicePrincipalByName -Name $name
        if ($sp) {
            $mipServicePrincipal = $sp
            Write-Verbose "Found MIP Sync Service: $($sp.DisplayName) (AppId: $($sp.AppId))"
            break
        }
    }
    
    # If not found by name, try well-known AppIds
    if (-not $rmsServicePrincipal) {
        Write-Verbose "Trying to find Rights Management Service by well-known AppId..."
        $sp = Get-MgServicePrincipal -Filter "appId eq '$($KnownAppIds.RightsManagement)'"
        if ($sp) {
            $rmsServicePrincipal = $sp
            Write-Verbose "Found Rights Management Service by AppId: $($sp.DisplayName)"
        }
    }
    
    if (-not $mipServicePrincipal) {
        Write-Verbose "Trying to find MIP Sync Service by well-known AppId..."
        $sp = Get-MgServicePrincipal -Filter "appId eq '$($KnownAppIds.MIPSyncService)'"
        if ($sp) {
            $mipServicePrincipal = $sp
            Write-Verbose "Found MIP Sync Service by AppId: $($sp.DisplayName)"
        }
    }
    
    # Return both service principals
    return @{
        RmsServicePrincipal = $rmsServicePrincipal
        MipServicePrincipal = $mipServicePrincipal
    }
}

# Main execution flow
try {
    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "Application.ReadWrite.All"
    Write-Host "Connected to Microsoft Graph successfully." -ForegroundColor Green
    
    # Check if app already exists
    $existingApp = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue
    
    if ($existingApp) {
        Write-Warning "App registration '$AppName' already exists. Please choose a different name."
        return
    }
    
    # Initialize required resource access array
    $requiredResourceAccess = @()
    
    # Process Microsoft Graph API permissions
    if ($GraphPermissions -and $GraphPermissions.Count -gt 0) {
        Write-Host "Processing Microsoft Graph API permissions..." -ForegroundColor Cyan
        
        # Get Microsoft Graph service principal
        $graphSP = Get-MgServicePrincipal -Filter "appId eq '$($KnownAppIds.MicrosoftGraph)'"
        
        if ($graphSP) {
            $resourceAccesses = @()
            
            foreach ($permission in $GraphPermissions) {
                $appRole = $graphSP.AppRoles | Where-Object { $_.Value -eq $permission }
                
                if ($appRole) {
                    $resourceAccesses += @{
                        Id   = $appRole.Id
                        Type = "Role"
                    }
                    Write-Verbose "Added Graph permission: $permission"
                } else {
                    Write-Warning "Graph permission '$permission' not found. Skipping."
                }
            }
            
            # Add Graph API permissions if any were found
            if ($resourceAccesses.Count -gt 0) {
                $requiredResourceAccess += @{
                    ResourceAppId  = $graphSP.AppId
                    ResourceAccess = $resourceAccesses
                }
                Write-Host "Added $($resourceAccesses.Count) Microsoft Graph permissions." -ForegroundColor Green
            }
        } else {
            Write-Error "Microsoft Graph service principal not found. Cannot add Graph API permissions."
        }
    }
    
    # Process Rights Management Services API permissions
    if ($RmsPermissions -and $RmsPermissions.Count -gt 0) {
        Write-Host "Processing Rights Management Services API permissions..." -ForegroundColor Cyan
        
        # Get Rights Management and MIP Sync service principals
        $rmsPrincipals = Get-RightsManagementServicePrincipals
        $rmsServicePrincipal = $rmsPrincipals.RmsServicePrincipal
        $mipServicePrincipal = $rmsPrincipals.MipServicePrincipal
        
        $rmsPermissionsAdded = $false
        
        if ($rmsServicePrincipal) {
            foreach ($permission in $RmsPermissions) {
                # Check if this is an MIP permission that should go to the MIP service principal
                if ($permission -eq "UnifiedPolicy.Tenant.Read" -and $mipServicePrincipal) {
                    $added = Add-AppRoleToRequiredAccess -ServicePrincipal $mipServicePrincipal -RoleName $permission -RequiredResourceAccess ([ref]$requiredResourceAccess)
                    $rmsPermissionsAdded = $added -or $rmsPermissionsAdded
                } else {
                    $added = Add-AppRoleToRequiredAccess -ServicePrincipal $rmsServicePrincipal -RoleName $permission -RequiredResourceAccess ([ref]$requiredResourceAccess)
                    $rmsPermissionsAdded = $added -or $rmsPermissionsAdded
                }
            }
        } else {
            Write-Warning "Rights Management service principal not found. Cannot add RMS permissions."
        }
        
        if ($rmsPermissionsAdded) {
            Write-Host "Added Rights Management permissions." -ForegroundColor Green
        } else {
            Write-Warning "Failed to add any Rights Management permissions."
        }
    }
    
    # Process Exchange Online API permissions
    if ($ExchangePermissions -and $ExchangePermissions.Count -gt 0) {
        Write-Host "Processing Exchange Online API permissions..." -ForegroundColor Cyan
        
        # Get Exchange Online service principal
        $exchangeSP = Get-MgServicePrincipal -Filter "appId eq '$($KnownAppIds.ExchangeOnline)'" -ErrorAction SilentlyContinue
        
        if (-not $exchangeSP) {
            # Try by name as fallback
            $possibleExchangeNames = @("Office 365 Exchange Online", "Exchange Online")
            foreach ($name in $possibleExchangeNames) {
                $exchangeSP = Get-ServicePrincipalByName -Name $name
                if ($exchangeSP) { break }
            }
        }
        
        $exchangePermissionsAdded = $false
        
        if ($exchangeSP) {
            foreach ($permission in $ExchangePermissions) {
                $added = Add-AppRoleToRequiredAccess -ServicePrincipal $exchangeSP -RoleName $permission -RequiredResourceAccess ([ref]$requiredResourceAccess)
                $exchangePermissionsAdded = $added -or $exchangePermissionsAdded
            }
            
            if ($exchangePermissionsAdded) {
                Write-Host "Added Exchange Online permissions." -ForegroundColor Green
            } else {
                Write-Warning "Failed to add any Exchange Online permissions."
            }
        } else {
            Write-Warning "Exchange Online service principal not found. Cannot add Exchange permissions."
        }
    }
    
    # Create the app registration with all specified permissions
    Write-Host "Creating app registration '$AppName'..." -ForegroundColor Cyan
    $appRegistration = New-MgApplication -DisplayName $AppName -RequiredResourceAccess $requiredResourceAccess
    
    # Create service principal for the app
    New-MgServicePrincipal -AppId $appRegistration.AppId | Out-Null
    
    Write-Host "App registration '$AppName' created successfully with ID: $($appRegistration.Id)" -ForegroundColor Green
    Write-Host "App ID (Client ID): $($appRegistration.AppId)" -ForegroundColor Green
    
    # Display applied permissions
    Write-Host "`nApplied API Permissions:" -ForegroundColor Cyan
    foreach ($resource in $requiredResourceAccess) {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$($resource.ResourceAppId)'"
        if ($sp) {
            Write-Host "Resource: $($sp.DisplayName)" -ForegroundColor Yellow
            foreach ($access in $resource.ResourceAccess) {
                if ($access.Type -eq "Role") {
                    $role = $sp.AppRoles | Where-Object { $_.Id -eq $access.Id }
                    if ($role) {
                        Write-Host " - $($role.Value)" -ForegroundColor Green
                    }
                }
            }
        }
    }
    
    Write-Host "`nIMPORTANT: An admin must explicitly grant consent for these permissions in the Azure Portal." -ForegroundColor Yellow
    
    # Return app registration object
    return $appRegistration
}
catch {
    Write-Error "An error occurred: $_"
}
finally {
    # Disconnect from Microsoft Graph
    Disconnect-MgGraph | Out-Null
    Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan
}