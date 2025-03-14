#-----------------------------------------------------------
# Ensure you're connected to Microsoft Graph with the required scopes.
# Author: Josh (https://github.com/uniQuk)
#-----------------------------------------------------------

<#
.SYNOPSIS
    Activates and manages Microsoft Entra Privileged Identity Management (PIM) roles and groups.

.DESCRIPTION
    This script provides an interactive interface to activate, deactivate, and extend PIM role 
    and group assignments. It supports both directory roles and privileged access groups.

.NOTES
    Required Permissions:
    - PrivilegedEligibilitySchedule.Read.AzureADGroup  : Required to view eligible privileged groups
    - PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup : Required to activate/deactivate group memberships
    - RoleEligibilitySchedule.Read.Directory  : Required to view eligible directory roles
    - RoleAssignmentSchedule.ReadWrite.Directory : Required to activate/deactivate directory roles
    
    To connect with these permissions, run:
    Connect-MgGraph -Scopes "PrivilegedEligibilitySchedule.Read.AzureADGroup","PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup","RoleEligibilitySchedule.Read.Directory","RoleAssignmentSchedule.ReadWrite.Directory"

.EXAMPLE
    # First connect to Microsoft Graph with required permissions
    Connect-MgGraph -Scopes "PrivilegedEligibilitySchedule.Read.AzureADGroup","PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup","RoleEligibilitySchedule.Read.Directory","RoleAssignmentSchedule.ReadWrite.Directory"
    
    # Run the script
    .\Graph-PIMActivator.ps1
#>

#-----------------------------------------------------------
# Check Connection to Microsoft Graph First
#-----------------------------------------------------------
function Test-GraphConnection {
    [CmdletBinding()]
    param(
        [switch]$ShowDetails
    )

    # This set matches our testing results - the minimum required permissions
    $requiredScopes = @(
        # For PIM Group operations
        "PrivilegedEligibilitySchedule.Read.AzureADGroup",
        "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
        
        # For PIM Role operations
        "RoleEligibilitySchedule.Read.Directory",
        "RoleAssignmentSchedule.ReadWrite.Directory"
    )
    
    # Check if connected to Microsoft Graph
    try {
        $context = Get-MgContext -ErrorAction Stop
        if (-not $context) {
            Write-Host "`n[ERROR] Not connected to Microsoft Graph. Please connect first with:" -ForegroundColor Red
            Write-Host "Connect-MgGraph -Scopes '$($requiredScopes -join "','")'" -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Host "`n[ERROR] Not connected to Microsoft Graph. Please connect first with:" -ForegroundColor Red
        Write-Host "Connect-MgGraph -Scopes '$($requiredScopes -join "','")'" -ForegroundColor Yellow
        return $false
    }

    # Get current scopes
    $currentScopes = $context.Scopes

    # Check for required permissions
    $missingScopes = @()
    foreach ($scope in $requiredScopes) {
        if ($currentScopes -notcontains $scope) {
            $missingScopes += $scope
        }
    }

    # Print connection information
    Write-Host "`n=== Microsoft Graph Connection ===" -ForegroundColor Cyan
    Write-Host "Connected as: $($context.Account)" -ForegroundColor White
    Write-Host "Tenant: $($context.TenantId)" -ForegroundColor White
    
    if ($ShowDetails) {
        Write-Host "Environment: $($context.Environment)" -ForegroundColor White
        Write-Host "App: $($context.AppName) ($($context.ClientId))" -ForegroundColor White
        Write-Host "Authentication: $($context.AuthType)" -ForegroundColor White
    }

    # Permission Analysis
    if ($missingScopes.Count -gt 0) {
        Write-Host "`n[WARNING] Missing required permissions: " -ForegroundColor Red
        $missingScopes | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
        
        # Check for alternative permissions that might work
        $alternatives = @(
            "Directory.AccessAsUser.All", 
            "RoleManagement.ReadWrite.Directory",
            "PrivilegedAccess.ReadWrite.AzureADGroup"
        )
        
        $hasAlternatives = $false
        foreach ($alt in $alternatives) {
            if ($currentScopes -contains $alt) {
                $hasAlternatives = $true
                break
            }
        }
        
        if ($hasAlternatives) {
            Write-Host "`nYou have some alternative permissions that might work." -ForegroundColor Yellow
            return $true # Continue with warning
        } else {
            Write-Host "`nPlease reconnect with all required permissions:" -ForegroundColor Yellow
            Write-Host "Disconnect-MgGraph" -ForegroundColor Yellow
            Write-Host "Connect-MgGraph -Scopes '$($requiredScopes -join "','")'" -ForegroundColor Yellow
            return $false
        }
    } else {
        Write-Host "`n✓ Connected with all required permissions" -ForegroundColor Green
    }
    
    return $true
}

# Check connection before proceeding - IMPORTANT - Add this BEFORE any API calls
if (-not (Test-GraphConnection)) {
    Write-Host "`nExiting script. Please connect with required permissions and try again." -ForegroundColor Red
    exit
}

#-----------------------------------------------------------
# Helper Functions
#-----------------------------------------------------------

# Get the display name for a group using its group ID.
function Get-GroupName {
    param ([string]$GroupId)
    try {
        (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId").displayName
    }
    catch {
        return $GroupId
    }
}

# Extract error details from Graph API response.
function Get-ErrorDetails {
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    $errorDetails = @{ Message = $ErrorRecord.Exception.Message; Details = "No additional details" }
    try {
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            $errorJson = $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($errorJson.error) {
                $errorDetails.Details = "Code: $($errorJson.error.code)`nMessage: $($errorJson.error.message)"
                if ($errorJson.error.details) {
                    $errorDetails.Details += "`nAdditional details:"
                    foreach ($detail in $errorJson.error.details) {
                        $errorDetails.Details += "`n- $($detail.target): $($detail.message)"
                    }
                }
            }
        }
    }
    catch { }
    return $errorDetails
}

# Check if an assignment is locked (activated less than 5 minutes ago).
function Test-AssignmentLock {
    param ($item)
    $baseTime = if ($item.PSObject.Properties['createdDateTime']) { 
                    [datetime]$item.createdDateTime 
                } else { 
                    [datetime]$item.startDateTime 
                }
    return ((Get-Date) -lt $baseTime.AddMinutes(5))
}

# Wait for deactivation to complete.
function Wait-ForDeactivation {
    param (
        [string]$Type,      # "Role" or "Group"
        [string]$Id,        # roleDefinitionId or groupId
        [int]$Timeout = 30,
        [int]$Interval = 5
    )
    $elapsed = 0
    while ($elapsed -lt $Timeout) {
        if ($Type -eq "Group") {
            $active = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances/filterByCurrentUser(on='principal')").value |
                      Where-Object { $_.groupId -eq $Id }
        }
        else {
            $active = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances/filterByCurrentUser(on='principal')").value |
                      Where-Object { $_.roleDefinitionId -eq $Id }
        }
        if (-not $active) { return $true }
        Write-Host "Waiting for deactivation to complete... ($elapsed seconds elapsed)" -ForegroundColor Yellow
        Start-Sleep -Seconds $Interval
        $elapsed += $Interval
    }
    return $false
}

# Validate payload with reprompt logic.
function Test-Payload {
    param (
        [hashtable]$Payload,
        [string]$Endpoint,
        [int]$AttemptsLimit = 3
    )
    $attempts = 0
    while ($attempts -lt $AttemptsLimit) {
        try {
            Write-Host "Validating request at $Endpoint..." -ForegroundColor Cyan
            $jsonPayload = $Payload | ConvertTo-Json -Depth 5
            Invoke-MgGraphRequest -Method POST -Uri $Endpoint -Body $jsonPayload -ContentType "application/json" | Out-Null
            Write-Host "Validation succeeded." -ForegroundColor Green
            return $Payload
        }
        catch {
            $attempts++
            $errorDetails = Get-ErrorDetails -ErrorRecord $_
            Write-Host "Validation failed: $($errorDetails.Message)" -ForegroundColor Red
            Write-Host $errorDetails.Details -ForegroundColor Red
            $errorMsg = $errorDetails.Message + " " + $errorDetails.Details
            if ($errorMsg -match "justification|Justification|reason") {
                $Payload.justification = Read-Host "Enter updated justification"
            }
            elseif ($errorMsg -match "ticket|Ticket|reference") {
                $Payload.ticketInfo = @{ "ticketNumber" = (Read-Host "Enter updated ticket info") }
            }
            else {
                Write-Host "Validation error encountered." -ForegroundColor Yellow
                $Payload.justification = Read-Host "Enter updated justification (if required)"
                $ticket = Read-Host "Enter ticket number (if required)"
                if ($ticket) { $Payload.ticketInfo = @{ "ticketNumber" = $ticket } }
            }
        }
    }
    throw "Too many validation attempts. Exiting."
}

# Process an assignment into a uniform object.
function ConvertTo-AssignmentObject {
    param (
        [object]$Assignment,
        [string]$Type,   # "Role" or "Group"
        [string]$State   # "Active" or "Eligible"
    )
    # For active assignments, skip if required properties are missing.
    if ($State -eq "Active") {
        if ($Type -eq "Role" -and (-not $Assignment.roleAssignmentScheduleId -or -not $Assignment.endDateTime)) { return $null }
        if ($Type -eq "Group" -and (-not $Assignment.assignmentScheduleId -or -not $Assignment.endDateTime)) { return $null }
    }
    $obj = [PSCustomObject]@{
        Type             = $Type
        State            = $State
        Name             = if ($Type -eq "Role") { $Assignment.roleDefinition.displayName } else { Get-GroupName $Assignment.groupId }
        RoleDefinitionId = if ($Type -eq "Role") { $Assignment.roleDefinitionId } else { $null }
        GroupId          = if ($Type -eq "Group") { $Assignment.groupId } else { $null }
        StartDateTime    = $Assignment.startDateTime
        EndDateTime      = $Assignment.endDateTime
        Raw              = $Assignment
        Locked           = $false
    }
    if ($State -eq "Active") { $obj.Locked = Test-AssignmentLock $Assignment }
    return $obj
}

#-----------------------------------------------------------
# Main Script
#-----------------------------------------------------------

# Query current user.
$currentUser = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/me"
$userId = $currentUser.id
Write-Host "Getting PIM roles and groups for user: $($currentUser.displayName) ($userId)" -ForegroundColor White
Write-Host ""

# Retrieve assignments.
$activeRoles    = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$userId'&`$expand=roleDefinition"
$eligibleRoles  = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$userId'&`$expand=roleDefinition"
$activeGroups   = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances/filterByCurrentUser(on='principal')"
$eligibleGroups = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules/filterByCurrentUser(on='principal')"

# Process assignments.
$processedActiveRoles    = @($activeRoles.value | ForEach-Object { ConvertTo-AssignmentObject -Assignment $_ -Type "Role" -State "Active" } | Where-Object { $_ })
$processedActiveGroups   = @($activeGroups.value | ForEach-Object { ConvertTo-AssignmentObject -Assignment $_ -Type "Group" -State "Active" } | Where-Object { $_ })
$processedEligibleRoles  = @($eligibleRoles.value | ForEach-Object { ConvertTo-AssignmentObject -Assignment $_ -Type "Role" -State "Eligible" } | Where-Object { $_ })
$processedEligibleGroups = @($eligibleGroups.value | ForEach-Object { ConvertTo-AssignmentObject -Assignment $_ -Type "Group" -State "Eligible" } | Where-Object { $_ })

# Filter out eligible assignments that already have an active counterpart.
$filteredEligibleRoles = @($processedEligibleRoles | Where-Object {
    $eligible = $_
    $activeMatch = @($processedActiveRoles | Where-Object { $_.RoleDefinitionId -eq $eligible.RoleDefinitionId })
    ($activeMatch.Count -eq 0)
})

$filteredEligibleGroups = @($processedEligibleGroups | Where-Object {
    $eligible = $_
    $activeMatch = @($processedActiveGroups | Where-Object { $_.GroupId -eq $eligible.GroupId })
    ($activeMatch.Count -eq 0)
})

# Combine assignments for display safely
$displayItems = @()
if ($processedActiveRoles.Count -gt 0) { $displayItems += $processedActiveRoles }
if ($processedActiveGroups.Count -gt 0) { $displayItems += $processedActiveGroups }
if ($filteredEligibleRoles.Count -gt 0) { $displayItems += $filteredEligibleRoles }
if ($filteredEligibleGroups.Count -gt 0) { $displayItems += $filteredEligibleGroups }

Write-Host "`n=== All PIM Roles and Groups ===" -ForegroundColor Cyan
Write-Host "Note: Recently activated roles require a 5-minute waiting period before they can be modified." -ForegroundColor Yellow

$headerFormat = "{0,-6} {1,-8} {2,-35} {3,-19} {4,-19} {5,-10} {6,-8}"
$header = $headerFormat -f "Type", "State", "Name", "Start Time", "End Time", "Status", "Action"
Write-Host $header -ForegroundColor Green
Write-Host ("-" * 110) -ForegroundColor Green

# Build menu items.
$menuItems = @()
$menuIndex = 1

foreach ($item in $displayItems) {
    $startStr = if ($item.StartDateTime) { ([datetime]$item.StartDateTime).ToString("yyyy-MM-dd HH:mm") } else { "N/A" }
    $endStr   = if ($item.EndDateTime)   { ([datetime]$item.EndDateTime).ToString("yyyy-MM-dd HH:mm") }   else { "Permanent" }
    $availability = if ($item.Locked) { "Locked" } else { "Available" }
    $ready = if ($item.Locked) {
        $baseTime = if ($item.Raw.PSObject.Properties['createdDateTime']) { [datetime]$item.Raw.createdDateTime } else { [datetime]$item.StartDateTime }
        $timeLeft = [math]::Ceiling(($baseTime.AddMinutes(5) - (Get-Date)).TotalMinutes)
        "Wait ${timeLeft}m"
    }
    else { "Ready" }
    Write-Host ($headerFormat -f $item.Type, $item.State, $item.Name.Substring(0, [Math]::Min(35, $item.Name.Length)), $startStr, $endStr, $availability, $ready)
    if (-not $item.Locked) {
        $item | Add-Member -NotePropertyName MenuIndex -NotePropertyValue $menuIndex -Force
        $menuItems += $item
        $menuIndex++
    }
}

Write-Host "`n=== PIM Activation/Modification Menu ===" -ForegroundColor Cyan
$menuItems | ForEach-Object { Write-Host "$($_.MenuIndex). [$($_.State) $($_.Type)] $($_.Name)" -ForegroundColor White }
Write-Host "0. Exit without modifying" -ForegroundColor Cyan

$selection = Read-Host "Select an assignment to modify (0-$($menuItems.Count))"
if ($selection -eq "0") { Write-Host "Exiting." -ForegroundColor Yellow; exit }
$selectedItem = $menuItems | Where-Object { $_.MenuIndex -eq [int]$selection }
if (-not $selectedItem) { Write-Host "Invalid selection." -ForegroundColor Yellow; exit }
if ($selectedItem.Locked) { Write-Host "Selected assignment is locked. Cannot modify." -ForegroundColor Red; exit }
Write-Host "You selected [$($selectedItem.State) $($selectedItem.Type)] '$($selectedItem.Name)'." -ForegroundColor White

#-----------------------------------------------------------
# Determine Action Based on Assignment State
#-----------------------------------------------------------
if ($selectedItem.State -eq "Eligible") {
    $action = "selfActivate"
    Write-Host "Action: Activate eligible assignment." -ForegroundColor Green
}
elseif ($selectedItem.State -eq "Active") {
    $choice = Read-Host "Assignment is active. Would you like to Extend (E) or Deactivate (D)? (E/D)"
    if ($choice -match "^[Ee]") {
         if (Test-AssignmentLock $selectedItem.Raw) { Write-Host "Cannot extend: Less than 5 minutes since activation." -ForegroundColor Red; exit }
         $action = "extend"
         Write-Host "Action: Extend active assignment." -ForegroundColor Green
    }
    elseif ($choice -match "^[Dd]") {
         if (Test-AssignmentLock $selectedItem.Raw) { Write-Host "Cannot deactivate: Less than 5 minutes since activation." -ForegroundColor Red; exit }
         $action = "selfDeactivate"
         Write-Host "Action: Deactivate active assignment." -ForegroundColor Green
    }
    else { Write-Host "Invalid choice. Exiting." -ForegroundColor Yellow; exit }
}
else { Write-Host "Unknown assignment state." -ForegroundColor Red; exit }

#-----------------------------------------------------------
# Prompt for Duration and Build ScheduleInfo (if needed)
#-----------------------------------------------------------
if ($action -in @("selfActivate", "extend")) {
    $defaultDuration = 8
    if ($selectedItem.EndDateTime -and $selectedItem.StartDateTime) {
         $defaultDuration = [math]::Round((([datetime]$selectedItem.EndDateTime - [datetime]$selectedItem.StartDateTime).TotalHours),2)
    }
    $durationInput = Read-Host "Enter duration in hours (default: $defaultDuration)"
    $duration = if ([string]::IsNullOrEmpty($durationInput)) { $defaultDuration } else { [double]$durationInput }
    if ($duration -eq [math]::Floor($duration)) { 
         $durationIso = "PT$($duration)H" 
    } else { 
         $minutes = [math]::Round($duration * 60)
         $durationIso = "PT$($minutes)M" 
    }
    $scheduleInfo = @{ 
        "startDateTime" = (Get-Date).ToUniversalTime().ToString("o")
        "expiration"    = @{ "type" = "afterDuration"; "duration" = $durationIso }
    }
} else {
    $scheduleInfo = @{ "startDateTime" = (Get-Date).ToUniversalTime().ToString("o") }
}

if ($action -eq "selfDeactivate") { 
    $justification = $null; $ticket = $null 
} else {
    $justification = Read-Host "Enter justification (if required)"
    $ticket = Read-Host "Enter ticket info (if required)"
}

#-----------------------------------------------------------
# Build Payload and Set Endpoint Based on Type
#-----------------------------------------------------------
if ($selectedItem.Type -eq "Role") {
    $payload = @{
         "action"           = $action
         "principalId"      = $userId
         "roleDefinitionId" = $selectedItem.RoleDefinitionId
         "directoryScopeId" = "/" 
    }
    if ($action -in @("selfActivate", "extend")) { $payload.scheduleInfo = $scheduleInfo }
    if ($justification) { $payload.justification = $justification }
    if ($ticket) { $payload.ticketInfo = @{ "ticketNumber" = $ticket } }
    $endpoint = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
}
elseif ($selectedItem.Type -eq "Group") {
    $payload = @{
         "action"      = $action
         "principalId" = $userId
         "accessId"    = "member"
         "groupId"     = $selectedItem.GroupId
    }
    if ($action -in @("selfActivate", "extend")) { $payload.scheduleInfo = $scheduleInfo }
    if ($justification) { $payload.justification = $justification }
    if ($ticket) { $payload.ticketInfo = @{ "ticketNumber" = $ticket } }
    $endpoint = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests"
}
else { Write-Host "Unknown assignment type." -ForegroundColor Red; exit }

#-----------------------------------------------------------
# For Extensions, perform deactivation then rebuild payload
#-----------------------------------------------------------
if ($action -eq "extend") {
    Write-Host "`nExtending assignment: Sending selfDeactivate request..." -ForegroundColor Cyan
    $deactPayload = $payload.Clone()
    $deactPayload.action = "selfDeactivate"
    $deactPayload.Remove("scheduleInfo") | Out-Null
    $deactPayload.isValidationOnly = $false
    try {
         $jsonDeact = $deactPayload | ConvertTo-Json -Depth 5
         Invoke-MgGraphRequest -Method POST -Uri $endpoint -Body $jsonDeact -ContentType "application/json" | Out-Null
         Write-Host "Deactivation succeeded." -ForegroundColor Green
    }
    catch {
         $errorDetails = Get-ErrorDetails -ErrorRecord $_
         Write-Host "Error during deactivation for extension:" -ForegroundColor Red
         Write-Host $errorDetails.Message -ForegroundColor Red
         Write-Host $errorDetails.Details -ForegroundColor Red
         exit
    }
    if (-not (Wait-ForDeactivation -Type $selectedItem.Type -Id ($selectedItem.Type -eq "Group" ? $selectedItem.GroupId : $selectedItem.RoleDefinitionId))) {
         Write-Host "Timed out waiting for deactivation. Exiting." -ForegroundColor Red
         exit
    }
    
    # Rebuild payload for selfActivate after extension.
    if ($selectedItem.Type -eq "Group") {
         $endpoint = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests"
         $payload = @{
              action      = "selfActivate"
              principalId = $userId
              accessId    = "member"
              groupId     = $selectedItem.GroupId
         }
    }
    else {
         $endpoint = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
         $payload = @{
              action           = "selfActivate"
              principalId      = $userId
              roleDefinitionId = $selectedItem.RoleDefinitionId
              directoryScopeId = "/"
         }
    }
    $payload.scheduleInfo = $scheduleInfo
    if ($justification) { $payload.justification = $justification }
    if ($ticket) { $payload.ticketInfo = @{ "ticketNumber" = $ticket } }
    
    Write-Host "`nExtension activation payload:" -ForegroundColor Cyan
    Write-Host ($payload | ConvertTo-Json -Depth 5) -ForegroundColor Cyan
}

#-----------------------------------------------------------
# Validate Payload with Reprompt Logic (for selfActivate and extend)
#-----------------------------------------------------------
if ($action -in @("selfActivate", "extend")) {
    $payload.isValidationOnly = $true
    $payload = Test-Payload -Payload $payload -Endpoint $endpoint
    $payload.isValidationOnly = $false
}

#-----------------------------------------------------------
# Execute API Request
#-----------------------------------------------------------
$jsonPayload = $payload | ConvertTo-Json -Depth 5
Write-Host "`nCalling API at $endpoint with action '$action'..." -ForegroundColor Cyan
try {
     $response = Invoke-MgGraphRequest -Method POST -Uri $endpoint -Body $jsonPayload -ContentType "application/json"
     Write-Host "`nResponse:" -ForegroundColor Green
     $response | Format-Table
}
catch {
     $errorDetails = Get-ErrorDetails -ErrorRecord $_
     Write-Host "`nError during request:" -ForegroundColor Red
     Write-Host $errorDetails.Message -ForegroundColor Red
     Write-Host $errorDetails.Details -ForegroundColor Red
     if ($action -eq "selfDeactivate") { exit }
}

if ($action -eq "selfDeactivate") {
     if (-not (Wait-ForDeactivation -Type $selectedItem.Type -Id ($selectedItem.Type -eq "Group" ? $selectedItem.GroupId : $selectedItem.RoleDefinitionId))) {
          Write-Host "Timed out waiting for deactivation." -ForegroundColor Red
     }
     else {
          Write-Host "Assignment deactivated." -ForegroundColor Green
     }
}