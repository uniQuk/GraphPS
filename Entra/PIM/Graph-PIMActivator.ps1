#-----------------------------------------------------------
# Ensure you’re connected to Microsoft Graph with the required scopes.
# Author: Josh (https://github.com/uniQuk)
#-----------------------------------------------------------

# Get the current user via /me
$currentUser = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/me"
$userId = $currentUser.id
Write-Host "Getting PIM roles and groups for user: $($currentUser.displayName) ($userId)" -ForegroundColor Cyan

#-----------------------------------------------------------
# Retrieve Active and Eligible Assignments
#-----------------------------------------------------------
# --- PIM Roles (Beta)
$activeRolesUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$userId'&`$expand=roleDefinition"
$activeRolesResponse = Invoke-MgGraphRequest -Method GET -Uri $activeRolesUri
$allActiveRoles = $activeRolesResponse.value
# Filter out permanent roles (assume PIM-managed roles have both startDateTime and endDateTime)
$activeRoles = $allActiveRoles | Where-Object { $_.startDateTime -and $_.endDateTime }

$eligibleRolesUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$userId'&`$expand=roleDefinition"
$eligibleRolesResponse = Invoke-MgGraphRequest -Method GET -Uri $eligibleRolesUri
$eligibleRoles = $eligibleRolesResponse.value

# --- PIM Groups (v1.0)
$activeGroupsUri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=principalId eq '$userId'&`$expand=group"
$activeGroupsResponse = Invoke-MgGraphRequest -Method GET -Uri $activeGroupsUri
$allActiveGroups = $activeGroupsResponse.value
# Filter out non-PIM (permanent) groups by ensuring they have both start and end times.
$activeGroups = $allActiveGroups | Where-Object { $_.startDateTime -and $_.endDateTime }

$eligibleGroupsUri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests?`$filter=principalId eq '$userId'&`$expand=group"
$eligibleGroupsResponse = Invoke-MgGraphRequest -Method GET -Uri $eligibleGroupsUri
$eligibleGroups = $eligibleGroupsResponse.value

#-----------------------------------------------------------
# Display Active Assignments
#-----------------------------------------------------------
Write-Host "`nFetching active PIM role assignments..."
Write-Host "Found $($activeRoles.Count) active PIM role assignment(s)"
if ($activeRoles.Count -gt 0) {
    $activeRoles | ForEach-Object {
        [PSCustomObject]@{
            RoleName      = $_.roleDefinition.displayName
            StartDateTime = $_.startDateTime
            EndDateTime   = $_.endDateTime
            Status        = $_.status
        }
    } | Format-Table -AutoSize
} else {
    Write-Host "  (None)"
}

Write-Host "`nFetching active PIM group memberships..."
Write-Host "Found $($activeGroups.Count) active PIM group membership(s)"
if ($activeGroups.Count -gt 0) {
    $activeGroups | ForEach-Object {
        [PSCustomObject]@{
            GroupName     = $_.group.displayName
            StartDateTime = $_.startDateTime
            EndDateTime   = $_.endDateTime
            Status        = $_.status
        }
    } | Format-Table -AutoSize
} else {
    Write-Host "  (None)"
}

#-----------------------------------------------------------
# Display Eligible Assignments
#-----------------------------------------------------------
Write-Host "`nFetching eligible PIM role assignments..."
Write-Host "Found $($eligibleRoles.Count) eligible PIM role assignment(s)"
if ($eligibleRoles.Count -gt 0) {
    $eligibleRoles | ForEach-Object {
        [PSCustomObject]@{
            RoleName        = $_.roleDefinition.displayName
            AssignmentState = $_.assignmentState
            StartDateTime   = $_.startDateTime
            EndDateTime     = $_.endDateTime
        }
    } | Format-Table -AutoSize
} else {
    Write-Host "  (None)"
}

Write-Host "`nFetching eligible PIM group memberships..."
Write-Host "Found $($eligibleGroups.Count) eligible PIM group membership(s)"
if ($eligibleGroups.Count -gt 0) {
    $eligibleGroups | ForEach-Object {
        [PSCustomObject]@{
            GroupName       = $_.group.displayName
            AssignmentState = $_.assignmentState
            StartDateTime   = $_.startDateTime
            EndDateTime     = $_.endDateTime
        }
    } | Format-Table -AutoSize
} else {
    Write-Host "  (None)"
}

#-----------------------------------------------------------
# Build the Activation Menu (combine eligible and active assignments)
#-----------------------------------------------------------
$menuItems = @()

# For roles: add eligible role assignments (and mark as Active if a matching PIM-managed assignment exists)
foreach ($role in $eligibleRoles) {
    $isActive = ($activeRoles | Where-Object { $_.roleDefinition.id -eq $role.roleDefinition.id }) -ne $null
    $menuItems += [PSCustomObject]@{
        Type             = "Role"
        Name             = $role.roleDefinition.displayName
        EligibleId       = $role.id
        RoleDefinitionId = $role.roleDefinition.id
        Category         = if ($isActive) { "Active" } else { "Eligible" }
    }
}

# For groups: add eligible group assignments…
foreach ($grp in $eligibleGroups) {
    $isActive = ($activeGroups | Where-Object { $_.group.id -eq $grp.group.id }) -ne $null
    $menuItems += [PSCustomObject]@{
        Type      = "Group"
        Name      = $grp.group.displayName
        EligibleId = $grp.id   # eligibility object ID (if any)
        GroupId    = $grp.group.id
        Category  = if ($isActive) { "Active" } else { "Eligible" }
    }
}
# ...and add any active groups (PIM-managed) that didn’t appear in the eligible list.
$eligibleGroupIds = $eligibleGroups | ForEach-Object { $_.group.id }
$activeGroupsExtra = $activeGroups | Where-Object { $eligibleGroupIds -notcontains $_.group.id }
foreach ($grp in $activeGroupsExtra) {
    $menuItems += [PSCustomObject]@{
        Type      = "Group"
        Name      = $grp.group.displayName
        EligibleId = $null   # no corresponding eligibility object
        GroupId    = $grp.group.id
        Category  = "Active"
    }
}

#-----------------------------------------------------------
# Display the Menu
#-----------------------------------------------------------
Write-Host "`n=== PIM Activation Menu ==="
for ($i = 0; $i -lt $menuItems.Count; $i++) {
    $item = $menuItems[$i]
    Write-Host "$($i+1). [$($item.Type)] $($item.Name)"
}
Write-Host "0. Exit without activating"

#-----------------------------------------------------------
# Process User Selection
#-----------------------------------------------------------
$selection = Read-Host "`nSelect an item to activate (0-$($menuItems.Count))"
if ($selection -eq "0") {
    Write-Host "Exiting without changes."
    exit
}

[int]$index = $selection - 1
if ($index -lt 0 -or $index -ge $menuItems.Count) {
    Write-Host "Invalid selection. Exiting..."
    exit
}

$selectedItem = $menuItems[$index]

#-----------------------------------------------------------
# Process the Selected Item
#-----------------------------------------------------------
if ($selectedItem.Category -eq "Active") {
    Write-Host "The selected [$($selectedItem.Type)] '$($selectedItem.Name)' is already active."
    Write-Host "Choose an option:"
    Write-Host "1. Deactivate"
    Write-Host "2. Extend"
    $action = Read-Host "Select an option (1 or 2)"
    if ($action -eq "1") {
        Write-Host "Deactivating the active assignment..."
        if ($selectedItem.Type -eq "Role") {
            # For roles, use the cancel endpoint on the active assignment instance.
            $activeRole = $activeRoles | Where-Object { $_.roleDefinition.id -eq $selectedItem.RoleDefinitionId } | Select-Object -First 1
            if ($activeRole) {
                $cancelUri = "https://graph.microsoft.com/beta/roleManagement/directory/assignmentScheduleInstances/$($activeRole.id)/cancel"
                Invoke-MgGraphRequest -Method POST -Uri $cancelUri -Body (@{ justification = "Deactivation via script" } | ConvertTo-Json)
                Write-Host "Deactivation request submitted."
            } else {
                Write-Host "Active role assignment not found."
            }
        }
        elseif ($selectedItem.Type -eq "Group") {
            # For groups, deactivation is done via a selfDeactivate action POSTed to assignmentScheduleRequests.
            $deactivationBody = @{
                "@odata.type" = "#microsoft.graph.privilegedAccessGroupAssignmentScheduleRequest"
                action        = "selfDeactivate"
                groupId       = $selectedItem.GroupId
                principalId   = $userId
                accessId      = "member"  # Adjust if necessary
                justification = "Deactivation via script"
            }
            $deactivationUri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests"
            Invoke-MgGraphRequest -Method POST -Uri $deactivationUri -Body ($deactivationBody | ConvertTo-Json -Depth 10)
            Write-Host "Deactivation request submitted."
        }
    }
    elseif ($action -eq "2") {
        Write-Host "Extending the active assignment..."
        $duration = Read-Host "Enter extension duration in hours (default: 8)"
        if ([string]::IsNullOrWhiteSpace($duration)) { $duration = "8" }
        if ($selectedItem.Type -eq "Role") {
            $activeRole = $activeRoles | Where-Object { $_.roleDefinition.id -eq $selectedItem.RoleDefinitionId } | Select-Object -First 1
            if ($activeRole) {
                $extendUri = "https://graph.microsoft.com/beta/roleManagement/directory/assignmentScheduleInstances/$($activeRole.id)/extend"
                $extendBody = @{
                    "@odata.type" = "#microsoft.graph.privilegedRoleAssignmentScheduleRequest"
                    action        = "adminExtend"
                    justification = "Extension via script"
                    scheduleInfo  = @{ expiration = @{ duration = "PT$($duration)H" } }
                }
                Invoke-MgGraphRequest -Method POST -Uri $extendUri -Body ($extendBody | ConvertTo-Json -Depth 10)
                Write-Host "Extension request submitted."
            } else {
                Write-Host "Active role assignment not found."
            }
        }
        elseif ($selectedItem.Type -eq "Group") {
            $activeGroup = $activeGroups | Where-Object { $_.group.id -eq $selectedItem.GroupId } | Select-Object -First 1
            if ($activeGroup) {
                # For groups, extension is done by submitting an extension request.
                $extendBody = @{
                    "@odata.type"    = "#microsoft.graph.privilegedAccessGroupAssignmentScheduleRequest"
                    action           = "adminExtend"
                    justification    = "Extension via script"
                    scheduleInfo     = @{ expiration = @{ duration = "PT$($duration)H" } }
                    targetScheduleId = $activeGroup.id  # Use the active assignment's ID as the target
                    groupId          = $selectedItem.GroupId
                    principalId      = $userId
                    accessId         = "member"  # Adjust if necessary
                }
                $extendUri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests"
                Invoke-MgGraphRequest -Method POST -Uri $extendUri -Body ($extendBody | ConvertTo-Json -Depth 10)
                Write-Host "Extension request submitted."
            } else {
                Write-Host "Active group assignment not found."
            }
        }
    }
    else {
        Write-Host "Invalid option. Exiting..."
        exit
    }
}
else {
    # Eligible but not active – prompt for activation details.
    Write-Host "You selected an eligible [$($selectedItem.Type)] '$($selectedItem.Name)' for activation."
    $duration = Read-Host "Enter activation duration in hours (default: 8)"
    if ([string]::IsNullOrWhiteSpace($duration)) { $duration = "8" }
    $justification = Read-Host "Enter justification for activation"
    if ($selectedItem.Type -eq "Role") {
        $activationBody = @{
            "@odata.type"      = "#microsoft.graph.privilegedRoleAssignmentScheduleRequest"
            action             = "selfActivate"
            roleDefinitionId   = $selectedItem.RoleDefinitionId
            principalId        = $userId
            justification      = $justification
            scheduleInfo       = @{ expiration = @{ duration = "PT$($duration)H" } }
        }
        $activationUri = "https://graph.microsoft.com/beta/roleManagement/directory/assignmentScheduleRequests"
        Write-Host "Activating role..."
        Invoke-MgGraphRequest -Method POST -Uri $activationUri -Body ($activationBody | ConvertTo-Json -Depth 10)
        Write-Host "Activation request submitted."
    }
    elseif ($selectedItem.Type -eq "Group") {
        $activationBody = @{
            "@odata.type" = "#microsoft.graph.privilegedAccessGroupAssignmentScheduleRequest"
            action        = "selfActivate"
            groupId       = $selectedItem.GroupId
            principalId   = $userId
            accessId      = "member"  # Adjust if needed
            justification = $justification
            scheduleInfo  = @{ expiration = @{ duration = "PT$($duration)H" } }
        }
        $activationUri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests"
        Write-Host "Activating group..."
        Invoke-MgGraphRequest -Method POST -Uri $activationUri -Body ($activationBody | ConvertTo-Json -Depth 10)
        Write-Host "Activation request submitted."
    }
}