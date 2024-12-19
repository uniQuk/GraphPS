# Description: This script retrieves and displays details of Privileged Access Groups in Azure AD Privileged Identity Management (PIM).
# Script 01:

# Script 01 - Graph-PIMGroupReport.ps1 - This is the simplest version I would use most of the time.
# Script 02 - Graph-PIMGroupReport-EC (Error Checking) - Is mostly the same as Script 01, but with some error handling.
# Script 03 - Graph-PIMGroupReport-runspace - Split into functions and uses runspace and parallel processing to speed up the script.

# Script to retrieve and display details of Privileged Access Groups in Azure AD Privileged Identity Management (PIM)
# Created by: uniQuk 2024

# Retrieve all eligible and active role assignments
$eligibleAssignments = Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance -ExpandProperty "*" -All
$activeAssignments = Get-MgBetaRoleManagementDirectoryRoleAssignmentScheduleInstance -ExpandProperty "*" -All

# Retrieve all groups (can be scoped to only groups that can be assigned to a role)
# $groups = Get-MgGroup -Filter "isAssignableToRole eq true" -All
$groups = Get-MgGroup -All

# Initialize an array to store the results
$results = @()

# Iterate through each group
foreach ($group in $groups) {
    # Filter eligible and active role assignments for the current group
    $eligibleGroupsRoles = $eligibleAssignments | Where-Object {$_.PrincipalId -eq $group.id}
    $activeGroupsRoles = $activeAssignments | Where-Object {$_.PrincipalId -eq $group.id}
    
    # Skip groups without any PIM assignments
    if (-not $eligibleGroupsRoles -and -not $activeGroupsRoles) {
        continue
    }

    # Retrieve eligible and active members for the current group
    $eligibleMembers = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -Filter "groupId eq '$($group.id)'"
    $activeMembers = Get-MgGroupMember -GroupId $group.id

    # Initialize arrays to store member details
    $eligibleMemberDetails = @()
    $activeMemberDetails = @()

    # Process eligible members and retrieve their details
    foreach ($member in $eligibleMembers) {
        $user = Get-MgUser -UserId $member.PrincipalId -Property Id, DisplayName, UserPrincipalName, AccountEnabled
        $eligibleMemberDetails += "$($user.DisplayName) ($($user.UserPrincipalName))"
    }

    # Process active members and retrieve their details
    foreach ($member in $activeMembers) {
        $user = Get-MgUser -UserId $member.Id -Property Id, DisplayName, UserPrincipalName, AccountEnabled
        $activeMemberDetails += "$($user.DisplayName) ($($user.UserPrincipalName))"
    }

    # Retrieve role names for eligible and active roles
    $eligibleRoleNames = $eligibleGroupsRoles | ForEach-Object { $_.RoleDefinition.DisplayName }
    $activeRoleNames = $activeGroupsRoles | ForEach-Object { $_.RoleDefinition.DisplayName }

    # Create a custom object to store group information
    $groupInfo = [PSCustomObject][ordered]@{
        GroupName = $group.DisplayName
        GroupId = $group.Id
        eligibileAdminRoles = ($eligibleRoleNames | Sort-Object -Unique) -join ", "
        activeAdminRoles = ($activeRoleNames | Sort-Object -Unique) -join ", "
        eligibleMembers = ($eligibleMemberDetails | Sort-Object -Unique) -join ", "
        activeMembers = ($activeMemberDetails | Sort-Object -Unique) -join ", "
    }
    # Add the group information to the results array
    $results += $groupInfo
}

# Display the results in a grid view
$results | Out-ConsoleGridView -Title "Privileged Access Group Details"
# $results