# Description: This script retrieves and displays details of Privileged Access Groups in Azure AD Privileged Identity Management (PIM).
# Script 02:

# Script 01 - Graph-PIMGroupReport.ps1 - This is the simplest version I would use most of the time.
# Script 02 - Graph-PIMGroupReport-EC (Error Checking) - Is mostly the same as Script 01, but with some error handling.
# Script 03 - Graph-PIMGroupReport-runspace - Split into functions and uses runspace and parallel processing to speed up the script.

# Script to retrieve and display details of Privileged Access Groups in Azure AD Privileged Identity Management (PIM)
# Created by: uniQuk 2024

param (
    [switch]$DebugMode
)

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Retrieve all assignments and groups
$eligibleAssignments = Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance -ExpandProperty "*" -All
$activeAssignments = Get-MgBetaRoleManagementDirectoryRoleAssignmentScheduleInstance -ExpandProperty "*" -All
$groups = Get-MgGroup -All

$results = @()

foreach ($group in $groups) {
    # Filter assignments for current group
    $eligibleGroupsRoles = $eligibleAssignments | Where-Object { $_.PrincipalId -eq $group.id }
    $activeGroupsRoles = $activeAssignments | Where-Object { $_.PrincipalId -eq $group.id }
    
    if (-not $eligibleGroupsRoles -and -not $activeGroupsRoles) {
        continue
    }

    # Get members
    $eligibleMembers = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -Filter "groupId eq '$($group.id)'"
    $activeMembers = Get-MgGroupMember -GroupId $group.id

    # Initialize arrays for member details
    $eligibleMemberDetails = @()
    $activeMemberDetails = @()

    # Get eligible member details
    foreach ($member in $eligibleMembers) {
        try {
            $user = Get-MgUser -UserId $member.PrincipalId -Property Id, DisplayName, UserPrincipalName, AccountEnabled
            if ($user) {
                $eligibleMemberDetails += "$($user.DisplayName) ($($user.UserPrincipalName))"
            }
        } catch {
            Write-Warning "Could not get eligible member details for $($member.PrincipalId): $_"
        }
    }

    # Get active member details
    foreach ($member in $activeMembers) {
        try {
            $user = Get-MgUser -UserId $member.Id -Property Id, DisplayName, UserPrincipalName, AccountEnabled
            if ($user) {
                $activeMemberDetails += "$($user.DisplayName) ($($user.UserPrincipalName))"
            }
        } catch {
            Write-Warning "Could not get active member details for $($member.Id): $_"
        }
    }

    # Create group info object
    $groupInfo = [PSCustomObject][ordered]@{
        GroupName = $group.DisplayName
        GroupId = $group.Id
        eligibleAdminRoles = ($eligibleGroupsRoles | ForEach-Object { $_.RoleDefinition.DisplayName } | Sort-Object -Unique) -join ", "
        activeAdminRoles = ($activeGroupsRoles | ForEach-Object { $_.RoleDefinition.DisplayName } | Sort-Object -Unique) -join ", "
        eligibleMembers = ($eligibleMemberDetails | Sort-Object -Unique) -join ", "
        activeMembers = ($activeMemberDetails | Sort-Object -Unique) -join ", "
    }

    $results += $groupInfo

    # Debug output
    if ($DebugMode) {
        Write-Host "Processing group: $($group.DisplayName)"
        Write-Host "Eligible members found: $($eligibleMemberDetails.Count)"
        Write-Host "Active members found: $($activeMemberDetails.Count)"
    }
}

$stopwatch.Stop()
Write-Host "Total execution time: $($stopwatch.Elapsed.TotalSeconds) seconds"

if ($DebugMode) {
    Write-Output $results
} else {
    $results | Out-ConsoleGridView -Title "Privileged Access Group Details"
}