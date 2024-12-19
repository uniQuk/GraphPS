# Description: Create a report of all PIM Groups and their active and eligible members.
# Script 03:

# Script 01 - Graph-PIMGroupReport.ps1 - This is the simplest version I would use most of the time.
# Script 02 - Graph-PIMGroupReport-EC (Error Checking) - Is mostly the same as Script 01, but with some error handling.
# Script 03 - Graph-PIMGroupReport-runspace - Split into functions and uses runspace and parallel processing to speed up the script.

# Script to retrieve and display details of Privileged Access Groups in Azure AD Privileged Identity Management (PIM)
# Created by: uniQuk 2024

# Create a report of all PIM Groups and their active and eligible members.
# This is the same script as: PIM-Graph-PIMGroupReport.ps1 using functions and runspaces for parallel processing.


# The script uses runspaces to parallelize the retrieval of user details.
# The script uses the Stopwatch class to measure the execution time.
# The script uses the Get-MemberDetails function to retrieve user details in parallel.
# The script uses the Get-RoleNames function to retrieve role names from assignments.
# The script uses the Get-EligibleAssignments, Get-ActiveAssignments, Get-Groups, Get-EligibleMembers, Get-ActiveMembers functions to retrieve the data.
# The script uses the Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance, Get-MgBetaRoleManagementDirectoryRoleAssignmentScheduleInstance, Get-MgGroup, Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule, Get-MgGroupMember, Get-MgUser functions to retrieve the data.


param (
    [switch]$DebugMode,
    [int]$ParallelTasks = 20
)

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Get-EligibleAssignments {
    Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance -ExpandProperty "*" -All
}

function Get-ActiveAssignments {
    Get-MgBetaRoleManagementDirectoryRoleAssignmentScheduleInstance -ExpandProperty "*" -All
}

function Get-Groups {
    Get-MgGroup -All
}

function Get-EligibleMembers {
    param ([string]$GroupId)
    Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -Filter "groupId eq '$GroupId'"
}

function Get-ActiveMembers {
    param ([string]$GroupId)
    Get-MgGroupMember -GroupId $GroupId
}

function Get-MemberDetails {
    param (
        [array]$MemberIds,
        [int]$ParallelTasks
    )

    if (-not $MemberIds -or $MemberIds.Count -eq 0) {
        return @()
    }

    $memberDetails = @()

    # Prepare runspace pool
    $runspacePool = [RunspaceFactory]::CreateRunspacePool(1, $ParallelTasks)
    $runspacePool.Open()

    $scriptBlock = {
        param($userId)
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        # If debugging, uncomment next line:
        # Write-Host "Fetching user for $userId"
        Get-MgUser -UserId $userId -Property Id, DisplayName, UserPrincipalName, AccountEnabled
    }

    # Create a list of PowerShell jobs
    $jobs = New-Object System.Collections.Generic.List[System.Management.Automation.PowerShell]

    foreach ($memberId in $MemberIds) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $runspacePool
        $null = $ps.AddScript($scriptBlock).AddArgument($memberId)
        $jobs.Add($ps)
    }

    # Invoke all jobs
    foreach ($job in $jobs) {
        $asyncResult = $job.BeginInvoke()
        while (-not $asyncResult.IsCompleted) {
            Start-Sleep -Milliseconds 100
        }

        $result = $job.EndInvoke($asyncResult)
        $job.Dispose()

        if ($null -ne $result) {
            $memberDetails += $result
        }
    }

    $runspacePool.Close()
    $runspacePool.Dispose()

    return $memberDetails
}

function Get-RoleNames {
    param ([array]$Assignments)
    $Assignments | ForEach-Object { $_.RoleDefinition.DisplayName } | Sort-Object -Unique
}

$eligibleAssignments = Get-EligibleAssignments
$activeAssignments = Get-ActiveAssignments
$groups = Get-Groups

$results = @()

foreach ($group in $groups) {
    $eligibleGroupsRoles = $eligibleAssignments | Where-Object { $_.PrincipalId -eq $group.Id }
    $activeGroupsRoles = $activeAssignments | Where-Object { $_.PrincipalId -eq $group.Id }

    if (-not $eligibleGroupsRoles -and -not $activeGroupsRoles) {
        continue
    }

    $eligibleMembers = Get-EligibleMembers -GroupId $group.Id
    $activeMembers   = Get-ActiveMembers -GroupId $group.Id

    $eligibleMemberIds = $eligibleMembers | ForEach-Object { $_.PrincipalId } | Where-Object { $_ -ne $null }
    $activeMemberIds  = $activeMembers | ForEach-Object { $_.Id } | Where-Object { $_ -ne $null }

    # Debug if needed:
    # Write-Host "Eligible Member IDs for group $($group.DisplayName): $($eligibleMemberIds -join ', ')"
    # Write-Host "Active Member IDs for group $($group.DisplayName): $($activeMemberIds -join ', ')"

    $eligibleMemberDetails = Get-MemberDetails -MemberIds $eligibleMemberIds -ParallelTasks $ParallelTasks
    $activeMemberDetails   = Get-MemberDetails -MemberIds $activeMemberIds -ParallelTasks $ParallelTasks

    $eligibleMembersOutput = ($eligibleMemberDetails | ForEach-Object {
        if ($_.DisplayName -and $_.UserPrincipalName) {
            "$($_.DisplayName) ($($_.UserPrincipalName))"
        }
    } | Sort-Object -Unique) -join ", "

    $activeMembersOutput = ($activeMemberDetails | ForEach-Object {
        if ($_.DisplayName -and $_.UserPrincipalName) {
            "$($_.DisplayName) ($($_.UserPrincipalName))"
        }
    } | Sort-Object -Unique) -join ", "

    $groupInfo = [PSCustomObject][ordered]@{
        GroupName          = $group.DisplayName
        GroupId            = $group.Id
        eligibleAdminRoles = (Get-RoleNames -Assignments $eligibleGroupsRoles) -join ", "
        activeAdminRoles   = (Get-RoleNames -Assignments $activeGroupsRoles) -join ", "
        eligibleMembers    = $eligibleMembersOutput
        activeMembers      = $activeMembersOutput
    }

    $results += $groupInfo
}

$stopwatch.Stop()
Write-Host "Total execution time: $($stopwatch.Elapsed.TotalSeconds) seconds"

if ($DebugMode) {
    Write-Output $results
} else {
    $results | Out-ConsoleGridView -Title "Privileged Access Group Details"
}