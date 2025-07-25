<#
.SYNOPSIS
    Comprehensive PIM and Privileged Access Reporting Script

.DESCRIPTION
    This script generates detailed reports of users with privileged access in Microsoft Entra ID.
    It covers all types of privileged assignments including direct roles, PIM roles, PIM groups,
    and group-based role assignments to provide a complete view of the privileged access landscape.
    
    The script generates two separate reports:
    1. User Assignments: Individual user role assignments (excluding groups/service principals from direct view)
    2. Group Report: Group-based access showing group name, assigned roles, and member counts (direct, PIM eligible, PIM active)

.NOTES
    Version:        2.0
    Author:         Josh (https://github.com/uniQuk)
    Creation Date:  July 25, 2025
    
    Required Permissions:
    - Directory.Read.All                                    : Read users, groups, and direct role assignments
    - RoleEligibilitySchedule.Read.Directory               : Read PIM eligible roles
    - RoleAssignmentSchedule.Read.Directory                : Read PIM active roles  
    - PrivilegedEligibilitySchedule.Read.AzureADGroup      : Read PIM eligible groups (tenant-wide access may require additional permissions)
    - PrivilegedAssignmentSchedule.Read.AzureADGroup       : Read PIM active groups (tenant-wide access may require additional permissions)
    
    Note: PIM Groups endpoints may require elevated permissions for tenant-wide reporting vs per-user access.
    If PIM Groups data is not collected, verify licensing (Microsoft Entra ID P2) and permissions.

.PARAMETER ExportPath
    Optional base path for CSV export. If specified, will create two files with suffixes:
    - _UserAssignments.csv: Individual user role assignments
    - _GroupReport.csv: Group-based access report
    If not specified, files will be created with timestamp in current directory.

.EXAMPLE
    # Connect with required permissions
    Connect-MgGraph -Scopes "Directory.Read.All","RoleEligibilitySchedule.Read.Directory","RoleAssignmentSchedule.Read.Directory","PrivilegedEligibilitySchedule.Read.AzureADGroup","PrivilegedAssignmentSchedule.Read.AzureADGroup"
    
    # Run the report (creates timestamped files)
    .\PIM-Reporting.ps1

.EXAMPLE
    # Run with custom export path
    .\PIM-Reporting.ps1 -ExportPath "C:\Reports\PIM_Report"
    # Creates: PIM_Report_UserAssignments.csv and PIM_Report_GroupReport.csv
#>

param(
    [string]$ExportPath
)

#-----------------------------------------------------------
# Global Variables and Caches
#-----------------------------------------------------------
$Global:UserCache = @{}
$Global:GroupCache = @{}
$Global:AllAssignments = @()
$Global:GroupReport = @()
$Global:Stats = @{
    DirectRoles = 0
    PIMEligibleRoles = 0
    PIMActiveRoles = 0
    PIMEligibleGroups = 0
    PIMActiveGroups = 0
    GroupBasedRoles = 0
    TotalUsers = 0
    TotalRoles = 0
}

#-----------------------------------------------------------
# Connection and Permission Check
#-----------------------------------------------------------
function Test-GraphConnection {
    [CmdletBinding()]
    param()

    $requiredScopes = @(
        "Directory.Read.All",
        "RoleEligibilitySchedule.Read.Directory",
        "RoleAssignmentSchedule.Read.Directory", 
        "PrivilegedEligibilitySchedule.Read.AzureADGroup",
        "PrivilegedAssignmentSchedule.Read.AzureADGroup"
    )
    
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

    $currentScopes = $context.Scopes
    $missingScopes = @()
    foreach ($scope in $requiredScopes) {
        if ($currentScopes -notcontains $scope) {
            $missingScopes += $scope
        }
    }

    Write-Host "`n=== Microsoft Graph Connection ===" -ForegroundColor Cyan
    Write-Host "Connected as: $($context.Account)" -ForegroundColor White
    Write-Host "Tenant: $($context.TenantId)" -ForegroundColor White

    if ($missingScopes.Count -gt 0) {
        Write-Host "`n[WARNING] Missing recommended permissions:" -ForegroundColor Yellow
        $missingScopes | ForEach-Object { Write-Host "- $_" -ForegroundColor Yellow }
        Write-Host "`nSome features may not work. Continue anyway? (Y/N)" -ForegroundColor Yellow
        $continue = Read-Host
        if ($continue -notmatch '^[Yy]') {
            return $false
        }
    } else {
        Write-Host "`n✓ Connected with all required permissions" -ForegroundColor Green
    }
    
    return $true
}

#-----------------------------------------------------------
# Helper Functions
#-----------------------------------------------------------
function Get-UserDisplayName {
    [CmdletBinding()]
    param(
        [string]$UserId
    )
    
    if ($Global:UserCache.ContainsKey($UserId)) {
        return $Global:UserCache[$UserId]
    }
    
    try {
        # First try as user
        $user = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$UserId" -ErrorAction Stop
        $displayName = "$($user.displayName) ($($user.userPrincipalName))"
        $Global:UserCache[$UserId] = $displayName
        return $displayName
    }
    catch {
        try {
            # If user lookup fails, try as directory object (could be group, service principal, etc.)
            $object = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$UserId" -ErrorAction Stop
            if ($object.'@odata.type' -eq '#microsoft.graph.group') {
                $displayName = "Group: $($object.displayName)"
            }
            elseif ($object.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
                $displayName = "ServicePrincipal: $($object.displayName)"
            }
            else {
                $displayName = "$($object.'@odata.type'): $($object.displayName)"
            }
            $Global:UserCache[$UserId] = $displayName
            return $displayName
        }
        catch {
            $Global:UserCache[$UserId] = "Unknown Object ($UserId)"
            return "Unknown Object ($UserId)"
        }
    }
}

function Get-GroupDisplayName {
    [CmdletBinding()]
    param(
        [string]$GroupId
    )
    
    if ($Global:GroupCache.ContainsKey($GroupId)) {
        return $Global:GroupCache[$GroupId]
    }
    
    try {
        $group = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId" -ErrorAction Stop
        $displayName = $group.displayName
        $Global:GroupCache[$GroupId] = $displayName
        return $displayName
    }
    catch {
        $Global:GroupCache[$GroupId] = "Unknown Group ($GroupId)"
        return "Unknown Group ($GroupId)"
    }
}

function Format-DateTime {
    [CmdletBinding()]
    param(
        [string]$DateTimeString
    )
    
    if ([string]::IsNullOrEmpty($DateTimeString)) {
        return "Permanent"
    }
    
    try {
        return ([datetime]$DateTimeString).ToString("yyyy-MM-dd HH:mm")
    }
    catch {
        return $DateTimeString
    }
}

function Write-Progress-Update {
    [CmdletBinding()]
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete = -1
    )
    
    if ($PercentComplete -ge 0) {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    } else {
        Write-Host "$Activity - $Status" -ForegroundColor Cyan
    }
}

#-----------------------------------------------------------
# Data Collection Functions
#-----------------------------------------------------------
function Get-DirectRoleAssignments {
    [CmdletBinding()]
    param()
    
    Write-Progress-Update -Activity "Collecting Data" -Status "Direct/Permanent Role Assignments"
    
    try {
        $assignments = @()
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$expand=roleDefinition"
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            foreach ($assignment in $response.value) {
                # Check if this is a user assignment (not group or service principal)
                $isUser = $true
                try {
                    $object = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$($assignment.principalId)" -ErrorAction Stop
                    if ($object.'@odata.type' -ne '#microsoft.graph.user') {
                        $isUser = $false
                    }
                }
                catch {
                    $isUser = $false
                }
                
                if ($isUser) {
                    $userDisplayName = Get-UserDisplayName -UserId $assignment.principalId
                    $assignments += [PSCustomObject]@{
                        AssignmentType = "Direct/Permanent"
                        UserDisplayName = $userDisplayName
                        UserId = $assignment.principalId
                        RoleName = $assignment.roleDefinition.displayName
                        RoleId = $assignment.roleDefinitionId
                        GroupName = ""
                        GroupId = ""
                        StartDateTime = ""
                        EndDateTime = ""
                        Source = "Direct Assignment"
                    }
                }
            }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        $Global:Stats.DirectRoles = $assignments.Count
        Write-Host "✓ Found $($assignments.Count) direct role assignments (users only)" -ForegroundColor Green
        return $assignments
    }
    catch {
        Write-Host "✗ Error collecting direct role assignments: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-PIMEligibleRoles {
    [CmdletBinding()]
    param()
    
    Write-Progress-Update -Activity "Collecting Data" -Status "PIM Eligible Role Assignments"
    
    try {
        $assignments = @()
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=roleDefinition"
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            foreach ($assignment in $response.value) {
                # Check if this is a user assignment (not group or service principal)
                $isUser = $true
                try {
                    $object = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$($assignment.principalId)" -ErrorAction Stop
                    if ($object.'@odata.type' -ne '#microsoft.graph.user') {
                        $isUser = $false
                    }
                }
                catch {
                    $isUser = $false
                }
                
                if ($isUser) {
                    $userDisplayName = Get-UserDisplayName -UserId $assignment.principalId
                    $assignments += [PSCustomObject]@{
                        AssignmentType = "PIM Eligible"
                        UserDisplayName = $userDisplayName
                        UserId = $assignment.principalId
                        RoleName = $assignment.roleDefinition.displayName
                        RoleId = $assignment.roleDefinitionId
                        GroupName = ""
                        GroupId = ""
                        StartDateTime = Format-DateTime $assignment.startDateTime
                        EndDateTime = Format-DateTime $assignment.endDateTime
                        Source = "PIM Eligible"
                    }
                }
            }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        $Global:Stats.PIMEligibleRoles = $assignments.Count
        Write-Host "✓ Found $($assignments.Count) PIM eligible role assignments (users only)" -ForegroundColor Green
        return $assignments
    }
    catch {
        Write-Host "✗ Error collecting PIM eligible roles: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-PIMActiveRoles {
    [CmdletBinding()]
    param()
    
    Write-Progress-Update -Activity "Collecting Data" -Status "PIM Active Role Assignments"
    
    try {
        $assignments = @()
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$expand=roleDefinition"
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            foreach ($assignment in $response.value) {
                # Check if this is a user assignment (not group or service principal)
                $isUser = $true
                try {
                    $object = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$($assignment.principalId)" -ErrorAction Stop
                    if ($object.'@odata.type' -ne '#microsoft.graph.user') {
                        $isUser = $false
                    }
                }
                catch {
                    $isUser = $false
                }
                
                if ($isUser) {
                    $userDisplayName = Get-UserDisplayName -UserId $assignment.principalId
                    $assignments += [PSCustomObject]@{
                        AssignmentType = "PIM Active"
                        UserDisplayName = $userDisplayName
                        UserId = $assignment.principalId
                        RoleName = $assignment.roleDefinition.displayName
                        RoleId = $assignment.roleDefinitionId
                        GroupName = ""
                        GroupId = ""
                        StartDateTime = Format-DateTime $assignment.startDateTime
                        EndDateTime = Format-DateTime $assignment.endDateTime
                        Source = "PIM Active"
                    }
                }
            }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        $Global:Stats.PIMActiveRoles = $assignments.Count
        Write-Host "✓ Found $($assignments.Count) PIM active role assignments (users only)" -ForegroundColor Green
        return $assignments
    }
    catch {
        Write-Host "✗ Error collecting PIM active roles: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-PIMEligibleGroups {
    [CmdletBinding()]
    param()
    
    Write-Progress-Update -Activity "Collecting Data" -Status "PIM Eligible Group Assignments"
    
    try {
        $assignments = @()
        
        # PIM Groups API requires per-group queries for tenant-wide reporting
        Write-Host "  Querying PIM eligible assignments via role-assignable groups..." -ForegroundColor Gray
        
        # Get all role-assignable groups (these are the only groups that can have PIM enabled)
        $roleAssignableGroups = @()
        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=isAssignableToRole eq true&`$select=id,displayName"
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            $roleAssignableGroups += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        # For each role-assignable group, get PIM eligibility data
        foreach ($group in $roleAssignableGroups) {
            try {
                # Get eligibility schedules for this specific group
                $groupEligibilityUri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($group.id)'"
                $groupResponse = Invoke-MgGraphRequest -Method GET -Uri $groupEligibilityUri
                
                foreach ($assignment in $groupResponse.value) {
                    $userDisplayName = Get-UserDisplayName -UserId $assignment.principalId
                    $assignments += [PSCustomObject]@{
                        AssignmentType = "PIM Group Eligible"
                        UserDisplayName = $userDisplayName
                        UserId = $assignment.principalId
                        RoleName = "Privileged Access Group Member"
                        RoleId = ""
                        GroupName = $group.displayName
                        GroupId = $group.id
                        StartDateTime = Format-DateTime $assignment.startDateTime
                        EndDateTime = Format-DateTime $assignment.endDateTime
                        Source = "PIM Group Eligible"
                    }
                }
            }
            catch {
                # This group may not have PIM enabled, continue to next
                continue
            }
        }
        
        $Global:Stats.PIMEligibleGroups = $assignments.Count
        Write-Host "✓ Found $($assignments.Count) PIM eligible group assignments" -ForegroundColor Green
        return $assignments
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Host "✗ Error collecting PIM eligible groups: $errorMessage" -ForegroundColor Red
        $Global:Stats.PIMEligibleGroups = 0
        return @()
    }
}

function Get-PIMActiveGroups {
    [CmdletBinding()]
    param()
    
    Write-Progress-Update -Activity "Collecting Data" -Status "PIM Active Group Assignments"
    
    try {
        $assignments = @()
        
        # PIM Groups API requires per-group queries for tenant-wide reporting
        Write-Host "  Querying PIM active assignments via role-assignable groups..." -ForegroundColor Gray
        
        # Get all role-assignable groups (these are the only groups that can have PIM enabled)
        $roleAssignableGroups = @()
        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=isAssignableToRole eq true&`$select=id,displayName"
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            $roleAssignableGroups += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        # For each role-assignable group, get PIM active assignment data
        foreach ($group in $roleAssignableGroups) {
            try {
                # Get assignment schedule instances for this specific group
                $groupActiveUri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$($group.id)'"
                $groupResponse = Invoke-MgGraphRequest -Method GET -Uri $groupActiveUri
                
                foreach ($assignment in $groupResponse.value) {
                    $userDisplayName = Get-UserDisplayName -UserId $assignment.principalId
                    $assignments += [PSCustomObject]@{
                        AssignmentType = "PIM Group Active"
                        UserDisplayName = $userDisplayName
                        UserId = $assignment.principalId
                        RoleName = "Privileged Access Group Member"
                        RoleId = ""
                        GroupName = $group.displayName
                        GroupId = $group.id
                        StartDateTime = Format-DateTime $assignment.startDateTime
                        EndDateTime = Format-DateTime $assignment.endDateTime
                        Source = "PIM Group Active"
                    }
                }
            }
            catch {
                # This group may not have PIM enabled, continue to next
                continue
            }
        }
        
        $Global:Stats.PIMActiveGroups = $assignments.Count
        Write-Host "✓ Found $($assignments.Count) PIM active group assignments" -ForegroundColor Green
        return $assignments
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Host "✗ Error collecting PIM active groups: $errorMessage" -ForegroundColor Red
        $Global:Stats.PIMActiveGroups = 0
        return @()
    }
}

function Get-GroupBasedRoleAssignments {
    [CmdletBinding()]
    param()
    
    Write-Progress-Update -Activity "Collecting Data" -Status "Group-Based Role Assignments"
    
    try {
        $assignments = @()
        
        # Get all role-assignable groups and their role assignments
        $roleAssignableGroups = @()
        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=isAssignableToRole eq true"
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            $roleAssignableGroups += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        foreach ($group in $roleAssignableGroups) {
            # Get role assignments for this group
            $groupRoleAssignments = @()
            $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($group.id)'&`$expand=roleDefinition"
            do {
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri
                $groupRoleAssignments += $response.value
                $uri = $response.'@odata.nextLink'
            } while ($uri)
            
            if ($groupRoleAssignments.Count -gt 0) {
                # Get members of this group
                $members = @()
                $uri = "https://graph.microsoft.com/v1.0/groups/$($group.id)/members"
                do {
                    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
                    $members += $response.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
                    $uri = $response.'@odata.nextLink'
                } while ($uri)
                
                # Create assignments for each member and role combination
                foreach ($member in $members) {
                    foreach ($roleAssignment in $groupRoleAssignments) {
                        $userDisplayName = Get-UserDisplayName -UserId $member.id
                        $groupDisplayName = Get-GroupDisplayName -GroupId $group.id
                        $assignments += [PSCustomObject]@{
                            AssignmentType = "Group-Based"
                            UserDisplayName = $userDisplayName
                            UserId = $member.id
                            RoleName = $roleAssignment.roleDefinition.displayName
                            RoleId = $roleAssignment.roleDefinitionId
                            GroupName = $groupDisplayName
                            GroupId = $group.id
                            StartDateTime = ""
                            EndDateTime = ""
                            Source = "Group Membership"
                        }
                    }
                }
            }
        }
        
        $Global:Stats.GroupBasedRoles = $assignments.Count
        Write-Host "✓ Found $($assignments.Count) group-based role assignments" -ForegroundColor Green
        return $assignments
    }
    catch {
        Write-Host "✗ Error collecting group-based roles: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-GroupAccessReport {
    [CmdletBinding()]
    param()
    
    Write-Progress-Update -Activity "Analyzing Data" -Status "Generating Group Access Report"
    
    try {
        $groupReport = @()
        
        # Get all role-assignable groups
        $roleAssignableGroups = @()
        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=isAssignableToRole eq true"
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            $roleAssignableGroups += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        foreach ($group in $roleAssignableGroups) {
            $groupDisplayName = Get-GroupDisplayName -GroupId $group.id
            
            # Get direct role assignments for this group
            $directRoles = @()
            $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($group.id)'&`$expand=roleDefinition"
            do {
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri
                $directRoles += $response.value
                $uri = $response.'@odata.nextLink'
            } while ($uri)
            
            # Get PIM eligible roles for this group
            $pimEligibleRoles = @()
            $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$($group.id)'&`$expand=roleDefinition"
            do {
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri
                $pimEligibleRoles += $response.value
                $uri = $response.'@odata.nextLink'
            } while ($uri)
            
            # Get PIM active roles for this group
            $pimActiveRoles = @()
            $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$($group.id)'&`$expand=roleDefinition"
            do {
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri
                $pimActiveRoles += $response.value
                $uri = $response.'@odata.nextLink'
            } while ($uri)
            
            # Get group members
            $directMembers = @()
            $uri = "https://graph.microsoft.com/v1.0/groups/$($group.id)/members"
            do {
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri
                $directMembers += $response.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
                $uri = $response.'@odata.nextLink'
            } while ($uri)
            
            # Get PIM eligible members for this group
            $pimEligibleMembers = @()
            try {
                $uri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($group.id)'"
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri
                $pimEligibleMembers = $response.value
            }
            catch {
                # Group may not have PIM enabled
            }
            
            # Get PIM active members for this group
            $pimActiveMembers = @()
            try {
                $uri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$($group.id)'"
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri
                $pimActiveMembers = $response.value
            }
            catch {
                # Group may not have PIM enabled
            }
            
            # Combine all roles assigned to this group
            $allRoles = @()
            $allRoles += $directRoles | ForEach-Object { [PSCustomObject]@{ RoleName = $_.roleDefinition.displayName; Type = "Direct" } }
            $allRoles += $pimEligibleRoles | ForEach-Object { [PSCustomObject]@{ RoleName = $_.roleDefinition.displayName; Type = "PIM Eligible" } }
            $allRoles += $pimActiveRoles | ForEach-Object { [PSCustomObject]@{ RoleName = $_.roleDefinition.displayName; Type = "PIM Active" } }
            
            # Create report entry for each role
            if ($allRoles.Count -gt 0 -or $directMembers.Count -gt 0 -or $pimEligibleMembers.Count -gt 0 -or $pimActiveMembers.Count -gt 0) {
                $rolesList = ($allRoles | ForEach-Object { "$($_.RoleName) ($($_.Type))" }) -join "; "
                if ([string]::IsNullOrEmpty($rolesList)) { $rolesList = "No Direct Roles" }
                
                $groupReport += [PSCustomObject]@{
                    GroupName = $groupDisplayName
                    GroupId = $group.id
                    AssignedRoles = $rolesList
                    DirectMembers = $directMembers.Count
                    PIMEligibleMembers = $pimEligibleMembers.Count
                    PIMActiveMembers = $pimActiveMembers.Count
                    TotalUniqueUsers = ($directMembers.id + $pimEligibleMembers.principalId + $pimActiveMembers.principalId | Sort-Object -Unique).Count
                    GroupType = if ($group.isAssignableToRole) { "Role-Assignable" } else { "Regular" }
                }
            }
        }
        
        $Global:GroupReport = $groupReport
        Write-Host "✓ Generated group access report for $($groupReport.Count) groups" -ForegroundColor Green
        return $groupReport
    }
    catch {
        Write-Host "✗ Error generating group access report: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

#-----------------------------------------------------------
# Report Functions
#-----------------------------------------------------------
function Show-AssignmentSummary {
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== PRIVILEGED ACCESS SUMMARY ===" -ForegroundColor Magenta
    Write-Host "Assignment Type              Count" -ForegroundColor Green
    Write-Host "--------------------------------" -ForegroundColor Green
    Write-Host "Direct/Permanent            $($Global:Stats.DirectRoles.ToString().PadLeft(6))" -ForegroundColor White
    Write-Host "PIM Eligible Roles          $($Global:Stats.PIMEligibleRoles.ToString().PadLeft(6))" -ForegroundColor Yellow
    Write-Host "PIM Active Roles            $($Global:Stats.PIMActiveRoles.ToString().PadLeft(6))" -ForegroundColor Red
    Write-Host "PIM Eligible Groups         $($Global:Stats.PIMEligibleGroups.ToString().PadLeft(6))" -ForegroundColor Yellow
    Write-Host "PIM Active Groups           $($Global:Stats.PIMActiveGroups.ToString().PadLeft(6))" -ForegroundColor Red
    Write-Host "Group-Based Roles           $($Global:Stats.GroupBasedRoles.ToString().PadLeft(6))" -ForegroundColor Cyan
    Write-Host "--------------------------------" -ForegroundColor Green
    $total = $Global:Stats.DirectRoles + $Global:Stats.PIMEligibleRoles + $Global:Stats.PIMActiveRoles + $Global:Stats.PIMEligibleGroups + $Global:Stats.PIMActiveGroups + $Global:Stats.GroupBasedRoles
    Write-Host "TOTAL ASSIGNMENTS           $($total.ToString().PadLeft(6))" -ForegroundColor Magenta
    
    $uniqueUsers = ($Global:AllAssignments | Select-Object -Unique UserId).Count
    $uniqueRoles = ($Global:AllAssignments | Where-Object { $_.RoleName -ne "Privileged Access Group Member" } | Select-Object -Unique RoleName).Count
    
    Write-Host "`nUnique Users with Privileges: $uniqueUsers" -ForegroundColor Cyan
    Write-Host "Unique Roles Assigned:        $uniqueRoles" -ForegroundColor Cyan
}

function Show-RoleSummary {
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== TOP 10 ROLES BY USER COUNT ===" -ForegroundColor Magenta
    
    $roleCounts = $Global:AllAssignments | 
        Where-Object { $_.RoleName -ne "Privileged Access Group Member" } |
        Group-Object -Property RoleName | 
        Sort-Object Count -Descending | 
        Select-Object -First 10
    
    Write-Host "Role Name                                        Users" -ForegroundColor Green
    Write-Host "------------------------------------------------ -----" -ForegroundColor Green
    
    foreach ($role in $roleCounts) {
        $roleName = $role.Name
        if ($roleName.Length -gt 48) {
            $roleName = $roleName.Substring(0, 45) + "..."
        }
        Write-Host "$($roleName.PadRight(48)) $($role.Count.ToString().PadLeft(5))" -ForegroundColor White
    }
}

function Show-GroupSummary {
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== TOP 10 GROUPS BY USER COUNT ===" -ForegroundColor Magenta
    
    $topGroups = $Global:GroupReport | 
        Sort-Object TotalUniqueUsers -Descending | 
        Select-Object -First 10
    
    Write-Host "Group Name                                       Users Roles" -ForegroundColor Green
    Write-Host "------------------------------------------------ ----- -----" -ForegroundColor Green
    
    foreach ($group in $topGroups) {
        $groupName = $group.GroupName
        if ($groupName.Length -gt 48) {
            $groupName = $groupName.Substring(0, 45) + "..."
        }
        $roleCount = ($group.AssignedRoles -split ';').Count
        Write-Host "$($groupName.PadRight(48)) $($group.TotalUniqueUsers.ToString().PadLeft(5)) $($roleCount.ToString().PadLeft(5))" -ForegroundColor White
    }
}

function Show-DetailedReport {
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== DETAILED REPORTS SAVED TO CSV ===" -ForegroundColor Magenta
    Write-Host "• User assignments: Individual user role assignments" -ForegroundColor Gray
    Write-Host "• Group report: Group-based access with member counts" -ForegroundColor Gray
}

#-----------------------------------------------------------
# Export Functions
#-----------------------------------------------------------
function Export-UserAssignments {
    [CmdletBinding()]
    param(
        [string]$Path
    )
    
    if ([string]::IsNullOrEmpty($Path)) {
        return
    }
    
    try {
        $Global:AllAssignments | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-Host "✓ User assignments exported to: $Path" -ForegroundColor Green
    }
    catch {
        Write-Host "✗ Error exporting user assignments to CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Export-GroupReport {
    [CmdletBinding()]
    param(
        [string]$Path
    )
    
    if ([string]::IsNullOrEmpty($Path)) {
        return
    }
    
    try {
        $Global:GroupReport | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-Host "✓ Group report exported to: $Path" -ForegroundColor Green
    }
    catch {
        Write-Host "✗ Error exporting group report to CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
}

#-----------------------------------------------------------
# Main Execution
#-----------------------------------------------------------
function Main {
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "    COMPREHENSIVE PIM REPORTING SCRIPT        " -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    
    # Check connection and permissions
    if (-not (Test-GraphConnection)) {
        Write-Host "`nExiting script. Please connect with required permissions and try again." -ForegroundColor Red
        return
    }
    
    Write-Host "`n=== COLLECTING PRIVILEGED ACCESS DATA ===" -ForegroundColor Cyan
    
    # Collect user assignments (excluding groups and service principals from direct assignments)
    $allAssignments = @()
    $allAssignments += Get-DirectRoleAssignments
    $allAssignments += Get-PIMEligibleRoles
    $allAssignments += Get-PIMActiveRoles
    $allAssignments += Get-PIMEligibleGroups
    $allAssignments += Get-PIMActiveGroups
    $allAssignments += Get-GroupBasedRoleAssignments
    
    $Global:AllAssignments = $allAssignments
    
    # Generate group access report
    $groupReport = Get-GroupAccessReport
    
    Write-Host "`n=== DATA COLLECTION COMPLETE ===" -ForegroundColor Green
    Write-Host "User assignments collected: $($allAssignments.Count)" -ForegroundColor White
    Write-Host "Groups analyzed: $($groupReport.Count)" -ForegroundColor White
    
    # Generate reports
    Show-AssignmentSummary
    Show-RoleSummary
    Show-GroupSummary
    Show-DetailedReport
    
    # Export CSV files with timestamp
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    
    # Export user assignments
    $userExportPath = if ([string]::IsNullOrEmpty($ExportPath)) {
        "PIM_UserAssignments_$timestamp.csv"
    } else {
        $ExportPath -replace '\.csv$', "_UserAssignments.csv"
    }
    Export-UserAssignments -Path $userExportPath
    
    # Export group report
    $groupExportPath = if ([string]::IsNullOrEmpty($ExportPath)) {
        "PIM_GroupReport_$timestamp.csv"
    } else {
        $ExportPath -replace '\.csv$', "_GroupReport.csv"
    }
    Export-GroupReport -Path $groupExportPath
    
    Write-Host "`n=== REPORTING COMPLETE ===" -ForegroundColor Cyan
    Write-Host "Cache statistics:" -ForegroundColor Gray
    Write-Host "  Users cached: $($Global:UserCache.Count)" -ForegroundColor Gray
    Write-Host "  Groups cached: $($Global:GroupCache.Count)" -ForegroundColor Gray
}

# Execute main function
Main
