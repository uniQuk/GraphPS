# Description: This script retrieves role definitions, role assignments, groups, and members from Intune using Microsoft Graph API.
# Author: uniQuk 2024
# Version 1.1
# Improvements: Improved readability and structure of the Main Script section. Added progress bar for role definition processing.

[CmdletBinding()]
param (
    [Parameter()]
    [string]$OutputPath = "RoleAssignments.csv"
)


# Retrieves role assignments for a specified role definition in Intune.
function Get-RoleAssignments($roleDefinitionId) {
    try {
        # Using beta endpoint to get role assignments for specific role definition
        $url = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions('$roleDefinitionId')/roleAssignments"
        $response = Invoke-MgGraphRequest -uri $url -method Get -OutputType PSObject | Select-Object -ExpandProperty value
        if ($response.Count -eq 0) {
            Write-Log "No role assignments found for role definition $roleDefinitionId" -Level Warning
        }
        return $response
    }
    catch {
        Write-Log "Error getting role assignments: $_" -Level Error
        throw
    }
} # End of Get-RoleAssignments function


# Retrieves groups associated with a role assignment.
function Get-Groups($roleAssignmentId) {
    try {
        # Get role assignment details including scope tags
        $url = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments('$roleAssignmentId')?$expand=microsoft.graph.deviceAndAppManagementRoleAssignment/roleScopeTags"
        $response = Invoke-MgGraphRequest -uri $url -method Get -OutputType PSObject | Select-Object -ExpandProperty members
        if ($response.Count -eq 0) {
            Write-Log "No groups found for role assignment $roleAssignmentId" -Level Warning
        }
        return $response
    }
    catch {
        Write-Log "Error getting groups: $_" -Level Error
        throw
    }
} # End of Get-Groups function


# Retrieves detailed information about a group and its members.
function Get-GroupDetails($groupId) {
    try {
        # Get group details
        $url = "https://graph.microsoft.com/v1.0/groups('$groupId')"
        $groupDetails = Invoke-MgGraphRequest -uri $url -method Get -OutputType PSObject
        
        # Get group members
        $urlMembers = "https://graph.microsoft.com/v1.0/groups('$groupId')/members"
        $groupMembers = Invoke-MgGraphRequest -uri $urlMembers -method Get -OutputType PSObject | Select-Object -ExpandProperty value
        return $groupDetails, $groupMembers
    }
    catch {
        Write-Log "Error getting group details: $_" -Level Error
        throw
    }
} # End of Get-GroupDetails function

# Process a single role definition and its assignments
function Process-RoleDefinition($roleDefinition) {
    $roleEntry = @{
        Assignments = @{}
    }

    $roleAssignments = Get-RoleAssignments($roleDefinition.id)
    
    if ($roleAssignments) {
        foreach ($roleAssignment in $roleAssignments) {
            $roleEntry.Assignments[$roleAssignment.displayName] = Process-RoleAssignment $roleAssignment
        }
        Write-Log "Processed role: $($roleDefinition.displayName) - Found assignments"
    }
    else {
        Write-Log "Processed role: $($roleDefinition.displayName) - No assignments found" -Level Info
    }

    return $roleEntry
}

# Helper function to process group members
function Format-GroupMembers($members) {
    if (-not $members) { return @() }
    
    return $members | ForEach-Object {
        @{
            DisplayName = $_.displayName
            Id = $_.id
        }
    }
}

# Process a single role assignment and its groups
function Process-RoleAssignment($roleAssignment) {
    $assignmentEntry = @{
        Groups = @{}
    }

    $groups = Get-Groups($roleAssignment.id)
    if (-not $groups) { return $assignmentEntry }

    foreach ($group in $groups) {
        $groupDetails, $groupMembers = Get-GroupDetails($group)
        $assignmentEntry.Groups[$groupDetails.displayName] = Format-GroupMembers $groupMembers
    }

    return $assignmentEntry
}

# Convert hierarchical data to flat structure for CSV export
function Convert-ToFlatStructure($roleHierarchy) {
    $results = @()

    foreach ($roleName in $roleHierarchy.Keys | Sort-Object) {
        if ($roleHierarchy[$roleName].Assignments.Count -eq 0) {
            $results += New-ResultEntry $roleName "No assignments" "N/A" "No members" "No role assignments configured"
            continue
        }

        foreach ($assignmentName in $roleHierarchy[$roleName].Assignments.Keys | Sort-Object) {
            if ($roleHierarchy[$roleName].Assignments[$assignmentName].Groups.Count -eq 0) {
                $results += New-ResultEntry $roleName $assignmentName "No groups" "No members" "No groups assigned"
                continue
            }

            foreach ($groupName in $roleHierarchy[$roleName].Assignments[$assignmentName].Groups.Keys | Sort-Object) {
                $members = $roleHierarchy[$roleName].Assignments[$assignmentName].Groups[$groupName]
                $memberString = if ($members.Count -gt 0) {
                    ($members | ForEach-Object { "$($_.DisplayName) ($($_.Id))" }) -join (";{0}" -f [Environment]::NewLine)
                } else { "No members" }
                
                $status = if ($members.Count -gt 0) { "$($members.Count) members found" } else { "Group has no members" }
                
                $results += New-ResultEntry $roleName $assignmentName $groupName $memberString $status
            }
        }
    }

    return $results
}

# Create a new result entry object
function New-ResultEntry($roleName, $assignmentName, $groupName, $members, $status) {
    return [PSCustomObject]@{
        RoleDefinition = $roleName
        RoleAssignment = $assignmentName
        Group = $groupName
        Members = $members
        Status = $status
    }
}

# Main Script
try {
    Write-Log "Starting Intune role assignment collection"
    
    # Get all role definitions from Intune with paging support
    $roleDefinitions = @()
    $url = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
    do {
        $response = Invoke-MgGraphRequest -uri $url -method Get -OutputType PSObject
        $roleDefinitions += $response.value
        $url = $response.'@odata.nextLink'
    } while ($url)

    # Process roles and build hierarchy
    $roleHierarchy = @{}
    $totalRoles = $roleDefinitions.Count

    foreach ($roleDefinition in $roleDefinitions) {
        Write-Progress -Activity "Processing Role Definitions" `
                      -Status "Processing $($roleDefinition.displayName)" `
                      -PercentComplete (($roleDefinitions.IndexOf($roleDefinition) + 1) / $totalRoles * 100)
        
        $roleHierarchy[$roleDefinition.displayName] = Process-RoleDefinition $roleDefinition
    }

    # Convert to flat structure and export
    $results = Convert-ToFlatStructure $roleHierarchy
    Write-Log "Found $($results.Count) total entries"

    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Log "Results exported to $OutputPath"
    }
    else {
        Write-Log "No results to export" -Level Warning
    }
}
catch {
    Write-Log "Script execution failed: $_" -Level Error
    throw
}
finally {
    Write-Progress -Activity "Processing Role Definitions" -Completed
}