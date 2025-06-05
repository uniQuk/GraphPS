## Enhanced DLP Report Converter - Handles ALL condition types generically (sender, domain, access scope, etc.)
## This script does not use graph - requires ExchangeOnline Module and also connecting to Security and Compliance:
# Connect-ExchangeOnline
# Connect-IPPSSession

function Test-HasMeaningfulValue {
    param([object]$Value)

    if ($null -eq $Value -or $Value -eq $false) { return $false }

    if ($Value -is [string]) {
        $trimmed = $Value.Trim()
        return -not ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed -eq "All")
    }

    if ($Value -is [Array] -or $Value -is [System.Collections.IEnumerable]) {
        $arrayValue = @($Value) | Where-Object { 
            $_ -ne $null -and -not ([string]::IsNullOrWhiteSpace($_)) -and $_ -ne "All" 
        }
        return $arrayValue.Count -gt 0
    }

    if ($Value -eq 0 -and $Value.GetType().Name -ne "DateTime") { return $false }

    return $true
}

function Test-ShouldBeTable {
    param(
        [object]$Array,
        [string]$PropertyName = ""
    )
    
    # Must be an array with PSCustomObjects
    if ($Array.Count -eq 0 -or $Array[0] -isnot [PSCustomObject]) {
        return $false
    }
    
    # Get all properties from all objects to determine table structure
    $allProperties = @()
    foreach ($item in $Array) {
        $allProperties += $item.PSObject.Properties.Name
    }
    
    # Remove duplicates and get unique properties
    $uniqueProperties = $allProperties | Sort-Object | Get-Unique
    
    # Common table patterns for DLP data
    $tablePatterns = @(
        # Sensitive information patterns
        @{
            RequiredProps = @("name", "classifiertype")
            OptionalProps = @("confidencelevel", "mincount", "maxcount", "minconfidence", "maxconfidence", "id")
            Description = "Sensitive Information Types"
        },
        # Generic object pattern - if all objects have the same structure and reasonable number of properties
        @{
            RequiredProps = @()
            OptionalProps = @()
            Description = "Generic Table"
            Condition = { 
                param($props, $objects)
                # Criteria: all objects have same properties, reasonable number of columns (2-10), mostly simple values
                $allHaveSameProps = $true
                $firstObjProps = $objects[0].PSObject.Properties.Name | Sort-Object
                
                foreach ($obj in $objects[1..($objects.Count-1)]) {
                    $objProps = $obj.PSObject.Properties.Name | Sort-Object
                    if ($null -ne (Compare-Object $firstObjProps $objProps)) {
                        $allHaveSameProps = $false
                        break
                    }
                }
                
                # Check if properties contain mostly simple values (strings, numbers, booleans)
                $simpleValueRatio = 0
                $totalValues = 0
                foreach ($obj in $objects) {
                    foreach ($prop in $obj.PSObject.Properties) {
                        $totalValues++
                        if ($prop.Value -is [string] -or $prop.Value -is [int] -or $prop.Value -is [bool] -or 
                            $prop.Value -is [decimal] -or $prop.Value -is [double] -or $null -eq $prop.Value) {
                            $simpleValueRatio++
                        }
                    }
                }
                
                $percentSimple = if ($totalValues -gt 0) { $simpleValueRatio / $totalValues } else { 0 }
                
                return ($allHaveSameProps -and $props.Count -ge 2 -and $props.Count -le 10 -and $percentSimple -ge 0.8)
            }
        }
    )
    
    # Check each pattern
    foreach ($pattern in $tablePatterns) {
        if ($pattern.Condition) {
            # Custom condition
            if (& $pattern.Condition $uniqueProperties $Array) {
                return $true
            }
        } else {
            # Required/Optional properties pattern
            $hasRequiredProps = $true
            foreach ($reqProp in $pattern.RequiredProps) {
                if ($reqProp -notin $uniqueProperties) {
                    $hasRequiredProps = $false
                    break
                }
            }
            
            if ($hasRequiredProps) {
                return $true
            }
        }
    }
    
    return $false
}

function Convert-ArrayToTable {
    param(
        [array]$Array,
        [string]$PropertyName,
        [int]$IndentLevel = 0
    )
    
    $indent = "  " * $IndentLevel
    $markdown = @()
    
    # Get all unique properties from all objects
    $allProperties = @()
    foreach ($item in $Array) {
        $allProperties += $item.PSObject.Properties.Name
    }
    $uniqueProperties = $allProperties | Sort-Object | Get-Unique
    
    # Determine if this looks like sensitive information types
    $isSensitiveInfo = $uniqueProperties -contains "name" -and 
                       ($uniqueProperties -contains "classifiertype" -or 
                        $uniqueProperties -contains "confidencelevel")
    
    if ($isSensitiveInfo) {
        # Use specialized headers for sensitive information
        $tableHeaders = @("Name", "Type", "Confidence", "Min Count", "Max Count", "Min Conf", "Max Conf")
        $markdown += "$indent- **$PropertyName** (Table):"
        $markdown += ""
        
        $headerRow = "$indent  | " + ($tableHeaders -join " | ") + " |"
        $separatorRow = "$indent  | " + (($tableHeaders | ForEach-Object { "---" }) -join " | ") + " |"
        
        $markdown += $headerRow
        $markdown += $separatorRow
        
        foreach ($item in $Array) {
            $name = if ($item.name) { $item.name -replace '\|', '\|' } else { "N/A" }
            $classifierType = if ($item.classifiertype) { $item.classifiertype } else { "N/A" }
            $confidenceLevel = if ($item.confidencelevel) { $item.confidencelevel } else { "N/A" }
            $minCount = if ($item.mincount) { $item.mincount.ToString() } else { "N/A" }
            $maxCount = if ($item.maxcount) { $item.maxcount.ToString() } else { "N/A" }
            $minConfidence = if ($item.minconfidence) { $item.minconfidence.ToString() } else { "N/A" }
            $maxConfidence = if ($item.maxconfidence) { $item.maxconfidence.ToString() } else { "N/A" }
            
            $row = "$indent  | $name | $classifierType | $confidenceLevel | $minCount | $maxCount | $minConfidence | $maxConfidence |"
            $markdown += $row
        }
    } else {
        # Generic table with dynamic columns
        $markdown += "$indent- **$PropertyName** (Table):"
        $markdown += ""
        
        # Create headers from property names (capitalize first letter)
        $tableHeaders = $uniqueProperties | ForEach-Object { 
            (Get-Culture).TextInfo.ToTitleCase($_)
        }
        
        $headerRow = "$indent  | " + ($tableHeaders -join " | ") + " |"
        $separatorRow = "$indent  | " + (($tableHeaders | ForEach-Object { "---" }) -join " | ") + " |"
        
        $markdown += $headerRow
        $markdown += $separatorRow
        
        foreach ($item in $Array) {
            $rowValues = @()
            foreach ($prop in $uniqueProperties) {
                $value = if ($null -ne $item.$prop) { 
                    $item.$prop.ToString() -replace '\|', '\|' 
                } else { 
                    "N/A" 
                }
                $rowValues += $value
            }
            
            $row = "$indent  | " + ($rowValues -join " | ") + " |"
            $markdown += $row
        }
    }
    
    $markdown += ""
    return $markdown
}

function Convert-ObjectToMarkdown {
    param(
        [object]$Object,
        [int]$IndentLevel = 0,
        [string]$PropertyName = ""
    )
    
    $indent = "  " * $IndentLevel
    $markdown = @()
    
    if ($null -eq $Object) {
        return "$indent- **$PropertyName**: *(null)*"
    }
    
    # Handle different object types
    switch ($Object.GetType().Name) {
        "String" {
            $markdown += "$indent- **$PropertyName**: ``$Object``"
        }
        "Boolean" {
            $markdown += "$indent- **$PropertyName**: ``$Object``"
        }
        { $_ -in @("Int32", "Int64", "Double", "Decimal") } {
            $markdown += "$indent- **$PropertyName**: $Object"
        }
        { $_ -in @("Object[]", "ArrayList") } {
            if ($Object.Count -eq 0) {
                $markdown += "$indent- **$PropertyName**: *(empty array)*"
            }
            elseif ($Object.Count -eq 1 -and $Object[0] -is [string]) {
                $markdown += "$indent- **$PropertyName**: ``$($Object[0])``"
            }
            elseif ($Object.Count -gt 0 -and $Object[0] -is [PSCustomObject] -and (Test-ShouldBeTable -Array $Object -PropertyName $PropertyName)) {
                # Convert to table
                $tableMarkdown = Convert-ArrayToTable -Array $Object -PropertyName $PropertyName -IndentLevel $IndentLevel
                $markdown += $tableMarkdown
            }
            # Check if this is a groups array that should be handled specially
            elseif ($PropertyName -eq "groups" -and $Object.Count -gt 0 -and $Object[0] -is [PSCustomObject]) {
                $markdown += "$indent- **$PropertyName** (Condition Groups):"
                for ($i = 0; $i -lt $Object.Count; $i++) {
                    $group = $Object[$i]
                    $markdown += "$indent  - **Group $($i + 1)**: $($group.name) (Operator: $($group.operator))"
                    
                    if ($group.sensitivetypes) {
                        $sensitivetypesMarkdown = Convert-ObjectToMarkdown -Object $group.sensitivetypes -IndentLevel ($IndentLevel + 2) -PropertyName "sensitivetypes"
                        $markdown += $sensitivetypesMarkdown
                    }
                }
            }
            else {
                $markdown += "$indent- **$PropertyName** (Array):"
                for ($i = 0; $i -lt $Object.Count; $i++) {
                    if ($Object[$i] -is [string]) {
                        $markdown += "$indent  - Item $($i + 1): ``$($Object[$i])``"
                    }
                    else {
                        $itemMarkdown = Convert-ObjectToMarkdown -Object $Object[$i] -IndentLevel ($IndentLevel + 1) -PropertyName "Item $($i + 1)"
                        $markdown += $itemMarkdown
                    }
                }
            }
        }
        default {
            # Handle PSCustomObject and other complex objects
            if ($Object -is [PSCustomObject] -or $Object.GetType().Name -eq "PSCustomObject") {
                if ($PropertyName) {
                    $markdown += "$indent- **$PropertyName**:"
                }
                
                $properties = $Object.PSObject.Properties | Sort-Object Name
                foreach ($prop in $properties) {
                    $propMarkdown = Convert-ObjectToMarkdown -Object $prop.Value -IndentLevel ($IndentLevel + 1) -PropertyName $prop.Name
                    $markdown += $propMarkdown
                }
            }
            else {
                # Fallback for unknown types
                $markdown += "$indent- **$PropertyName**: $($Object.ToString())"
            }
        }
    }
    
    return $markdown
}

function Get-SensitiveInformationTypes {
    param(
        [object]$Value
    )
    
    $sensitiveTypes = @()
    
    if ($null -eq $Value) {
        return $sensitiveTypes
    }
    
    # Handle array of items
    if ($Value -is [Array] -or $Value.GetType().Name -like "*ArrayList*") {
        foreach ($item in $Value) {
            # Look for Groups property
            if ($item.PSObject.Properties.Name -contains "Groups") {
                if ($item.Groups -is [Array] -or $item.Groups.GetType().Name -like "*ArrayList*") {
                    foreach ($group in $item.Groups) {
                        # Look for sensitivetypes property
                        if ($group.PSObject.Properties.Name -contains "sensitivetypes") {
                            if ($group.sensitivetypes -is [Array] -or $group.sensitivetypes.GetType().Name -like "*ArrayList*") {
                                $sensitiveTypes += $group.sensitivetypes
                            }
                        }
                    }
                }
            }
            # Also check if the item itself has sensitive type properties
            elseif ($item.PSObject.Properties.Name -contains "name" -and 
                   ($item.PSObject.Properties.Name -contains "classifiertype" -or 
                    $item.PSObject.Properties.Name -contains "confidencelevel")) {
                $sensitiveTypes += $item
            }
        }
    }
    # Handle single object
    elseif ($Value -is [PSCustomObject]) {
        # Check if this object directly contains sensitive type properties
        if ($Value.PSObject.Properties.Name -contains "name" -and 
           ($Value.PSObject.Properties.Name -contains "classifiertype" -or 
            $Value.PSObject.Properties.Name -contains "confidencelevel")) {
            $sensitiveTypes += $Value
        }
        # Or if it has nested structure
        elseif ($Value.PSObject.Properties.Name -contains "Groups") {
            $nestedTypes = Get-SensitiveInformationTypes -Value @($Value)
            $sensitiveTypes += $nestedTypes
        }
    }
    
    return $sensitiveTypes
}

function Convert-ConditionToMarkdown {
    param(
        [object]$Condition,
        [int]$IndentLevel = 1
    )
    
    $indent = "  " * $IndentLevel
    $markdown = @()
    
    if ($null -eq $Condition) {
        return @()
    }
    
    # Handle conditions with ConditionName (leaf conditions)
    if ($Condition.ConditionName) {
        $markdown += "$indent- **$($Condition.ConditionName)**"
        
        if ($Condition.Value) {
            # Special handling for ContentContainsSensitiveInformation
            if ($Condition.ConditionName -eq "ContentContainsSensitiveInformation") {
                # Extract sensitive information types from the nested structure
                $sensitiveTypes = Get-SensitiveInformationTypes -Value $Condition.Value
                
                if ($sensitiveTypes.Count -gt 0) {
                    # Convert to table format
                    $tableMarkdown = Convert-ArrayToTable -Array $sensitiveTypes -PropertyName "Value" -IndentLevel ($IndentLevel + 1)
                    $markdown += $tableMarkdown
                } else {
                    # Fallback to regular object markdown if no sensitive types found
                    $valueMarkdown = Convert-ObjectToMarkdown -Object $Condition.Value -IndentLevel ($IndentLevel + 1) -PropertyName "Value"
                    $markdown += $valueMarkdown
                }
            } else {
                # Regular handling for other condition types
                $valueMarkdown = Convert-ObjectToMarkdown -Object $Condition.Value -IndentLevel ($IndentLevel + 1) -PropertyName "Value"
                $markdown += $valueMarkdown
            }
        }
    }
    # Handle conditions with Operator (nested conditions)
    elseif ($Condition.Operator) {
        $markdown += "$indent- **Operator**: $($Condition.Operator)"
        
        if ($Condition.SubConditions) {
            $markdown += "$indent- **Sub Conditions**:"
            foreach ($subCondition in $Condition.SubConditions) {
                $subMarkdown = Convert-ConditionToMarkdown -Condition $subCondition -IndentLevel ($IndentLevel + 1)
                $markdown += $subMarkdown
            }
        }
    }
    # Fallback for other condition types
    else {
        $conditionMarkdown = Convert-ObjectToMarkdown -Object $Condition -IndentLevel $IndentLevel -PropertyName "Condition"
        $markdown += $conditionMarkdown
    }
    
    return $markdown
}

function Convert-AdvancedRuleToMarkdown {
    param(
        [string]$AdvancedRuleJson,
        [string]$RuleName
    )
    
    if ([string]::IsNullOrWhiteSpace($AdvancedRuleJson) -or $AdvancedRuleJson -eq "{…}") {
        return "*(No advanced rule details available)*"
    }
    
    try {
        $rule = $AdvancedRuleJson | ConvertFrom-Json
        $markdown = @()
        
        $markdown += "**Advanced Rule Configuration**"
        $markdown += ""
        
        # Handle Version if present
        if ($rule.Version) {
            $markdown += "**Version**: $($rule.Version)"
            $markdown += ""
        }
        
        # Handle the main Condition using the recursive function
        if ($rule.Condition) {
            $markdown += "**Main Condition**:"
            
            # Handle main condition operator
            if ($rule.Condition.Operator) {
                $markdown += "- **Operator**: $($rule.Condition.Operator)"
            }
            
            # Handle SubConditions recursively
            if ($rule.Condition.SubConditions) {
                $markdown += "- **Sub Conditions**:"
                
                foreach ($subCondition in $rule.Condition.SubConditions) {
                    $conditionMarkdown = Convert-ConditionToMarkdown -Condition $subCondition -IndentLevel 1
                    $markdown += $conditionMarkdown
                }
            }
        }
        
        # Handle any other top-level properties generically
        $rule.PSObject.Properties | Where-Object { $_.Name -notin @("Version", "Condition") } | ForEach-Object {
            $markdown += ""
            $propMarkdown = Convert-ObjectToMarkdown -Object $_.Value -IndentLevel 0 -PropertyName $_.Name
            $markdown += $propMarkdown
        }
        
        return ($markdown -join "`n")
    }
    catch {
        return "*(Error parsing advanced rule: $($_.Exception.Message))*"
    }
}

function Get-DLPPolicyDetailsMarkdown {
    $policies = Get-DlpCompliancePolicy -IncludeExtendedProperties $true -IncludeRulesMetadata $true -Summary
    $rules = Get-DlpComplianceRule -IncludeExecutionRuleGuids $true

    $markdown = @()
    
    # Title and overview
    $markdown += "# DLP Policies and Rules Report (Enhanced)"
    $markdown += ""
    $markdown += "Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $markdown += "*This enhanced report captures ALL condition types: sensitive information, sender, domain, access scope, sharing, and more.*"
    $markdown += ""
    $markdown += "## Overview"
    $markdown += ""
    $markdown += "| Metric | Count |"
    $markdown += "| --- | --- |"
    $markdown += "| Total Policies | $($policies.Count) |"
    $markdown += "| Total Rules | $($rules.Count) |"
    $markdown += ""
    
    # Policies summary
    $markdown += "## Policies Summary"
    $markdown += ""
    $markdown += "| Policy Name | Mode | Type | Workload | Priority | Enabled |"
    $markdown += "| --- | --- | --- | --- | --- | --- |"
    
    foreach ($policy in $policies | Sort-Object Priority) {
        $markdown += "| $($policy.DisplayName) | $($policy.Mode) | $($policy.Type) | $($policy.Workload) | $($policy.Priority) | $($policy.Enabled) |"
    }
    $markdown += ""
    
    # Detailed policy and rule information
    $markdown += "## Detailed Policy Information"
    $markdown += ""
    
    foreach ($policy in $policies | Sort-Object Priority) {
        $markdown += "### $($policy.DisplayName)"
        $markdown += ""
        
        # Policy details table - optimized with explicit empty value handling
        $markdown += "| Property | Value |"
        $markdown += "| --- | --- |"
        
        # Always show these core fields
        $markdown += "| Display Name | $($policy.DisplayName) |"
        $markdown += "| Mode | $($policy.Mode) |"
        $markdown += "| Type | $($policy.Type) |"
        $markdown += "| Workload | $($policy.Workload) |"
        $markdown += "| Priority | $($policy.Priority) |"
        $markdown += "| Enabled | $($policy.Enabled) |"
        
        # Show Distribution Status only if not empty
        if (![string]::IsNullOrWhiteSpace($policy.DistributionStatus)) {
            $markdown += "| Distribution Status | $($policy.DistributionStatus) |"
        }
        
        if (![string]::IsNullOrWhiteSpace($policy.DistributionSyncStatus)) {
            $markdown += "| Distribution Sync Status | $($policy.DistributionSyncStatus) |"
        }
        
        # Function to test location values more explicitly
        function Test-LocationHasValue {
            param($LocationValue)
            
            if ($null -eq $LocationValue) { return $false }
            if ($LocationValue -eq "") { return $false }
            
            # Handle arrays/collections explicitly
            if ($LocationValue -is [Array] -or $LocationValue.GetType().Name -like "*Collection*" -or $LocationValue.GetType().Name -eq "ArrayList") {
                $array = @($LocationValue)
                if ($array.Count -eq 0) { return $false }
                
                # Filter out empty and default values
                $meaningful = $array | Where-Object { 
                    $_ -ne "" -and 
                    $_ -ne "All" -and 
                    $null -ne $_ -and 
                    (-not [string]::IsNullOrWhiteSpace($_))
                }
                
                return $meaningful.Count -gt 0
            }
            
            # Handle strings
            if ($LocationValue -is [string]) {
                return ![string]::IsNullOrWhiteSpace($LocationValue) -and $LocationValue.Trim() -ne "All"
            }
            
            return $true
        }
        
        # Only show location fields if they have specific targeting
        if (Test-LocationHasValue $policy.ExchangeLocation) {
            $markdown += "| Exchange Location | $($policy.ExchangeLocation) |"
        }
        
        if (Test-LocationHasValue $policy.SharePointLocation) {
            $markdown += "| SharePoint Location | $($policy.SharePointLocation) |"
        }
        
        if (Test-LocationHasValue $policy.OneDriveLocation) {
            $markdown += "| OneDrive Location | $($policy.OneDriveLocation) |"
        }
        
        if (Test-LocationHasValue $policy.TeamsLocation) {
            $markdown += "| Teams Location | $($policy.TeamsLocation) |"
        }
        
        if (Test-LocationHasValue $policy.EndpointDlpLocation) {
            $markdown += "| Endpoint DLP Location | $($policy.EndpointDlpLocation) |"
        }
        
        # Show other meaningful fields
        if (![string]::IsNullOrWhiteSpace($policy.CreatedBy)) {
            $markdown += "| Created By | $($policy.CreatedBy) |"
        }
        
        if ($null -ne $policy.CreationTimeUtc -and $policy.CreationTimeUtc -ne "") {
            $markdown += "| Creation Date | $($policy.CreationTimeUtc) |"
        }
        
        $markdown += ""
        
        if ($policy.Comment) {
            $markdown += "Description: $($policy.Comment)"
            $markdown += ""
        }

        # Filter rules associated with the current policy
        $policyRules = $rules | Where-Object { $_.ParentPolicyName.Trim() -eq $policy.DisplayName.Trim() }

        # Check if there are any rules for the current policy
        if ($policyRules) {
            $markdown += "#### Rules for this Policy"
            $markdown += ""

            # Loop through each rule and display its details
            foreach ($rule in $policyRules) {
                $markdown += "##### $($rule.DisplayName)"
                $markdown += ""
                
function Convert-RuleToTable {
    param(
        [object]$Rule
    )
    
    $markdown = @()
    
    # Define core fields that should always be shown if present
    $coreFields = @("DisplayName", "CreatedBy", "Mode")
    
    # Define fields that need special formatting
    $specialFields = @{
        "Id" = {
            param($value)
            # Format rule ID to be more readable
            $ruleIdDisplay = $value
            if ($value -match "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})") {
                $ruleIdDisplay = $matches[1]
            } elseif ($value.Contains("/")) {
                $parts = $value.Split("/")
                $ruleIdDisplay = $parts[-1]
                if ($ruleIdDisplay.Length -gt 40) {
                    $ruleIdDisplay = "$($ruleIdDisplay.Substring(0, 37))..."
                }
            } elseif ($value.Length -gt 50) {
                $ruleIdDisplay = "$($value.Substring(0, 47))..."
            }
            return "``$ruleIdDisplay``"
        }
        "Priority" = {
            param($value)
            # Only show priority if it's not the default value (0)
            if ($null -ne $value -and $value -ne 0) {
                return $value.ToString()
            }
            return $null  # Skip this field
        }
    }
    
    # Fields to skip entirely (internal/system fields that aren't useful in reports)
    $skipFields = @(
        "PSComputerName", "PSShowComputerName", "PSSourceJobInstanceId", 
        "RunspaceId", "Identity", "DistinguishedName", "WhenChanged", 
        "WhenChangedUTC", "OrganizationId", "PSSession", "Guid"
    )
    
    $markdown += "| Property | Value |"
    $markdown += "| --- | --- |"
    
    # First, show core fields in order
    foreach ($coreField in $coreFields) {
        if ($Rule.PSObject.Properties.Name -contains $coreField) {
            $value = $Rule.$coreField
            if (Test-HasMeaningfulValue $value) {
                if ($specialFields.ContainsKey($coreField)) {
                    $formattedValue = & $specialFields[$coreField] $value
                    if ($null -ne $formattedValue) {
                        $markdown += "| $coreField | $formattedValue |"
                    }
                } else {
                    $markdown += "| $coreField | $value |"
                }
            }
        }
    }
    
    # Then show all other meaningful fields dynamically
    $allProperties = $Rule.PSObject.Properties | Where-Object { 
        $_.Name -notin $coreFields -and 
        $_.Name -notin $skipFields -and
        (Test-HasMeaningfulValue $_.Value)
    } | Sort-Object Name
    
    foreach ($prop in $allProperties) {
        $fieldName = $prop.Name
        $value = $prop.Value
        
        if ($specialFields.ContainsKey($fieldName)) {
            $formattedValue = & $specialFields[$fieldName] $value
            if ($null -ne $formattedValue) {
                $markdown += "| $fieldName | $formattedValue |"
            }
        } else {
            # Handle different value types appropriately
            if ($value -is [bool]) {
                $markdown += "| $fieldName | ``$value`` |"
            } elseif ($value -is [datetime]) {
                $markdown += "| $fieldName | $($value.ToString('yyyy-MM-dd HH:mm:ss')) |"
            } elseif ($value -is [array] -and $value.Count -le 3) {
                # For small arrays, show inline
                $arrayStr = ($value | ForEach-Object { "``$_``" }) -join ", "
                $markdown += "| $fieldName | $arrayStr |"
            } elseif ($value -is [string] -and $value.Length -lt 100) {
                # For shorter strings, use code formatting
                $markdown += "| $fieldName | ``$value`` |"
            } else {
                # For longer strings or complex objects, show as-is
                $markdown += "| $fieldName | $value |"
            }
        }
    }
    
    return $markdown
}
                
                $markdown += ""
                
                # Advanced rule details
                if ($rule.AdvancedRule -and $rule.AdvancedRule -ne "{…}") {
                    $markdown += "Advanced Rule Configuration:"
                    $markdown += ""
                    $advancedRuleMarkdown = Convert-AdvancedRuleToMarkdown -AdvancedRuleJson $rule.AdvancedRule -RuleName $rule.DisplayName
                    $markdown += $advancedRuleMarkdown
                    $markdown += ""
                }
                
                $markdown += "---"
                $markdown += ""
            }
        } else {
            $markdown += "#### No rules found for this policy"
            $markdown += ""
        }
        
        $markdown += ""
    }
    
    return ($markdown -join "`n")
}

# Generate the markdown report
$markdownContent = Get-DLPPolicyDetailsMarkdown
$markdownContent | Out-File "DLPPolicyDetails.md" -Encoding UTF8

Write-Host "Enhanced DLP Policy report generated: DLPPolicyDetails.md" -ForegroundColor Green
Write-Host "This report captures ALL DLP rule condition types (sender, domain, access scope, content sharing, sensitive info, etc.)" -ForegroundColor Cyan