# Very Basic script to get Conditional Access Policies as JSON
# More complex CA scripts can be found here: https://github.com/uniQuk/caReports
function Get-ConditionalAccessPolicies {
    $uri = "/v1.0/identity/conditionalAccess/policies"
    try {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        return $response
    } catch {
        Write-Error "Failed to retrieve conditional access policies: $_"
        throw
    }
}

$policies = Get-ConditionalAccessPolicies
foreach ($policy in $policies.value) {
    $policy.displayName
    $policy.id
    $policy | ConvertTo-Json -Depth 10
}