
# Set specific user ID directly in the script
$SpecificUserId = "guid" # Replace with actual user GUID

# Calculate date ranges
$today = Get-Date
$startDate = $today.AddDays(-30)
$minAllowedDate = Get-Date "2025-03-15"
if ($startDate -lt $minAllowedDate) {
    $startDate = $minAllowedDate
}
$formattedStartDate = $startDate.ToString("yyyy-MM-dd")
$formattedEndDate = $today.ToString("yyyy-MM-dd")

Write-Host "Fetching data for period: $formattedStartDate to $formattedEndDate"

# Get the specific user
$user = Get-MgUser -UserId $SpecificUserId -Property Id, DisplayName, UserPrincipalName
Write-Host "Processing user: $($user.UserPrincipalName)" -ForegroundColor Cyan

# Create results arrays
$signInResults = @()
$auditResults = @()

$userPrincipalName = $user.UserPrincipalName
$userId = $user.Id

# Fetch sign-in activity
$signInFilter = "userId eq '$userId' and createdDateTime ge $formattedStartDate"
$userSignIns = Get-MgAuditLogSignIn -Filter $signInFilter -All

$groupedByDay = $userSignIns | Group-Object { ($_.CreatedDateTime -as [DateTime]).ToString("yyyy-MM-dd") }

foreach ($dayGroup in $groupedByDay) {
    $day = $dayGroup.Name
    $daySignIns = $dayGroup.Group | Sort-Object { $_.CreatedDateTime -as [DateTime] }

    $firstSignIn = $daySignIns | Select-Object -First 1
    $lastActivity = $daySignIns | Select-Object -Last 1

    if ($firstSignIn) {
        $signInResults += [PSCustomObject]@{
            Date              = $day
            UserPrincipalName = $userPrincipalName
            DisplayName       = $user.DisplayName
            FirstSignInTime   = $firstSignIn.CreatedDateTime
            LastActivityTime  = $lastActivity.CreatedDateTime
            AppDisplayName    = $firstSignIn.AppDisplayName
            ClientAppUsed     = $firstSignIn.ClientAppUsed
            IPAddress         = $firstSignIn.IPAddress
            Location          = $firstSignIn.Location.City
            DeviceDetail      = $firstSignIn.DeviceDetail.DisplayName
            Status            = ($firstSignIn.Status.ErrorCode -eq 0) ? "Success" : "Failure"
        }
    }
}

Write-Host "  - Processed $($userSignIns.Count) sign-in records" -ForegroundColor Green

# Fetch post-login Office activity using Unified Audit Log
foreach ($signIn in $signInResults) {
    $firstLoginTime = [DateTime]$signIn.FirstSignInTime
    $twoHoursAfterLogin = $firstLoginTime.AddHours(2)

    Write-Host "  - Getting app activity for $($signIn.Date) from $($firstLoginTime.ToString("HH:mm")) to $($twoHoursAfterLogin.ToString("HH:mm"))" -ForegroundColor Yellow

    try {
        $activities = Search-UnifiedAuditLog -StartDate $firstLoginTime -EndDate $twoHoursAfterLogin -UserIds $userPrincipalName -ResultSize 5000

        foreach ($activity in $activities) {
            $data = $activity.AuditData | ConvertFrom-Json

            $auditResults += [PSCustomObject]@{
                Date              = $signIn.Date
                FirstLoginTime    = $firstLoginTime.ToString("HH:mm:ss")
                TimeWindow        = "$($firstLoginTime.ToString("HH:mm"))-$($twoHoursAfterLogin.ToString("HH:mm"))"
                UserPrincipalName = $userPrincipalName
                Workload          = $activity.Workload
                Operation         = $activity.Operation
                RecordType        = $activity.RecordType
                ActivityTime      = $activity.CreationDate
                IPAddress         = $activity.ClientIP
                ObjectModified    = $data.ObjectId
                ItemName          = $data.Name
                Detail            = $data.OperationProperties
            }
        }

        if ($activities.Count -gt 0) {
            Write-Host "  - Found $($activities.Count) post-login activities on $($signIn.Date)" -ForegroundColor Green
        }
        else {
            Write-Host "  - No app activity in first 2 hours on $($signIn.Date)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  - Error fetching UAL data for $userPrincipalName on $($signIn.Date): $_" -ForegroundColor Red
    }
}

# Export to CSV
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$signInOutputPath = "./UserSignInActivity_$timestamp.csv"
$auditOutputPath = "./PostLoginOfficeActivity_$timestamp.csv"

$signInResults | Export-Csv -Path $signInOutputPath -NoTypeInformation
$auditResults | Export-Csv -Path $auditOutputPath -NoTypeInformation

Write-Host "Sign-in report saved to: $signInOutputPath" -ForegroundColor Green
Write-Host "Office activity report saved to: $auditOutputPath" -ForegroundColor Green