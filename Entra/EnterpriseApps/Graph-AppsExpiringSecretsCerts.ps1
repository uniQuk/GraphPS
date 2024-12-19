# Description: This script will list all app registrations with secrets and certificates that are expiring within the next 30 days.
# Usage: .\Graph-AppsExpiringSecretsCerts.ps1
# Script 01: Graph-AppsExpiringSecretsCerts.ps1

# This is the simple working version of the script. 
# The reason for uploading both (and same with other copies of scripts) is that adding debugging, 
# error handling, and other features can make the script more complex and harder to understand. 


# Version: 1.0
# Created by: uniQuk 2024

$today = Get-Date
$expiryThreshold = $today.AddDays(30)

# Get all app registrations
$appRegistrations = Invoke-MgGraphRequest -uri "https://graph.microsoft.com/beta/applications" -Method GET -OutputType PSObject

# Initialise empty array to store the results
$expiringApps = @()

# Loop through each app registration
foreach ($app in $appRegistrations.value) {
    
    # Check passwordCredentials (secrets)
    foreach ($secret in $app.passwordCredentials) {
        if ($secret.endDateTime -lt $expiryThreshold) {
            $expiringApps += [PSCustomObject]@{
                AppId = $app.appId
                AppName = $app.displayName
                CredentialType = "Client Secret"
                EndDateTime = $secret.endDateTime
                DaysUntilExpiry = [math]::Round(($secret.endDateTime - (Get-Date)).TotalDays, 1)
                KeyId = $secret.keyId
            }
        }
    } 
    
    # Check keyCredentials (certificates)
    foreach ($cert in $app.keyCredentials) {
        if ($cert.endDateTime -lt $expiryThreshold) {
            $expiringApps += [PSCustomObject]@{
                AppId = $app.appId
                AppName = $app.displayName
                CredentialType = "Certificate"
                EndDateTime = $cert.endDateTime
                DaysUntilExpiry = [math]::Round(($cert.endDateTime - (Get-Date)).TotalDays, 1)
                KeyId = $cert.keyId
                # Thumbprint = $cert.thumbprint ## ToDO
            }
        }
    } # End of passwordCredentials loop
} # End of appRegistrations loop

# Output the results
$expiringApps | Sort-Object EndDateTime | Format-Table -AutoSize
# $expiringApps | Sort-Object EndDateTime | Format-Table -AutoSize | Out-File -FilePath "C:\temp\ExpiringApps.txt"
# $expiringApps | Out-ConsoleGridView
