# Description: This script will list all app registrations with secrets and certificates that are expiring within the next 30 days.
# Script 02: Graph-AppsExpiringSecretsCerts-EC.ps1

# Examples:
## Usafe: .\Graph-AppsExpiringSecretsCerts-EC.ps1
## Usage: .\Graph-AppsExpiringSecretsCerts-EC.ps1 -EnableLogging
## Usage: .\Graph-AppsExpiringSecretsCerts-EC.ps1 -EnableLogging -LogPath "/path/to/logs"
## Usage: .\Graph-AppsExpiringSecretsCerts-EC.ps1 -DaysToExpiry 45 -ExportToFile -EnableLogging -LogPath "C:\temp\logs"

# This is the enhanced version of the script with added features like logging, error handling, and export to file.
# The script will list all app registrations with secrets and certificates that are expiring within the next 30 days.
# There is a simpler working version of the script without Error Checking that's easier to read and learn from if you're new to Graph PowerShell.

# Version: 1.2
# Created by: uniQuk 2024

# Configuration parameters
param (
    [int]$DaysToExpiry = 30,
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) "ExpiringApps.csv"),
    [switch]$ExportToFile,
    [switch]$EnableLogging,
    [string]$LogPath = (Join-Path $PSScriptRoot "logs")
)

# Initialize logging if enabled
$ErrorActionPreference = "Stop"
$logFile = $null

if ($EnableLogging) {
    $logDate = Get-Date -Format "yyyyMMdd-HHmmss"
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }
    $logFile = Join-Path $LogPath "AppCredentialCheck_$logDate.log"
    Write-Host "Logging enabled. Log file: $logFile"
}

function Write-Log {
    param($Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Host $logMessage
    if ($EnableLogging -and $logFile) {
        Add-Content -Path $logFile -Value $logMessage
    }
}

try {
    Write-Log "Script started"
    $today = Get-Date
    $expiryThreshold = $today.AddDays($DaysToExpiry)

    # Get all app registrations with error handling
    Write-Log "Fetching app registrations"
    $appRegistrations = Invoke-MgGraphRequest -uri "https://graph.microsoft.com/beta/applications" -Method GET -OutputType PSObject -ErrorAction Stop

    # Initialize thread-safe collection
    $expiringApps = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

    # Process apps in parallel
    $appRegistrations.value | ForEach-Object -ThrottleLimit 10 -Parallel {
        $app = $_
        $expiryThreshold = $using:expiryThreshold
        $expiringApps = $using:expiringApps

        # Process secrets
        foreach ($secret in $app.passwordCredentials) {
            if ($secret.endDateTime -lt $expiryThreshold) {
                $expiringApps.Add([PSCustomObject]@{
                    AppId = $app.appId
                    AppName = $app.displayName
                    CredentialType = "Client Secret"
                    EndDateTime = $secret.endDateTime
                    DaysUntilExpiry = [math]::Round(($secret.endDateTime - (Get-Date)).TotalDays, 1)
                    KeyId = $secret.keyId
                })
            }
        }

        # Process certificates
        foreach ($cert in $app.keyCredentials) {
            if ($cert.endDateTime -lt $expiryThreshold) {
                $expiringApps.Add([PSCustomObject]@{
                    AppId = $app.appId
                    AppName = $app.displayName
                    CredentialType = "Certificate"
                    EndDateTime = $cert.endDateTime
                    DaysUntilExpiry = [math]::Round(($cert.endDateTime - (Get-Date)).TotalDays, 1)
                    KeyId = $cert.keyId
                    Thumbprint = $cert.thumbprint
                })
            }
        }
    }

    # Sort and output results
    $results = $expiringApps | Sort-Object EndDateTime

    if ($results.Count -eq 0) {
        Write-Log "No expiring credentials found"
    } else {
        Write-Log "Found $($results.Count) expiring credentials"
        $results | Format-Table -AutoSize

        if ($ExportToFile) {
            $results | Export-Csv -Path $OutputPath -NoTypeInformation
            Write-Log "Results exported to $OutputPath"
        }
    }
}
catch {
    Write-Log "Error: $_"
    throw
}
finally {
    Write-Log "Script completed"
}
