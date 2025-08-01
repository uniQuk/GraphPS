<#
.SYNOPSIS
    Lists all app registrations and enterprise applications with secrets and certificates that are expiring within the specified threshold.

.DESCRIPTION
    This script queries Microsoft Entra ID (Azure AD) to identify expiring credentials across:
    - App Registration secrets and certificates
    - SAML SSO certificates (when -IncludeSAML is specified)
    
    The script maintains backward compatibility with the original functionality while adding
    enhanced features for comprehensive credential monitoring.

.PARAMETER DaysThreshold
    Number of days from today to check for expiring credentials. Must be between 1-365 days.
    Default: 30 days

.PARAMETER IncludeSAML
    Include SAML SSO certificates from Enterprise Applications in the scan.
    Default: False (App Registrations only)

.PARAMETER OutputFormat
    Output format for results. Supports Table (console display), CSV, JSON, and HTML formats.
    Valid values: Table, CSV, JSON, HTML
    Default: Table

.PARAMETER OutputPath
    File path where exported data should be saved. Optional for CSV, JSON, and HTML formats.
    If not specified, a timestamped filename will be generated in the current directory.
    Example: "C:\Reports\credential-report.csv"

.EXAMPLE
    .\Get-ExpiringEntraCredentials.ps1
    Uses default settings (30 days, App Registrations only, Table output)

.EXAMPLE
    .\Get-ExpiringEntraCredentials.ps1 -DaysThreshold 60 -IncludeSAML -Verbose
    Shows credentials expiring within 60 days including SAML certificates with verbose output

.EXAMPLE
    .\Get-ExpiringEntraCredentials.ps1 -DaysThreshold 7
    Shows only critically expiring credentials (within 7 days)

.EXAMPLE
    .\Get-ExpiringEntraCredentials.ps1 -OutputFormat CSV -OutputPath "C:\Reports\expiring-creds.csv"
    Exports results to CSV file at specified path

.EXAMPLE
    .\Get-ExpiringEntraCredentials.ps1 -OutputFormat HTML
    Generates HTML report with auto-generated timestamped filename in current directory

.EXAMPLE
    .\Get-ExpiringEntraCredentials.ps1 -IncludeSAML -OutputFormat HTML -OutputPath "report.html"
    Generates styled HTML report including SAML certificates

.EXAMPLE
    .\Get-ExpiringEntraCredentials.ps1 -DaysThreshold 90 -OutputFormat JSON -OutputPath "credentials.json"
    Exports comprehensive JSON report with 90-day threshold

.NOTES
    Version: 2.0
    Created: July 30, 2025
    Based on original script by: uniQuk 2024
    
    Requirements:
    - Microsoft Graph PowerShell SDK
    - Permissions: Application.Read.All, ServicePrincipal.Read.All
    - Connected to Microsoft Graph (Connect-MgGraph)

.LINK
    https://docs.microsoft.com/en-us/graph/api/resources/application
    https://docs.microsoft.com/en-us/graph/api/resources/serviceprincipal
#>

[CmdletBinding()]
param(
    # Number of days from today to check for expiring credentials (default: 30)
    [Parameter(Mandatory = $false, HelpMessage = "Number of days from today to check for expiring credentials (1-365)")]
    [ValidateRange(1, 365)]
    [int]$DaysThreshold = 30,
    
    # Include SAML SSO certificates from Enterprise Applications
    [Parameter(Mandatory = $false, HelpMessage = "Include SAML SSO certificates from Enterprise Applications")]
    [switch]$IncludeSAML,
    
    # Output format for results (future enhancement placeholder)
    [Parameter(Mandatory = $false, HelpMessage = "Output format for results")]
    [ValidateSet('Table', 'CSV', 'JSON', 'HTML')]
    [string]$OutputFormat = 'Table',
    
    # Output file path for export formats (CSV, JSON, HTML only)
    [Parameter(Mandatory = $false, HelpMessage = "File path for exported data (optional - auto-generated if not specified)")]
    [string]$OutputPath
)

#region Helper Functions

<#
.SYNOPSIS
    Retrieves expiring credentials from App Registrations
#>
function Get-AppRegistrationCredentials {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]$ExpiryThreshold
    )
    
    Write-Verbose "Querying App Registrations for expiring credentials..."
    Write-ProgressInfo -Activity "Scanning App Registrations" -Status "Retrieving application list..." -PercentComplete 0
    
    try {
        # Get all app registrations with retry logic
        $appRegistrations = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/applications" -Method GET
        $expiringCredentials = @()
        
        if (-not $appRegistrations.value -or $appRegistrations.value.Count -eq 0) {
            Write-ProgressInfo -Activity "Scanning App Registrations" -Status "No applications found" -PercentComplete 100
            Write-Warning "No App Registrations found in tenant"
            return @()
        }
        
        $totalApps = $appRegistrations.value.Count
        $processedApps = 0
        
        Write-Verbose "Found $totalApps App Registration(s) to process"
        
        foreach ($app in $appRegistrations.value) {
            $processedApps++
            $percentComplete = [math]::Round(($processedApps / $totalApps) * 100)
            
            Write-ProgressInfo -Activity "Scanning App Registrations" -Status "Processing applications..." -PercentComplete $percentComplete -CurrentOperation "Checking: $($app.displayName)"
            Write-Verbose "Processing App Registration ($processedApps/$totalApps): $($app.displayName)"
            
            # Check passwordCredentials (secrets)
            if ($app.passwordCredentials) {
                foreach ($secret in $app.passwordCredentials) {
                    if ($secret.endDateTime -lt $ExpiryThreshold) {
                        $daysUntilExpiry = [math]::Round(($secret.endDateTime - (Get-Date)).TotalDays, 1)
                        $riskLevel = Get-CredentialRiskLevel -DaysUntilExpiry $daysUntilExpiry
                        
                        $expiringCredentials += [PSCustomObject]@{
                            AppId = $app.appId
                            AppName = $app.displayName
                            AppType = "App Registration"
                            CredentialType = "Client Secret"
                            EndDateTime = $secret.endDateTime
                            DaysUntilExpiry = $daysUntilExpiry
                            RiskLevel = $riskLevel
                            KeyId = $secret.keyId
                            Thumbprint = $null
                            DisplayName = $secret.displayName
                            ActivityStatus = "N/A (Secret)"
                            Usage = "Authentication"
                            CertificateType = "N/A"
                        }
                    }
                }
            }
            
            # Check keyCredentials (certificates)
            if ($app.keyCredentials) {
                foreach ($cert in $app.keyCredentials) {
                    if ($cert.endDateTime -lt $ExpiryThreshold) {
                        $daysUntilExpiry = [math]::Round(($cert.endDateTime - (Get-Date)).TotalDays, 1)
                        $riskLevel = Get-CredentialRiskLevel -DaysUntilExpiry $daysUntilExpiry
                        
                        $expiringCredentials += [PSCustomObject]@{
                            AppId = $app.appId
                            AppName = $app.displayName
                            AppType = "App Registration"
                            CredentialType = "Certificate"
                            EndDateTime = $cert.endDateTime
                            DaysUntilExpiry = $daysUntilExpiry
                            RiskLevel = $riskLevel
                            KeyId = $cert.keyId
                            Thumbprint = $cert.customKeyIdentifier
                            DisplayName = $cert.displayName
                            ActivityStatus = "N/A (App Reg)"
                            Usage = $cert.usage
                            CertificateType = $cert.type
                        }
                    }
                }
            }
        }
        
        Write-ProgressInfo -Activity "Scanning App Registrations" -Status "Completed" -PercentComplete 100
        Write-Progress -Activity "Scanning App Registrations" -Completed
        
        Write-Verbose "Found $($expiringCredentials.Count) expiring App Registration credentials"
        return $expiringCredentials
    }
    catch {
        Write-Progress -Activity "Scanning App Registrations" -Completed
        Write-Error "Failed to retrieve App Registration credentials: $($_.Exception.Message)"
        Write-Host "💡 Troubleshooting tips:" -ForegroundColor Yellow
        Write-Host "   • Verify connection: Get-MgContext" -ForegroundColor White
        Write-Host "   • Check permissions: Application.Read.All required" -ForegroundColor White
        Write-Host "   • Try reconnecting: Connect-MgGraph -Scopes 'Application.Read.All','ServicePrincipal.Read.All'" -ForegroundColor White
        return @()
    }
}

<#
.SYNOPSIS
    Retrieves expiring SAML certificates from Enterprise Applications
#>
function Get-SAMLCertificates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]$ExpiryThreshold
    )
    
    Write-Verbose "Querying Enterprise Applications for expiring SAML certificates..."
    Write-ProgressInfo -Activity "Scanning SAML Applications" -Status "Retrieving SAML-enabled applications..." -PercentComplete 0
    
    try {
        # Get SAML-enabled service principals with retry logic
        $samlQuery = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=preferredSingleSignOnMode eq 'saml'&`$select=appId,displayName,keyCredentials,preferredSingleSignOnMode"
        $samlApps = Invoke-GraphRequestWithRetry -Uri $samlQuery -Method GET
        
        if (-not $samlApps.value -or $samlApps.value.Count -eq 0) {
            Write-ProgressInfo -Activity "Scanning SAML Applications" -Status "No SAML applications found" -PercentComplete 100
            Write-Progress -Activity "Scanning SAML Applications" -Completed
            Write-Warning "No SAML SSO applications found in tenant"
            return @()
        }
        
        $totalApps = $samlApps.value.Count
        $processedApps = 0
        $expiringCertificates = @()
        
        Write-Verbose "Found $totalApps SAML-enabled application(s) to process"
        
        foreach ($app in $samlApps.value) {
            $processedApps++
            $percentComplete = [math]::Round(($processedApps / $totalApps) * 100)
            
            Write-ProgressInfo -Activity "Scanning SAML Applications" -Status "Processing SAML applications..." -PercentComplete $percentComplete -CurrentOperation "Checking: $($app.displayName)"
            Write-Verbose "Processing SAML Enterprise Application ($processedApps/$totalApps): $($app.displayName)"
            
            # Check keyCredentials for SAML certificates
            if ($app.keyCredentials) {
                foreach ($cert in $app.keyCredentials) {
                    if ($cert.endDateTime -lt $ExpiryThreshold) {
                        # Determine certificate activity status
                        $activityStatus = Test-CertificateActive -Certificate $cert -ServicePrincipal $app
                        
                        # Calculate risk level
                        $daysUntilExpiry = [math]::Round(($cert.endDateTime - (Get-Date)).TotalDays, 1)
                        $riskLevel = Get-CredentialRiskLevel -DaysUntilExpiry $daysUntilExpiry
                        
                        $expiringCertificates += [PSCustomObject]@{
                            AppId = $app.appId
                            AppName = $app.displayName
                            AppType = "Enterprise Application (SAML)"
                            CredentialType = "SAML Certificate"
                            EndDateTime = $cert.endDateTime
                            DaysUntilExpiry = $daysUntilExpiry
                            RiskLevel = $riskLevel
                            KeyId = $cert.keyId
                            Thumbprint = $cert.customKeyIdentifier
                            DisplayName = $cert.displayName
                            ActivityStatus = $activityStatus
                            Usage = $cert.usage
                            CertificateType = $cert.type
                        }
                    }
                }
            }
        }
        
        Write-ProgressInfo -Activity "Scanning SAML Applications" -Status "Completed" -PercentComplete 100
        Write-Progress -Activity "Scanning SAML Applications" -Completed
        
        Write-Verbose "Found $($expiringCertificates.Count) expiring SAML certificates"
        return $expiringCertificates
    }
    catch {
        Write-Progress -Activity "Scanning SAML Applications" -Completed
        
        # Provide specific guidance for SAML-related errors
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match "403|Forbidden|permission") {
            Write-Error "Failed to retrieve SAML certificates: Insufficient permissions"
            Write-Host "💡 SAML certificate scanning requires ServicePrincipal.Read.All permission" -ForegroundColor Yellow
            Write-Host "💡 Try: Connect-MgGraph -Scopes 'Application.Read.All','ServicePrincipal.Read.All'" -ForegroundColor Yellow
        } else {
            Write-Error "Failed to retrieve SAML certificates: $errorMessage"
            Write-Host "💡 Troubleshooting tips:" -ForegroundColor Yellow
            Write-Host "   • Verify connection: Get-MgContext" -ForegroundColor White
            Write-Host "   • Check permissions: ServicePrincipal.Read.All required for SAML scanning" -ForegroundColor White
        }
        return @()
    }
}

<#
.SYNOPSIS
    Tests whether a SAML certificate appears to be actively used
.DESCRIPTION
    Analyzes SAML certificates to determine if they are likely active based on:
    - Certificate usage field (Sign vs Verify)
    - Certificate creation date patterns
    - Validity period patterns
    - Certificate key usage attributes
.PARAMETER Certificate
    The certificate object from keyCredentials
.PARAMETER ServicePrincipal
    The service principal object containing the certificate
.OUTPUTS
    String indicating certificate status: "Active", "Inactive", or "Unknown"
#>
function Test-CertificateActive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Certificate,
        
        [Parameter(Mandatory = $true)]
        [PSObject]$ServicePrincipal
    )
    
    Write-Verbose "Analyzing certificate activity for KeyId: $($Certificate.keyId)"
    
    try {
        $confidenceScore = 0
        $maxScore = 100
        
        # Rule 1: Certificate Usage Field Analysis (40 points)
        if ($Certificate.usage) {
            switch ($Certificate.usage.ToLower()) {
                'sign' { 
                    $confidenceScore += 30
                    Write-Verbose "  ✓ Certificate marked for signing (high activity indicator)"
                }
                'verify' { 
                    $confidenceScore += 20
                    Write-Verbose "  ✓ Certificate marked for verification (medium activity indicator)"
                }
                'encrypt' { 
                    $confidenceScore += 10
                    Write-Verbose "  ~ Certificate marked for encryption (low activity indicator)"
                }
                default { 
                    Write-Verbose "  ? Unknown usage type: $($Certificate.usage)"
                }
            }
        } else {
            Write-Verbose "  - No usage field specified"
        }
        
        # Rule 2: Certificate Age Analysis (30 points)
        if ($Certificate.startDateTime) {
            $certAge = (Get-Date) - [DateTime]$Certificate.startDateTime
            $daysOld = $certAge.TotalDays
            
            if ($daysOld -le 90) {
                $confidenceScore += 30
                Write-Verbose "  ✓ Recently created certificate ($([math]::Round($daysOld, 1)) days old) - likely active"
            }
            elseif ($daysOld -le 365) {
                $confidenceScore += 20
                Write-Verbose "  ✓ Moderately recent certificate ($([math]::Round($daysOld, 1)) days old)"
            }
            elseif ($daysOld -le 730) {
                $confidenceScore += 10
                Write-Verbose "  ~ Older certificate ($([math]::Round($daysOld, 1)) days old)"
            }
            else {
                $confidenceScore += 0
                Write-Verbose "  - Very old certificate ($([math]::Round($daysOld, 1)) days old) - likely inactive"
            }
        }
        
        # Rule 3: Certificate Validity Period (15 points)
        if ($Certificate.startDateTime -and $Certificate.endDateTime) {
            $validityPeriod = ([DateTime]$Certificate.endDateTime - [DateTime]$Certificate.startDateTime).TotalDays
            
            if ($validityPeriod -ge 365 -and $validityPeriod -le 1095) { # 1-3 years
                $confidenceScore += 15
                Write-Verbose "  ✓ Standard validity period ($([math]::Round($validityPeriod, 0)) days) - production pattern"
            }
            elseif ($validityPeriod -ge 90 -and $validityPeriod -le 364) { # 3 months - 1 year
                $confidenceScore += 8
                Write-Verbose "  ~ Shorter validity period ($([math]::Round($validityPeriod, 0)) days) - may be test/temporary"
            }
            else {
                Write-Verbose "  ? Unusual validity period ($([math]::Round($validityPeriod, 0)) days)"
            }
        }
        
        # Rule 4: Certificate Type Analysis (15 points)
        if ($Certificate.type) {
            if ($Certificate.type -eq "AsymmetricX509Cert") {
                $confidenceScore += 15
                Write-Verbose "  ✓ Standard X509 certificate type"
            }
            else {
                $confidenceScore += 5
                Write-Verbose "  ~ Non-standard certificate type: $($Certificate.type)"
            }
        }
        
        # Determine final status based on confidence score with improved thresholds
        $confidencePercentage = [math]::Round(($confidenceScore / $maxScore) * 100, 1)
        Write-Verbose "  📊 Activity confidence score: $confidenceScore/$maxScore ($confidencePercentage%)"
        
        if ($confidenceScore -ge 60) {
            return "Active"
        }
        elseif ($confidenceScore -ge 35) {
            return "Likely Active"
        }
        elseif ($confidenceScore -ge 20) {
            return "Possibly Inactive"
        }
        else {
            return "Likely Inactive"
        }
    }
    catch {
        Write-Verbose "  ❌ Error analyzing certificate activity: $($_.Exception.Message)"
        return "Unknown"
    }
}

<#
.SYNOPSIS
    Determines the risk level of a credential based on days until expiry
.DESCRIPTION
    Categorizes credentials into risk levels:
    - Expired: Already expired (negative days)
    - Critical: 0-7 days until expiry
    - Warning: 8-30 days until expiry  
    - Info: 31-90 days until expiry
    - Low: 91+ days until expiry
.PARAMETER DaysUntilExpiry
    Number of days until the credential expires (can be negative for expired)
.OUTPUTS
    String indicating risk level: "Expired", "Critical", "Warning", "Info", or "Low"
#>
function Get-CredentialRiskLevel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$DaysUntilExpiry
    )
    
    Write-Verbose "Calculating risk level for credential expiring in $DaysUntilExpiry days"
    
    try {
        if ($DaysUntilExpiry -lt 0) {
            Write-Verbose "  🔴 EXPIRED: Credential has already expired"
            return "Expired"
        }
        elseif ($DaysUntilExpiry -le 7) {
            Write-Verbose "  🔴 CRITICAL: Expires within 7 days"
            return "Critical"
        }
        elseif ($DaysUntilExpiry -le 30) {
            Write-Verbose "  🟡 WARNING: Expires within 30 days"
            return "Warning"
        }
        elseif ($DaysUntilExpiry -le 90) {
            Write-Verbose "  🔵 INFO: Expires within 90 days"
            return "Info"
        }
        else {
            Write-Verbose "  🟢 LOW: Expires in more than 90 days"
            return "Low"
        }
    }
    catch {
        Write-Verbose "  ❌ Error calculating risk level: $($_.Exception.Message)"
        return "Unknown"
    }
}

<#
.SYNOPSIS
    Formats and displays the credential report
#>
function Format-CredentialReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Credentials,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputFormat = 'Table',
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )
    
    if ($Credentials.Count -eq 0) {
        Write-Host "✅ No expiring credentials found within the specified threshold." -ForegroundColor Green
        return
    }
    
    Write-Host "`n📊 Found $($Credentials.Count) expiring credential(s):" -ForegroundColor Yellow
    
    # Show risk level summary
    Write-Host "`n🎯 Risk Level Summary:" -ForegroundColor Cyan
    $expiredCount = ($Credentials | Where-Object { $_.RiskLevel -eq "Expired" }).Count
    $criticalCount = ($Credentials | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $warningCount = ($Credentials | Where-Object { $_.RiskLevel -eq "Warning" }).Count
    $infoCount = ($Credentials | Where-Object { $_.RiskLevel -eq "Info" }).Count
    $lowCount = ($Credentials | Where-Object { $_.RiskLevel -eq "Low" }).Count
    
    if ($expiredCount -gt 0) { Write-Host "   • Expired: $expiredCount" -ForegroundColor Red }
    if ($criticalCount -gt 0) { Write-Host "   • Critical (0-7 days): $criticalCount" -ForegroundColor Red }
    if ($warningCount -gt 0) { Write-Host "   • Warning (8-30 days): $warningCount" -ForegroundColor Yellow }
    if ($infoCount -gt 0) { Write-Host "   • Info (31-90 days): $infoCount" -ForegroundColor Cyan }
    if ($lowCount -gt 0) { Write-Host "   • Low (90+ days): $lowCount" -ForegroundColor Green }
    
    # Show activity analysis summary for SAML certificates
    $samlCerts = $Credentials | Where-Object { $_.CredentialType -eq "SAML Certificate" }
    if ($samlCerts.Count -gt 0) {
        Write-Host "`n🔍 SAML Certificate Activity Analysis:" -ForegroundColor Cyan
        $activeCount = ($samlCerts | Where-Object { $_.ActivityStatus -eq "Active" }).Count
        $likelyActiveCount = ($samlCerts | Where-Object { $_.ActivityStatus -eq "Likely Active" }).Count
        $possiblyInactiveCount = ($samlCerts | Where-Object { $_.ActivityStatus -eq "Possibly Inactive" }).Count
        $likelyInactiveCount = ($samlCerts | Where-Object { $_.ActivityStatus -eq "Likely Inactive" }).Count
        $unknownCount = ($samlCerts | Where-Object { $_.ActivityStatus -eq "Unknown" }).Count
        
        Write-Host "   • Active: $activeCount" -ForegroundColor Green
        Write-Host "   • Likely Active: $likelyActiveCount" -ForegroundColor Yellow
        Write-Host "   • Possibly Inactive: $possiblyInactiveCount" -ForegroundColor Orange
        Write-Host "   • Likely Inactive: $likelyInactiveCount" -ForegroundColor Red
        if ($unknownCount -gt 0) {
            Write-Host "   • Unknown: $unknownCount" -ForegroundColor Gray
        }
    }
    
    switch ($OutputFormat) {
        'Table' {
            # Display with enhanced formatting for activity status and risk level
            $sortedCredentials = $Credentials | Sort-Object EndDateTime
            $sortedCredentials | Format-Table -Property AppName, CredentialType, EndDateTime, DaysUntilExpiry, RiskLevel, ActivityStatus, Usage -AutoSize
        }
        'CSV' {
            Write-Host "`n📁 Exporting to CSV format..." -ForegroundColor Cyan
            $exportedFile = Export-CredentialReport -Credentials $Credentials -OutputFormat 'CSV' -OutputPath $OutputPath
            if ($exportedFile) {
                Write-Host "✅ CSV report exported successfully: $exportedFile" -ForegroundColor Green
            }
        }
        'JSON' {
            Write-Host "`n📁 Exporting to JSON format..." -ForegroundColor Cyan
            $exportedFile = Export-CredentialReport -Credentials $Credentials -OutputFormat 'JSON' -OutputPath $OutputPath
            if ($exportedFile) {
                Write-Host "✅ JSON report exported successfully: $exportedFile" -ForegroundColor Green
            }
        }
        'HTML' {
            Write-Host "`n📁 Exporting to HTML format..." -ForegroundColor Cyan
            $exportedFile = Export-CredentialReport -Credentials $Credentials -OutputFormat 'HTML' -OutputPath $OutputPath
            if ($exportedFile) {
                Write-Host "✅ HTML report exported successfully: $exportedFile" -ForegroundColor Green
                Write-Host "💡 Open in browser to view styled report" -ForegroundColor Yellow
            }
        }
        default {
            $sortedCredentials = $Credentials | Sort-Object EndDateTime
            $sortedCredentials | Format-Table -Property AppName, CredentialType, EndDateTime, DaysUntilExpiry, RiskLevel, ActivityStatus, Usage -AutoSize
        }
    }
}

<#
.SYNOPSIS
    Exports credential data to various formats (CSV, JSON, HTML)
.DESCRIPTION
    Handles exporting credential data to different file formats while maintaining
    data integrity and professional formatting. Supports CSV, JSON, and HTML with
    appropriate styling and structure for each format.
.PARAMETER Credentials
    Array of credential objects to export
.PARAMETER OutputFormat
    Export format: CSV, JSON, or HTML
.PARAMETER OutputPath
    File path where the exported data should be saved
.OUTPUTS
    String path to the created export file
#>
function Export-CredentialReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Credentials,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('CSV', 'JSON', 'HTML')]
        [string]$OutputFormat,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    Write-Verbose "Exporting $($Credentials.Count) credentials to $OutputFormat format"
    
    try {
        # Ensure output directory exists
        $outputDir = Split-Path $OutputPath -Parent
        if ($outputDir -and !(Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            Write-Verbose "Created output directory: $outputDir"
        }
        
        switch ($OutputFormat) {
            'CSV' {
                Write-Verbose "Generating CSV export..."
                
                # Select and order columns for CSV export
                $csvData = $Credentials | Select-Object -Property `
                    AppName, AppId, AppType, CredentialType, EndDateTime, DaysUntilExpiry, `
                    RiskLevel, ActivityStatus, Usage, CertificateType, KeyId, Thumbprint, DisplayName
                
                # Export to CSV with proper formatting
                $csvData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                Write-Verbose "CSV export completed: $OutputPath"
            }
            
            'JSON' {
                Write-Verbose "Generating JSON export..."
                
                # Create structured JSON with metadata
                $jsonData = @{
                    ExportMetadata = @{
                        ExportDate = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                        ExportFormat = 'JSON'
                        TotalCredentials = $Credentials.Count
                        RiskLevelSummary = @{}
                    }
                    Credentials = $Credentials
                }
                
                # Add risk level summary to metadata
                $riskGroups = $Credentials | Group-Object RiskLevel
                foreach ($group in $riskGroups) {
                    $jsonData.ExportMetadata.RiskLevelSummary[$group.Name] = $group.Count
                }
                
                # Export to JSON with proper formatting
                $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
                Write-Verbose "JSON export completed: $OutputPath"
            }
            
            'HTML' {
                Write-Verbose "Generating HTML export..."
                
                # Create HTML with professional styling
                $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Entra ID Credential Expiry Report</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5; 
        }
        .header { 
            background: linear-gradient(135deg, #0078d4, #00bcf2); 
            color: white; 
            padding: 20px; 
            border-radius: 8px; 
            margin-bottom: 20px; 
        }
        .summary { 
            background: white; 
            padding: 15px; 
            border-radius: 8px; 
            margin-bottom: 20px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            background: white; 
            border-radius: 8px; 
            overflow: hidden; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        th { 
            background: #0078d4; 
            color: white; 
            padding: 12px; 
            text-align: left; 
            font-weight: 600; 
        }
        td { 
            padding: 10px 12px; 
            border-bottom: 1px solid #e1e1e1; 
        }
        tr:nth-child(even) { 
            background-color: #f8f9fa; 
        }
        .risk-expired { background-color: #ffeaea !important; color: #d13438; font-weight: bold; }
        .risk-critical { background-color: #ffeaea !important; color: #d13438; font-weight: bold; }
        .risk-warning { background-color: #fff8e1 !important; color: #f57c00; font-weight: bold; }
        .risk-info { background-color: #e3f2fd !important; color: #1976d2; }
        .risk-low { background-color: #e8f5e8 !important; color: #388e3c; }
        .activity-active { color: #388e3c; font-weight: bold; }
        .activity-inactive { color: #f57c00; }
        .footer { 
            text-align: center; 
            color: #666; 
            margin-top: 20px; 
            font-size: 12px; 
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Entra ID Credential Expiry Report</h1>
        <p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Total Expiring Credentials:</strong> $($Credentials.Count)</p>
"@
                
                # Add risk level summary
                $riskGroups = $Credentials | Group-Object RiskLevel | Sort-Object Name
                if ($riskGroups) {
                    $htmlContent += "<p><strong>Risk Level Distribution:</strong></p><ul>"
                    foreach ($group in $riskGroups) {
                        $riskClass = "risk-$($group.Name.ToLower())"
                        $htmlContent += "<li class='$riskClass'>$($group.Name): $($group.Count)</li>"
                    }
                    $htmlContent += "</ul>"
                }
                
                # Add credentials table
                $htmlContent += @"
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Application Name</th>
                <th>Type</th>
                <th>Credential Type</th>
                <th>Expiry Date</th>
                <th>Days Until Expiry</th>
                <th>Risk Level</th>
                <th>Activity Status</th>
                <th>Usage</th>
            </tr>
        </thead>
        <tbody>
"@
                
                # Add credential rows
                foreach ($cred in ($Credentials | Sort-Object EndDateTime)) {
                    $riskClass = "risk-$($cred.RiskLevel.ToLower())"
                    $activityClass = if ($cred.ActivityStatus -match "Active") { "activity-active" } 
                                   elseif ($cred.ActivityStatus -match "Inactive") { "activity-inactive" } 
                                   else { "" }
                    
                    $htmlContent += @"
            <tr>
                <td>$($cred.AppName)</td>
                <td>$($cred.AppType)</td>
                <td>$($cred.CredentialType)</td>
                <td>$($cred.EndDateTime)</td>
                <td>$($cred.DaysUntilExpiry)</td>
                <td class="$riskClass">$($cred.RiskLevel)</td>
                <td class="$activityClass">$($cred.ActivityStatus)</td>
                <td>$($cred.Usage)</td>
            </tr>
"@
                }
                
                $htmlContent += @"
        </tbody>
    </table>
    
    <div class="footer">
        <p>Generated by Entra ID Credential Management Script v2.0</p>
    </div>
</body>
</html>
"@
                
                # Save HTML file
                $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
                Write-Verbose "HTML export completed: $OutputPath"
            }
        }
        
        return $OutputPath
    }
    catch {
        Write-Error "Failed to export credentials to $OutputFormat format: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Invokes Microsoft Graph API with retry logic and exponential backoff
.DESCRIPTION
    Wraps Invoke-MgGraphRequest with retry logic to handle transient failures,
    rate limiting, and network issues. Uses exponential backoff strategy.
.PARAMETER Uri
    The Graph API URI to call
.PARAMETER Method
    HTTP method (GET, POST, etc.)
.PARAMETER MaxRetries
    Maximum number of retry attempts (default: 3)
.PARAMETER BaseDelaySeconds
    Base delay in seconds for exponential backoff (default: 1)
.OUTPUTS
    Graph API response object
#>
function Invoke-GraphRequestWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $false)]
        [string]$Method = 'GET',
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory = $false)]
        [double]$BaseDelaySeconds = 1.0
    )
    
    $attempt = 1
    $lastException = $null
    
    while ($attempt -le ($MaxRetries + 1)) {
        try {
            Write-Verbose "Graph API call attempt $attempt/$($MaxRetries + 1): $Uri"
            
            $result = Invoke-MgGraphRequest -Uri $Uri -Method $Method -OutputType PSObject
            
            if ($attempt -gt 1) {
                Write-Verbose "✅ Graph API call succeeded on attempt $attempt"
            }
            
            return $result
        }
        catch {
            $lastException = $_
            $errorMessage = $_.Exception.Message
            
            # Check if this is a retryable error
            $isRetryable = $false
            
            # HTTP 429 (Too Many Requests) - Rate limiting
            if ($errorMessage -match "429|Too Many Requests|throttled") {
                $isRetryable = $true
                Write-Verbose "⏳ Rate limiting detected on attempt $attempt"
            }
            # HTTP 5xx (Server errors)
            elseif ($errorMessage -match "50[0-9]|Service Unavailable|Internal Server Error") {
                $isRetryable = $true
                Write-Verbose "🔄 Server error detected on attempt $attempt"
            }
            # Network/timeout errors
            elseif ($errorMessage -match "timeout|network|connection") {
                $isRetryable = $true
                Write-Verbose "🌐 Network error detected on attempt $attempt"
            }
            # Authentication errors (not retryable)
            elseif ($errorMessage -match "401|Unauthorized|authentication|token") {
                Write-Verbose "❌ Authentication error - not retryable: $errorMessage"
                throw $_
            }
            # Permission errors (not retryable)
            elseif ($errorMessage -match "403|Forbidden|permission|access.*denied") {
                Write-Verbose "❌ Permission error - not retryable: $errorMessage"
                throw $_
            }
            
            if ($isRetryable -and $attempt -le $MaxRetries) {
                # Calculate exponential backoff delay
                $delay = $BaseDelaySeconds * [Math]::Pow(2, ($attempt - 1))
                Write-Verbose "⏱️  Retrying in $delay seconds (attempt $attempt/$MaxRetries)..."
                Start-Sleep -Seconds $delay
            }
            elseif ($attempt -gt $MaxRetries) {
                Write-Verbose "❌ Max retries ($MaxRetries) exceeded for: $Uri"
                throw $lastException
            }
            else {
                # Not retryable, throw immediately
                throw $_
            }
        }
        
        $attempt++
    }
    
    # Should never reach here, but just in case
    throw $lastException
}

<#
.SYNOPSIS
    Validates Microsoft Graph connection and required permissions
.DESCRIPTION
    Checks if user is connected to Microsoft Graph and has the required permissions
    for the credential scanning operations. Provides helpful guidance for common issues.
.PARAMETER RequiredScopes
    Array of required permission scopes
.OUTPUTS
    Boolean indicating if validation passed
#>
function Test-GraphPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$RequiredScopes = @('Application.Read.All', 'ServicePrincipal.Read.All')
    )
    
    Write-Verbose "Validating Microsoft Graph connection and permissions..."
    
    try {
        # Check if connected to Microsoft Graph
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            Write-Host "❌ Not connected to Microsoft Graph" -ForegroundColor Red
            Write-Host "💡 Please connect using: Connect-MgGraph -Scopes '$($RequiredScopes -join "','")'" -ForegroundColor Yellow
            return $false
        }
        
        Write-Verbose "✅ Connected to Microsoft Graph"
        Write-Verbose "   Account: $($context.Account)"
        Write-Verbose "   Tenant: $($context.TenantId)"
        
        # Test basic Graph API access with a simple call
        try {
            Write-Verbose "Testing basic Graph API access..."
            $testResult = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/me" -Method GET
            Write-Verbose "✅ Basic Graph API access confirmed"
        }
        catch {
            $errorMessage = $_.Exception.Message
            
            if ($errorMessage -match "403|Forbidden|permission") {
                Write-Host "❌ Insufficient permissions detected" -ForegroundColor Red
                Write-Host "💡 Required permissions: $($RequiredScopes -join ', ')" -ForegroundColor Yellow
                Write-Host "💡 Reconnect with: Connect-MgGraph -Scopes '$($RequiredScopes -join "','")'" -ForegroundColor Yellow
                return $false
            }
            elseif ($errorMessage -match "401|Unauthorized|authentication|token") {
                Write-Host "❌ Authentication failed - token may be expired" -ForegroundColor Red
                Write-Host "💡 Please reconnect: Connect-MgGraph -Scopes '$($RequiredScopes -join "','")'" -ForegroundColor Yellow
                return $false
            }
            else {
                Write-Verbose "⚠️ Unexpected error during permission test: $errorMessage"
                # Continue anyway - might be a different issue
            }
        }
        
        # Test Application.Read.All permission
        try {
            Write-Verbose "Testing Application.Read.All permission..."
            $appTest = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/applications?`$top=1" -Method GET
            Write-Verbose "✅ Application.Read.All permission confirmed"
        }
        catch {
            if ($_.Exception.Message -match "403|Forbidden|permission") {
                Write-Host "❌ Missing Application.Read.All permission" -ForegroundColor Red
                Write-Host "💡 This permission is required to read App Registration credentials" -ForegroundColor Yellow
                Write-Host "💡 Reconnect with: Connect-MgGraph -Scopes '$($RequiredScopes -join "','")'" -ForegroundColor Yellow
                return $false
            }
            # Continue if other error - might still work
        }
        
        # Test ServicePrincipal.Read.All permission (for SAML)
        try {
            Write-Verbose "Testing ServicePrincipal.Read.All permission..."
            $spTest = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$top=1" -Method GET
            Write-Verbose "✅ ServicePrincipal.Read.All permission confirmed"
        }
        catch {
            if ($_.Exception.Message -match "403|Forbidden|permission") {
                Write-Host "⚠️ Missing ServicePrincipal.Read.All permission" -ForegroundColor Yellow
                Write-Host "💡 This permission is required for SAML certificate scanning (-IncludeSAML)" -ForegroundColor Yellow
                Write-Host "💡 App Registration scanning will still work" -ForegroundColor Green
                # Don't return false - just warn
            }
        }
        
        Write-Verbose "✅ Permission validation completed successfully"
        return $true
    }
    catch {
        Write-Host "❌ Unexpected error during permission validation: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "💡 Try reconnecting: Connect-MgGraph -Scopes '$($RequiredScopes -join "','")'" -ForegroundColor Yellow
        return $false
    }
}

<#
.SYNOPSIS
    Displays progress information for long-running operations
.DESCRIPTION
    Provides user feedback during credential processing operations,
    especially useful for large tenants with many applications.
.PARAMETER Activity
    Description of the current activity
.PARAMETER Status
    Current status message
.PARAMETER PercentComplete
    Percentage complete (0-100)
.PARAMETER CurrentOperation
    Current operation being performed
#>
function Write-ProgressInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Activity,
        
        [Parameter(Mandatory = $false)]
        [string]$Status = "",
        
        [Parameter(Mandatory = $false)]
        [int]$PercentComplete = -1,
        
        [Parameter(Mandatory = $false)]
        [string]$CurrentOperation = ""
    )
    
    # Use Write-Progress for PowerShell progress bar
    if ($PercentComplete -ge 0) {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete -CurrentOperation $CurrentOperation
    } else {
        Write-Progress -Activity $Activity -Status $Status -CurrentOperation $CurrentOperation
    }
    
    # Also provide verbose output
    if ($CurrentOperation) {
        Write-Verbose "$Activity - $Status - $CurrentOperation"
    } else {
        Write-Verbose "$Activity - $Status"
    }
}
#endregion

#region Main Script Logic

try {
    # Validate Microsoft Graph connection and permissions first
    Write-Host "🔐 Validating Microsoft Graph connection and permissions..." -ForegroundColor Cyan
    if (-not (Test-GraphPermissions)) {
        Write-Host "`n❌ Permission validation failed. Cannot proceed." -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Microsoft Graph validation completed successfully" -ForegroundColor Green
    
    # Initialize
    $today = Get-Date
    $expiryThreshold = $today.AddDays($DaysThreshold)
    $allExpiringCredentials = @()
    
    # Auto-generate output path if not provided for export formats
    if ($OutputFormat -ne 'Table' -and -not $OutputPath) {
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $extension = switch ($OutputFormat) {
            'CSV' { 'csv' }
            'JSON' { 'json' }
            'HTML' { 'html' }
            default { 'txt' }
        }
        $OutputPath = "EntraCredentialReport_$timestamp.$extension"
        Write-Host "📁 No output path specified. Using: $OutputPath" -ForegroundColor Yellow
    }
    
    Write-Host "`n🔍 Entra ID Credential Expiry Scanner" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "📅 Checking for credentials expiring within $DaysThreshold days (before $($expiryThreshold.ToString('yyyy-MM-dd')))" -ForegroundColor White
    
    # Process App Registration credentials
    Write-Host "`n📱 Scanning App Registrations..." -ForegroundColor Blue
    $appCredentials = Get-AppRegistrationCredentials -ExpiryThreshold $expiryThreshold
    $allExpiringCredentials += $appCredentials
    
    # Process SAML certificates (if requested)
    if ($IncludeSAML) {
        Write-Host "`n🔐 Scanning SAML SSO Certificates..." -ForegroundColor Blue
        $samlCredentials = Get-SAMLCertificates -ExpiryThreshold $expiryThreshold
        $allExpiringCredentials += $samlCredentials
    } else {
        Write-Verbose "SAML certificate scanning skipped (use -IncludeSAML to include)"
    }
    
    # Display results
    Format-CredentialReport -Credentials $allExpiringCredentials -OutputFormat $OutputFormat -OutputPath $OutputPath
    
    # Summary
    Write-Host "`n📋 Summary:" -ForegroundColor Cyan
    Write-Host "   • App Registration credentials: $($appCredentials.Count)" -ForegroundColor White
    if ($IncludeSAML) {
        $samlCertCount = ($allExpiringCredentials | Where-Object {$_.AppType -eq 'Enterprise Application (SAML)'}).Count
        Write-Host "   • SAML SSO certificates: $samlCertCount" -ForegroundColor White
        
        # Add activity analysis summary
        if ($samlCertCount -gt 0) {
            $activeSamlCerts = ($allExpiringCredentials | Where-Object {$_.AppType -eq 'Enterprise Application (SAML)' -and $_.ActivityStatus -in @('Active', 'Likely Active')}).Count
            $inactiveSamlCerts = ($allExpiringCredentials | Where-Object {$_.AppType -eq 'Enterprise Application (SAML)' -and $_.ActivityStatus -in @('Possibly Inactive', 'Likely Inactive')}).Count
            Write-Host "     ├─ Active/Likely Active: $activeSamlCerts" -ForegroundColor Green
            Write-Host "     └─ Possibly/Likely Inactive: $inactiveSamlCerts" -ForegroundColor Yellow
        }
    }
    Write-Host "   • Total expiring credentials: $($allExpiringCredentials.Count)" -ForegroundColor White
    
    # Add risk level breakdown to summary
    if ($allExpiringCredentials.Count -gt 0) {
        $riskSummary = $allExpiringCredentials | Group-Object RiskLevel | Sort-Object Name
        Write-Host "   • Risk Level Breakdown:" -ForegroundColor White
        foreach ($riskGroup in $riskSummary) {
            $color = switch ($riskGroup.Name) {
                "Expired" { "Red" }
                "Critical" { "Red" }
                "Warning" { "Yellow" }
                "Info" { "Cyan" }
                "Low" { "Green" }
                default { "White" }
            }
            Write-Host "     ├─ $($riskGroup.Name): $($riskGroup.Count)" -ForegroundColor $color
        }
    }
    
    Write-Host "   • Days threshold: $DaysThreshold days" -ForegroundColor White
}
catch {
    # Clean up any active progress indicators
    Write-Progress -Activity "Scanning" -Completed
    
    $errorMessage = $_.Exception.Message
    Write-Host "`n❌ Script execution failed: $errorMessage" -ForegroundColor Red
    
    # Provide specific troubleshooting guidance based on error type
    if ($errorMessage -match "401|Unauthorized|authentication|token") {
        Write-Host "`n🔑 Authentication Issue Detected:" -ForegroundColor Yellow
        Write-Host "   • Your authentication token may have expired" -ForegroundColor White
        Write-Host "   • Solution: Reconnect to Microsoft Graph" -ForegroundColor White
        Write-Host "   • Command: Connect-MgGraph -Scopes 'Application.Read.All','ServicePrincipal.Read.All'" -ForegroundColor Cyan
    }
    elseif ($errorMessage -match "403|Forbidden|permission") {
        Write-Host "`n🚫 Permission Issue Detected:" -ForegroundColor Yellow
        Write-Host "   • Your account lacks required permissions" -ForegroundColor White
        Write-Host "   • Required: Application.Read.All, ServicePrincipal.Read.All" -ForegroundColor White
        Write-Host "   • Solution: Reconnect with proper scopes" -ForegroundColor White
        Write-Host "   • Command: Connect-MgGraph -Scopes 'Application.Read.All','ServicePrincipal.Read.All'" -ForegroundColor Cyan
    }
    elseif ($errorMessage -match "429|Too Many Requests|throttled") {
        Write-Host "`n⏳ Rate Limiting Issue Detected:" -ForegroundColor Yellow
        Write-Host "   • Microsoft Graph is throttling requests" -ForegroundColor White
        Write-Host "   • Solution: Wait a few minutes and try again" -ForegroundColor White
        Write-Host "   • The script includes retry logic, but severe throttling may still cause issues" -ForegroundColor White
    }
    elseif ($errorMessage -match "50[0-9]|Service Unavailable|Internal Server Error") {
        Write-Host "`n🔧 Microsoft Graph Service Issue Detected:" -ForegroundColor Yellow
        Write-Host "   • Microsoft Graph service is experiencing issues" -ForegroundColor White
        Write-Host "   • Solution: Try again in a few minutes" -ForegroundColor White
        Write-Host "   • Check Microsoft Graph service status if issues persist" -ForegroundColor White
    }
    elseif ($errorMessage -match "network|connection|timeout") {
        Write-Host "`n🌐 Network Issue Detected:" -ForegroundColor Yellow
        Write-Host "   • Network connectivity problem" -ForegroundColor White
        Write-Host "   • Solution: Check your internet connection and try again" -ForegroundColor White
        Write-Host "   • Verify access to graph.microsoft.com" -ForegroundColor White
    }
    else {
        Write-Host "`n💡 General Troubleshooting Tips:" -ForegroundColor Yellow
        Write-Host "   • Verify connection: Get-MgContext" -ForegroundColor White
        Write-Host "   • Check permissions: Application.Read.All, ServicePrincipal.Read.All" -ForegroundColor White
        Write-Host "   • Reconnect if needed: Connect-MgGraph -Scopes 'Application.Read.All','ServicePrincipal.Read.All'" -ForegroundColor White
        Write-Host "   • Try running with -Verbose for more details" -ForegroundColor White
    }
    
    Write-Host "`n🔍 Additional Diagnostic Commands:" -ForegroundColor Cyan
    Write-Host "   • Check current context: Get-MgContext" -ForegroundColor White
    Write-Host "   • Test basic access: Get-MgApplication -Top 1" -ForegroundColor White
    Write-Host "   • Get help: Get-Help .\Get-ExpiringEntraCredentials.ps1 -Full" -ForegroundColor White
    
    exit 1
}

#endregion
