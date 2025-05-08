#Requires -Modules @{ ModuleName="Microsoft.Graph.Applications"; ModuleVersion="2.25.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="2.25.0" }

<#
.SYNOPSIS
    Adds a certificate or client secret to an existing app registration.
.DESCRIPTION
    This script adds a credential to an existing app registration. The credential can be either:
    - A client secret (password)
    - A self-signed certificate
    
    For certificate generation, this script uses openssl and is compatible with macOS.
.PARAMETER AppName
    Display name of the existing app registration
.PARAMETER CredentialType
    Type of credential to add: "Secret" or "Certificate"
.PARAMETER DisplayName
    Display name for the credential
.PARAMETER ValidityYears
    Number of years the credential should be valid for (default: 1)
.PARAMETER OutputPath
    Path where the credential files will be saved (default: "./Credentials")
.EXAMPLE
    # Add a client secret
    .\Add-AppCredential.ps1 -AppName "MyApp" -CredentialType Secret -DisplayName "MySecret"
.EXAMPLE
    # Add a certificate
    .\Add-AppCredential.ps1 -AppName "MyApp" -CredentialType Certificate -DisplayName "MyCert" -ValidityYears 2
.NOTES
    Author: Josh
    Date: May 8, 2025
    Requires: macOS, openssl for certificate generation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppName,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Secret", "Certificate")]
    [string]$CredentialType,
    
    [Parameter(Mandatory = $false)]
    [string]$DisplayName = "AppCredential",
    
    [Parameter(Mandatory = $false)]
    [int]$ValidityYears = 1,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./Credentials"
)

# Check for macOS if adding a certificate - we use openssl for certificate generation
if ($CredentialType -eq "Certificate" -and -not $IsMacOS) {
    Write-Warning "Certificate generation is optimized for macOS. Some commands may not work correctly on other platforms."
}

# Create output directory if it doesn't exist
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory | Out-Null
    Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
}

# Function to add a client secret to an app
function Add-ClientSecret {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        
        [Parameter(Mandatory = $true)]
        [string]$SecretDisplayName,
        
        [Parameter(Mandatory = $true)]
        [int]$ValidityYears
    )
    
    try {
        # Get the application
        $app = Get-MgApplication -Filter "displayName eq '$AppName'"
        
        if (-not $app) {
            Write-Error "Application '$AppName' not found."
            return $null
        }
        
        # Add the secret
        $endDateTime = (Get-Date).AddYears($ValidityYears)
        $passwordCredential = @{
            displayName = $SecretDisplayName
            endDateTime = $endDateTime
        }
        
        # Create the password credential
        $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential $passwordCredential
        
        Write-Host "Added client secret to app '$AppName'. Secret expires on $($secret.EndDateTime)" -ForegroundColor Green
        
        # Return the secret details
        return @{
            AppId = $app.AppId
            AppName = $AppName
            ClientSecret = $secret.SecretText
            SecretId = $secret.KeyId
            ExpiryDate = $secret.EndDateTime
        }
    }
    catch {
        Write-Error "Failed to add client secret to app '$AppName'. Error: $_"
        return $null
    }
}

# Function to add a self-signed certificate to an app
function Add-Certificate {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        
        [Parameter(Mandatory = $true)]
        [string]$CertDisplayName,
        
        [Parameter(Mandatory = $true)]
        [string]$CertPath,
        
        [Parameter(Mandatory = $true)]
        [int]$ValidityYears
    )
    
    try {
        # Get the application
        $app = Get-MgApplication -Filter "displayName eq '$AppName'"
        
        if (-not $app) {
            Write-Error "Application '$AppName' not found."
            return $null
        }
        
        # Create paths for certificate files
        $certName = $AppName.Replace(" ", "_")
        $privateKeyPath = Join-Path -Path $CertPath -ChildPath "$certName-private.key"
        $certFilePath = Join-Path -Path $CertPath -ChildPath "$certName.crt"
        $pfxFilePath = Join-Path -Path $CertPath -ChildPath "$certName.pfx"
        $publicKeyPath = Join-Path -Path $CertPath -ChildPath "$certName-public.pem"
        
        # Generate a secure password for PFX
        $pfxPassword = [System.Guid]::NewGuid().ToString()
        $pfxPasswordFile = Join-Path -Path $CertPath -ChildPath "$certName-password.txt"
        
        # Save the PFX password to a file
        $pfxPassword | Out-File -FilePath $pfxPasswordFile -Force
        
        Write-Host "Generating self-signed certificate for '$AppName'..." -ForegroundColor Cyan
        
        # Generate private key
        & openssl genrsa -out $privateKeyPath 2048 2>&1 | Out-Null
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to generate private key for '$AppName'."
            return $null
        }
        
        # Calculate certificate validity period
        $validFrom = (Get-Date).ToString("MMM dd HH:mm:ss yyyy")
        $validTo = (Get-Date).AddYears($ValidityYears).ToString("MMM dd HH:mm:ss yyyy")
        
        # Generate certificate signing request (CSR) configuration
        $csrConf = @"
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $AppName

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
"@
        
        $csrConfPath = Join-Path -Path $CertPath -ChildPath "$certName-csr.conf"
        $csrConf | Out-File -FilePath $csrConfPath -Force
        
        # Generate self-signed certificate
        & openssl req -new -x509 -key $privateKeyPath -out $certFilePath -days (365 * $ValidityYears) -config $csrConfPath 2>&1 | Out-Null
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to generate certificate for '$AppName'."
            return $null
        }
        
        # Export public key
        & openssl x509 -in $certFilePath -pubkey -noout > $publicKeyPath 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to export public key for '$AppName'."
            return $null
        }
        
        # Create PFX
        & openssl pkcs12 -export -out $pfxFilePath -inkey $privateKeyPath -in $certFilePath -password "pass:$pfxPassword" 2>&1 | Out-Null
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to create PFX for '$AppName'."
            return $null
        }
        
        # Calculate certificate thumbprint
        $thumbprint = & openssl x509 -in $certFilePath -fingerprint -noout
        $thumbprint = $thumbprint -replace "SHA1 Fingerprint=", ""
        $thumbprint = $thumbprint -replace ":", ""
        
        # Read the certificate file
        $certBytes = [System.IO.File]::ReadAllBytes($certFilePath)
        
        # Create the key credential
        $keyCredential = @{
            Type = "AsymmetricX509Cert"
            Usage = "Verify"
            Key = $certBytes
            DisplayName = $CertDisplayName
        }
        
        # Update the application with the key credential
        Update-MgApplication -ApplicationId $app.Id -KeyCredential $keyCredential
        
        Write-Host "Added self-signed certificate to app '$AppName'." -ForegroundColor Green
        Write-Host "Certificate files saved in $CertPath directory." -ForegroundColor Green
        Write-Host "Certificate thumbprint: $thumbprint" -ForegroundColor Green
        
        # Return the certificate details
        return @{
            AppId = $app.AppId
            AppName = $AppName
            CertificatePath = $certFilePath
            PfxPath = $pfxFilePath
            PfxPasswordFile = $pfxPasswordFile
            Thumbprint = $thumbprint
        }
    }
    catch {
        Write-Error "Failed to add certificate to app '$AppName'. Error: $_"
        return $null
    }
}

# Main script execution
try {
    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "Application.ReadWrite.All"
    Write-Host "Connected to Microsoft Graph successfully." -ForegroundColor Green
    
    # Verify app exists
    $app = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue
    
    if (-not $app) {
        Write-Error "App registration '$AppName' not found. Please ensure the app exists before adding credentials."
        return
    }
    
    Write-Host "Found app registration '$AppName' with ID: $($app.Id)" -ForegroundColor Green
    
    # Add the specified credential type
    switch ($CredentialType) {
        "Secret" {
            Write-Host "Adding client secret to app '$AppName'..." -ForegroundColor Cyan
            $result = Add-ClientSecret -AppName $AppName -SecretDisplayName $DisplayName -ValidityYears $ValidityYears
            
            if ($result) {
                # Save secret details to CSV file
                $secretOutputPath = Join-Path -Path $OutputPath -ChildPath "$($AppName.Replace(' ', '_'))-secret.csv"
                $result | Export-Csv -Path $secretOutputPath -NoTypeInformation
                Write-Host "Secret details exported to $secretOutputPath" -ForegroundColor Green
                
                Write-Host "`nClient Secret Summary:" -ForegroundColor Cyan
                Write-Host "App Name: $($result.AppName)" -ForegroundColor Green
                Write-Host "App ID (Client ID): $($result.AppId)" -ForegroundColor Green
                Write-Host "Secret ID: $($result.SecretId)" -ForegroundColor Green
                Write-Host "Secret Value: $($result.ClientSecret)" -ForegroundColor Yellow
                Write-Host "Expiry Date: $($result.ExpiryDate)" -ForegroundColor Green
            }
        }
        
        "Certificate" {
            Write-Host "Adding certificate to app '$AppName'..." -ForegroundColor Cyan
            $result = Add-Certificate -AppName $AppName -CertDisplayName $DisplayName -CertPath $OutputPath -ValidityYears $ValidityYears
            
            if ($result) {
                # Save certificate details to CSV file
                $certInfoPath = Join-Path -Path $OutputPath -ChildPath "$($AppName.Replace(' ', '_'))-cert-info.csv"
                $result | Export-Csv -Path $certInfoPath -NoTypeInformation
                
                Write-Host "`nCertificate Summary:" -ForegroundColor Cyan
                Write-Host "App Name: $($result.AppName)" -ForegroundColor Green
                Write-Host "App ID (Client ID): $($result.AppId)" -ForegroundColor Green
                Write-Host "Certificate Path: $($result.CertificatePath)" -ForegroundColor Green
                Write-Host "PFX Path: $($result.PfxPath)" -ForegroundColor Green
                Write-Host "PFX Password File: $($result.PfxPasswordFile)" -ForegroundColor Green
                Write-Host "Thumbprint: $($result.Thumbprint)" -ForegroundColor Yellow
            }
        }
    }
    
    Write-Host "`nCredential added successfully to app '$AppName'." -ForegroundColor Green
    Write-Host "`nReminder: These credentials need to be securely stored." -ForegroundColor Yellow
    Write-Host "Client secrets and certificate passwords are highly sensitive!" -ForegroundColor Yellow
}
catch {
    Write-Error "An error occurred: $_"
}
finally {
    # Disconnect from Microsoft Graph
    Disconnect-MgGraph | Out-Null
    Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan
}