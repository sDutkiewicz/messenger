# PowerShell script to generate self-signed SSL certificates
# Usage: .\generate-certs.ps1

# Check if OpenSSL is available
$opensslPath = Get-Command openssl -ErrorAction SilentlyContinue

if (-not $opensslPath) {
    Write-Host "ERROR: OpenSSL is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Install from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
    exit 1
}

Write-Host "`nOpenSSL found: $($opensslPath.Source)" -ForegroundColor Green

# Create certs directory if it doesn't exist
$certsDir = ".\certs"
if (-not (Test-Path $certsDir)) {
    New-Item -ItemType Directory -Path $certsDir | Out-Null
    Write-Host "Created directory: $certsDir" -ForegroundColor Green
}

# Change to certs directory
Push-Location $certsDir

try {
    Write-Host "`nGenerating self-signed certificate..." -ForegroundColor Yellow
    Write-Host "This certificate is valid for 365 days" -ForegroundColor Gray
    
    # Generate self-signed certificate
    & openssl req -x509 `
        -newkey rsa:4096 `
        -nodes `
        -out cert.pem `
        -keyout key.pem `
        -days 365 `
        -subj "/C=PL/ST=Masovia/L=Warsaw/O=Messenger/CN=localhost"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nCertificate generated successfully!" -ForegroundColor Green
        Write-Host "  Certificate: cert.pem" -ForegroundColor Green
        Write-Host "  Private key: key.pem" -ForegroundColor Green
        
        # Display certificate info
        Write-Host "`nCertificate Details:" -ForegroundColor Cyan
        Write-Host "=====================" -ForegroundColor Cyan
        & openssl x509 -in cert.pem -text -noout | Select-String -Pattern "Subject:|Issuer:|Not Before|Not After|Public-Key"
    } else {
        Write-Host "`n✗ Error generating certificate" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Host "`n✗ Error: $_" -ForegroundColor Red
    exit 1
}
finally {
    Pop-Location
}
