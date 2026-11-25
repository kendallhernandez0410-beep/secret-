# Script de Generación de Certificados TLS Autofirmados para Laboratorio Local
param(
    [string]$OutputDir = "$PSScriptRoot\..\docker\certs"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host "Generando certificado autofirmado para SecureVault (localhost)..." -ForegroundColor Cyan

# Generar certificado para localhost
$cert = New-SelfSignedCertificate -DnsName "localhost", "127.0.0.1" -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(1) -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256

$certPath = "$OutputDir\vault.crt"
$keyPath = "$OutputDir\vault.key"
$pfxPath = "$OutputDir\vault.pfx"
$password = ConvertTo-SecureString -String "securevault" -Force -AsPlainText

# Exportar PFX
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password | Out-Null

# Convertir o generar PEM
$certPem = [System.Convert]::ToBase64String($cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
"-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----" | Out-File -FilePath $certPath -Encoding ascii

Write-Host "Certificado exportado en: $certPath" -ForegroundColor Green
Write-Host "Para el despliegue en producción real con Docker/Nginx, monte los certificados emitidos por Let's Encrypt o su CA corporativa." -ForegroundColor Yellow
