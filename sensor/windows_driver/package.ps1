# Package SnsDrv into a test-signed driver package (.sys/.inf/.cat + .cer).
#
# A no-elevation alternative to `cargo make`, whose wdk-build makefile bootstrap
# needs a symlink privilege (Developer Mode / admin / eWDK prompt). This drives the
# WDK tools directly: stampinf -> Inf2Cat -> self-signed cert -> signtool.
#
# Usage (from a normal PowerShell):
#   $env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
#   .\package.ps1                 # debug build
#   .\package.ps1 -Release        # release build
param([switch]$Release)

$ErrorActionPreference = "Stop"
$proj = $PSScriptRoot
$cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"

# Locate the newest WDK bin (stampinf/signtool are x64; Inf2Cat is x86-only).
$binRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
$ver = (Get-ChildItem $binRoot -Directory | Where-Object { $_.Name -match '^10\.' } |
    Sort-Object Name -Descending | Select-Object -First 1).Name
$x64 = "$binRoot\$ver\x64"
$x86 = "$binRoot\$ver\x86"

$profileDir = if ($Release) { "release" } else { "debug" }
$profileArg = if ($Release) { @("build", "--release") } else { @("build") }

Write-Host "==> cargo $profileArg"
& $cargo @profileArg

$pkg = "$proj\target\package"
Remove-Item $pkg -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $pkg | Out-Null
Copy-Item "$proj\target\x86_64-pc-windows-msvc\$profileDir\snsdrv.dll" "$pkg\SnsDrv.sys"
Copy-Item "$proj\SnsDrv.inx" "$pkg\SnsDrv.inf"

Write-Host "==> stampinf"
& "$x64\stampinf.exe" -f "$pkg\SnsDrv.inf" -d "*" -a "amd64" -v "*"

Write-Host "==> Inf2Cat"
& "$x86\Inf2Cat.exe" /driver:"$pkg" /os:10_x64 /uselocaltime

Write-Host "==> self-signed test cert + signtool"
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=SnsDrv Test Cert" `
    -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3") -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears(5)
Export-Certificate -Cert $cert -FilePath "$pkg\WDRLocalTestCert.cer" | Out-Null
& "$x64\signtool.exe" sign /v /fd SHA256 /sha1 $cert.Thumbprint "$pkg\SnsDrv.sys"
& "$x64\signtool.exe" sign /v /fd SHA256 /sha1 $cert.Thumbprint "$pkg\*.cat"

Write-Host "`nPackage in $pkg :"
Get-ChildItem $pkg | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "To load: import WDRLocalTestCert.cer into LocalMachine Root + TrustedPublisher"
Write-Host "(or 'bcdedit /set testsigning on'), then sc create / fltmc load."
