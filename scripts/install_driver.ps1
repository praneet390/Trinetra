<#
.SYNOPSIS
    One-time driver setup for Entity on a new Windows machine.

.DESCRIPTION
    Handles the full setup chain that a fresh git clone is missing:
      1. Locates or builds sensor.sys from driver/sensor/sensor.vcxproj
      2. Creates a self-signed code-signing certificate (once per machine)
      3. Trusts that certificate in TrustedPublisher and Root stores
      4. Signs sensor.sys
      5. Enables test-signing mode (bcdedit /set testsigning on)
      6. Creates and starts the 'sensor' kernel-driver Windows service

    Safe to run more than once.  Each step is idempotent: an existing cert,
    an already-running service, or test-signing already on are all detected
    and skipped without error.

.NOTES
    Requirements:
      - Run as Administrator (the script self-elevates if needed)
      - Windows 10 / 11 x64
      - Visual Studio 2022 + WDK installed to build the driver (optional:
        skip if you already have sensor.sys)

    After the first run you may be asked to reboot once (test signing).
    Subsequent agent launches call ensure_driver_running() in kernel_sensor.py
    which starts the already-registered service without any of these steps.
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 0. Self-elevate if not already running as Administrator
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[*] Relaunching as Administrator..." -ForegroundColor Cyan
    $argList = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $MyInvocation.MyCommand.Definition
    Start-Process powershell -Verb RunAs -ArgumentList $argList -Wait
    exit $LASTEXITCODE
}

# ---------------------------------------------------------------------------
# 1. Resolve paths relative to the repository root
# ---------------------------------------------------------------------------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot  = Split-Path -Parent $scriptDir

$vcxproj   = Join-Path $repoRoot 'driver\sensor\sensor.vcxproj'
$sysDebug  = Join-Path $repoRoot 'driver\sensor\x64\Debug\sensor.sys'
$sysRel    = Join-Path $repoRoot 'driver\sensor\x64\Release\sensor.sys'

function Find-SensorSys {
    foreach ($candidate in @($sysDebug, $sysRel)) {
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

$certFriendlyName = 'EntityDriverTestCert'
$serviceName      = 'sensor'
$rebootRequired   = $false

Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  Entity  --  kernel driver installer"            -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 2. Locate or build sensor.sys
# ---------------------------------------------------------------------------
$sysPath = Find-SensorSys

if (-not $sysPath) {
    Write-Host "[*] sensor.sys not found -- attempting to build from source..." -ForegroundColor Yellow

    if (-not (Test-Path $vcxproj)) {
        Write-Error "driver\sensor\sensor.vcxproj not found.  Is the repository complete?"
    }

    # Locate MSBuild shipped with Visual Studio 2019 / 2022 (Build Tools or full IDE).
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        Write-Error (
            "vswhere.exe not found.`n" +
            "Install Visual Studio 2022 (Community / Build Tools) with the" +
            " 'Desktop development with C++' workload and the WDK, then re-run."
        )
    }

    $vsInstallPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
                                -property installationPath 2>$null | Select-Object -First 1
    if (-not $vsInstallPath) {
        Write-Error "No Visual Studio installation with MSBuild found.  Install VS 2022 + WDK."
    }

    $msbuild = Join-Path $vsInstallPath 'MSBuild\Current\Bin\MSBuild.exe'
    if (-not (Test-Path $msbuild)) {
        Write-Error "MSBuild.exe not found at $msbuild.  Check your Visual Studio installation."
    }

    Write-Host "[*] Building sensor.vcxproj (x64, Debug) ..." -ForegroundColor Cyan
    & $msbuild $vcxproj /p:Configuration=Debug /p:Platform=x64 /m /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) {
        Write-Error "MSBuild failed (exit $LASTEXITCODE). Ensure the WDK matching your VS version is installed."
    }

    $sysPath = Find-SensorSys
    if (-not $sysPath) {
        Write-Error "Build succeeded but sensor.sys was not found at the expected output path."
    }
    Write-Host "[+] Built: $sysPath" -ForegroundColor Green
} else {
    Write-Host "[+] Found sensor.sys: $sysPath" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 3. Create (or reuse) a self-signed code-signing certificate
# ---------------------------------------------------------------------------
$cert = Get-ChildItem -Path 'Cert:\CurrentUser\My' |
        Where-Object { $_.FriendlyName -eq $certFriendlyName } |
        Select-Object -First 1

if ($cert) {
    Write-Host "[+] Reusing existing cert: $($cert.Thumbprint)" -ForegroundColor Green
} else {
    Write-Host "[*] Creating self-signed code-signing certificate..." -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate `
        -Subject          "CN=$certFriendlyName" `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -Type             CodeSigningCert `
        -KeyUsage         DigitalSignature `
        -FriendlyName     $certFriendlyName `
        -NotAfter         (Get-Date).AddYears(10)
    Write-Host "[+] Created cert: $($cert.Thumbprint)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 4. Trust the certificate in TrustedPublisher and Root stores
# ---------------------------------------------------------------------------
$certFile = Join-Path $env:TEMP "$certFriendlyName.cer"
Export-Certificate -Cert $cert -FilePath $certFile -Type CERT | Out-Null

foreach ($store in @('TrustedPublisher', 'Root')) {
    $existing = Get-ChildItem -Path "Cert:\LocalMachine\$store" |
                Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if ($existing) {
        Write-Host "[+] Cert already trusted in LocalMachine\$store" -ForegroundColor Green
    } else {
        Import-Certificate -FilePath $certFile -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
        Write-Host "[+] Trusted cert in LocalMachine\$store" -ForegroundColor Green
    }
}
Remove-Item $certFile -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 5. Sign sensor.sys with the certificate
# ---------------------------------------------------------------------------
Write-Host "[*] Signing $sysPath ..." -ForegroundColor Cyan
$sig = Set-AuthenticodeSignature -FilePath $sysPath -Certificate $cert -TimestampServer $null
if ($sig.Status -ne 'Valid') {
    Write-Error "Signing failed: $($sig.StatusMessage)"
}
Write-Host "[+] Signed successfully (status: $($sig.Status))" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 6. Enable test-signing mode
# ---------------------------------------------------------------------------
$bcdedit = "$env:SystemRoot\System32\bcdedit.exe"
$tsOutput = & $bcdedit /enum '{current}' 2>&1 | Out-String
if ($tsOutput -match 'testsigning\s+Yes') {
    Write-Host "[+] Test signing already enabled" -ForegroundColor Green
} else {
    Write-Host "[*] Enabling test signing (bcdedit /set testsigning on) ..." -ForegroundColor Yellow
    & $bcdedit /set testsigning on | Out-Null
    Write-Host "[+] Test signing enabled" -ForegroundColor Green
    $rebootRequired = $true
}

# ---------------------------------------------------------------------------
# 7. Create and start the kernel-driver service
# ---------------------------------------------------------------------------
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($svc) {
    Write-Host "[+] Service '$serviceName' already exists (status: $($svc.Status))" -ForegroundColor Green
} else {
    Write-Host "[*] Creating kernel driver service '$serviceName' ..." -ForegroundColor Cyan
    $result = sc.exe create $serviceName type= kernel start= demand binPath= "`"$sysPath`""
    if ($LASTEXITCODE -ne 0) {
        Write-Error "sc.exe create failed: $result"
    }
    Write-Host "[+] Service '$serviceName' created" -ForegroundColor Green
}

if ($rebootRequired) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host "  REBOOT REQUIRED" -ForegroundColor Yellow
    Write-Host "  Test signing was just enabled.  Reboot, then run:"        -ForegroundColor Yellow
    Write-Host "  sc.exe start $serviceName" -ForegroundColor Yellow
    Write-Host "  (or just launch the agent -- it starts the service itself)" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Yellow
} else {
    # Start the service now
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Host "[+] Service '$serviceName' is already running" -ForegroundColor Green
    } else {
        Write-Host "[*] Starting service '$serviceName' ..." -ForegroundColor Cyan
        $start = sc.exe start $serviceName 2>&1 | Out-String
        $svc   = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Host "[+] Service '$serviceName' is running" -ForegroundColor Green
        } else {
            Write-Warning "Service did not reach Running state.  Output: $start"
            Write-Warning "If you see error 577 (code integrity), verify test signing is on and reboot."
        }
    }
}

Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  Setup complete.  Launch the agent with:"        -ForegroundColor Cyan
Write-Host "  python src\main.py"                             -ForegroundColor White
Write-Host "  (or: python src\web_server.py for the dashboard)" -ForegroundColor White
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""
