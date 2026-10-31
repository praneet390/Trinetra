# capture_live_logs.ps1
# Runs main.py under each sensor config, fires each harness, captures real sensor logs.
# Run from: C:\Users\kaush\OneDrive\Desktop\Entity_2.0\src
# Requires: driver loaded, Sysmon running, harnesses built in ..\driver\sensor\

$python   = "..\venv\Scripts\python.exe"
$mainpy   = "main.py"
$harnesses = @{
    "ppid_spoof"      = "..\driver\sensor\ppid_spoof_test.exe"
    "lsass_access"    = "..\driver\sensor\lsass_access_test.exe"
    "defender_tamper" = "..\driver\sensor\cmdline_blind_spot_test.exe"
    "office_lolbin"   = "..\driver\sensor\parentimage_blind_spot_test.exe"
}

$configs = @(
    @{ id="all_three";   flags="" },
    @{ id="kernel_only"; flags="--no-sysmon --no-etw" },
    @{ id="sysmon_only"; flags="--no-etw --no-kernel" },
    @{ id="etw_only";    flags="--no-sysmon --no-kernel" }
)

$outDir = "live_logs"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

foreach ($cfg in $configs) {
    Write-Host "`n======================================" -ForegroundColor Cyan
    Write-Host "CONFIG: $($cfg.id)  flags: '$($cfg.flags)'" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan

    $logFile = "$outDir\$($cfg.id).txt"
    "CONFIG: $($cfg.id)  flags: $($cfg.flags)" | Out-File $logFile

    # Start main.py in background, redirect output to log file
    $mainArgs = if ($cfg.flags) { "$mainpy $($cfg.flags)" } else { $mainpy }
    $proc = Start-Process -FilePath $python -ArgumentList $mainArgs `
                          -RedirectStandardOutput $logFile `
                          -RedirectStandardError  "$outDir\$($cfg.id)_err.txt" `
                          -PassThru -WindowStyle Hidden

    Write-Host "  main.py started (pid=$($proc.Id)), waiting 5s for sensors to init..."
    Start-Sleep -Seconds 5

    foreach ($scenario in $harnesses.Keys) {
        $exe = $harnesses[$scenario]
        if (-not (Test-Path $exe)) {
            Write-Host "  [SKIP] $scenario — harness not found: $exe" -ForegroundColor Yellow
            continue
        }
        Write-Host "  Running harness: $scenario" -ForegroundColor White
        & $exe | Out-Null
        Start-Sleep -Seconds 3   # let the engine process the event
    }

    # Give engine a moment to flush logs then stop it
    Start-Sleep -Seconds 2
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Write-Host "  Logs saved -> $logFile"
}

Write-Host "`n=== COMBINED OUTPUT ===" -ForegroundColor Green
foreach ($cfg in $configs) {
    $logFile = "$outDir\$($cfg.id).txt"
    Write-Host "`n--- $($cfg.id) ---" -ForegroundColor Yellow
    Get-Content $logFile | Select-String -Pattern "ALERT|WARNING|TELEMETRY|ABLATION|EDR|score|detected|ppid|lsass|driver|tamper|lolbin" -CaseSensitive:$false
}
