@echo off
:: Run as Administrator. One-time setup on a new machine.
:: Trusts the pre-built driver cert, enables test signing, then reboot once.
:: After reboot, launching the agent starts the driver service automatically.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Run this as Administrator.
    pause
    exit /b 1
)

echo [*] Trusting driver certificate...
certutil -addstore TrustedPublisher driver\sensor\EntityDriverCert.cer
certutil -addstore Root             driver\sensor\EntityDriverCert.cer

echo [*] Enabling test signing...
bcdedit /set testsigning on

echo.
echo Done. Reboot once, then run:  python src\main.py
pause
