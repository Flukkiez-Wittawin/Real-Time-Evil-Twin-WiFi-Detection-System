@echo off
echo ==========================================
echo    WiFi SOC: Launching System...
echo ==========================================
if not exist venv (
    echo [!] venv not found. Running setup first...
    call setup_system.cmd
)
echo [*] Starting Real-Time Monitor...
start http://localhost:5000
.\venv\Scripts\python main.py
pause
