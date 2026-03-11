@echo off
echo ==========================================
echo    WiFi SOC: Setup Virtual Environment
echo ==========================================
echo [*] Creating venv...
python -m venv venv
echo [*] Installing dependencies into venv...
.\venv\Scripts\python -m pip install --upgrade pip
.\venv\Scripts\pip install -r requirements.txt
echo ==========================================
echo    Setup Complete!
echo ==========================================
pause
