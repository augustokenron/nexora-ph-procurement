@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Please run install_windows.bat first.
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
set PROCURETRACK_HOST=0.0.0.0
echo WARNING: Pilot use only. Restrict Windows Firewall access to the Private office network.
echo Find the server LAN IPv4 address with ipconfig, then staff can visit http://SERVER-IP:5000
python app.py
pause
