@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Please run install_windows.bat first.
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
set PROCURETRACK_HOST=127.0.0.1
python app.py
pause
