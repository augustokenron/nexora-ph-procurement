@echo off
cd /d "%~dp0"
echo Installing ProcureTrack PH dependencies...
py -3 -m venv .venv
if errorlevel 1 goto error
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 goto error
echo.
echo Installation complete. Double-click start_windows.bat to run.
pause
exit /b 0
:error
echo Installation failed. Check that Python 3.11+ is installed and available with the py command.
pause
exit /b 1
