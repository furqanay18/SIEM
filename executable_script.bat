@echo off
title 🚀 SIEM Logs Consumer
echo ==========================================
echo   Starting logs_consumer.py
echo ==========================================

:: Go to the directory where this .bat file is located
cd /d "%~dp0"

:: Activate venv if it exists
if exist ".venv\Scripts\activate.bat" (
    echo ✅ Activating virtual environment...
    call ".venv\Scripts\activate.bat"
) else (
    echo ⚠️ No virtual environment found, using system Python.
)

:: Check Python installation
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python not found! Please install Python 3.
    pause
    exit /b
)

:: Run the script directly
echo ✅ Running logs_consumer.py ...
python logs_consumer.py

echo.
echo ==========================================
echo 🟢 logs_consumer.py has exited.
echo Press any key to close this window.
pause >nul
