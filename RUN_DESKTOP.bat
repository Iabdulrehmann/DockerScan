@echo off
title DockerScan Launcher
cd /d "%~dp0"

set "PY="
py -3 --version >nul 2>nul && set "PY=py -3"
if not defined PY (python --version >nul 2>nul && set "PY=python")
if not defined PY (
    echo [ERROR] Python 3.9+ was not found. Install it from https://www.python.org/downloads/
    echo         and tick "Add Python to PATH" during setup.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    %PY% -m venv .venv
    if errorlevel 1 ( echo [ERROR] Could not create the virtual environment. & pause & exit /b 1 )
)

echo Checking dependencies...
".venv\Scripts\python.exe" -m pip install -r requirements.txt --quiet --disable-pip-version-check
if errorlevel 1 ( echo [ERROR] Could not install requirements. Check your internet connection once. & pause & exit /b 1 )

echo Starting DockerScan...
start "" ".venv\Scripts\pythonw.exe" main.py
exit /b 0
