@echo off
title DockerScan - Build EXE
cd /d "%~dp0"

set "PY="
py -3 --version >nul 2>nul && set "PY=py -3"
if not defined PY (python --version >nul 2>nul && set "PY=python")
if not defined PY (
    echo [ERROR] Python 3.9+ was not found. Install it from https://www.python.org/downloads/
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    %PY% -m venv .venv
    if errorlevel 1 ( echo [ERROR] Could not create the virtual environment. & pause & exit /b 1 )
)

echo Installing build dependencies...
".venv\Scripts\python.exe" -m pip install -r requirements.txt pyinstaller --quiet --disable-pip-version-check
if errorlevel 1 ( echo [ERROR] pip install failed. & pause & exit /b 1 )

echo.
echo [1/2] Building the desktop app: DockerScan.exe (a few minutes)...
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name DockerScan --icon icon.ico --collect-all customtkinter ^
    --add-data "data;data" --add-data "icon.ico;." --add-data "icon.png;." main.py
if errorlevel 1 ( echo [ERROR] Desktop build failed. See the messages above. & pause & exit /b 1 )

echo.
echo [2/2] Building the command-line tool: DockerScan-cli.exe ...
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --onefile --console ^
    --name DockerScan-cli --icon icon.ico --add-data "data;data" cli.py
if errorlevel 1 ( echo [ERROR] CLI build failed. See the messages above. & pause & exit /b 1 )

echo.
echo ============================================================
echo  SUCCESS!
echo    Desktop app : dist\DockerScan.exe
echo    Command line: dist\DockerScan-cli.exe scan image.tar
echo ============================================================
pause
