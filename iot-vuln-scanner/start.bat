@echo off
:: IoT Security Scanner - double-click this file to start it on Windows.
:: It asks for administrator rights (needed for ARP and Nmap), installs the
:: Python packages the first time and opens the interactive menu.
cd /d "%~dp0"
title IoT Security Scanner

net session >nul 2>&1
if errorlevel 1 (
    echo Asking for administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: UTF-8, so the logo and the symbols are shown correctly
chcp 65001 >nul
set PYTHONIOENCODING=utf-8

set "PY=python"
if exist "..\.venv\Scripts\python.exe" set "PY=..\.venv\Scripts\python.exe"
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"

%PY% --version >nul 2>&1
if errorlevel 1 (
    echo Python was not found. Install Python 3.11+ from https://www.python.org and try again.
    pause
    exit /b 1
)

%PY% -c "import scapy, nmap, mac_vendor_lookup, requests, rich" >nul 2>&1
if errorlevel 1 (
    echo First start: installing the required Python packages...
    %PY% -m pip install -r requirements.txt
    if errorlevel 1 (
        pause
        exit /b 1
    )
)

%PY% main.py %*
if errorlevel 1 pause
