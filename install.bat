@echo off
:: PGaudussy Installation Script for Windows
:: Copyright 2025

echo PGaudussy Installation Script
echo Copyright 2025
echo ===============================================
echo.

:: Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script requires administrator privileges.
    echo Please run as administrator and try again.
    pause
    exit /b 1
)

echo Checking for Chocolatey package manager...
where choco >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing Chocolatey package manager...
    @powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
    if %errorLevel% neq 0 (
        echo Failed to install Chocolatey. Please install manually from https://chocolatey.org/install
        pause
        exit /b 1
    )
    echo Chocolatey installed successfully.
) else (
    echo Chocolatey is already installed.
)

:: Check for Python
echo Checking for Python...
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing Python...
    choco install -y python
    if %errorLevel% neq 0 (
        echo Failed to install Python. Please install manually from https://www.python.org/downloads/
        pause
        exit /b 1
    )
    echo Python installed successfully.
    :: Refresh environment variables
    call refreshenv
) else (
    echo Python is already installed.
)

:: Check for PostgreSQL client
echo Checking for PostgreSQL client...
where psql >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing PostgreSQL client...
    choco install -y postgresql
    if %errorLevel% neq 0 (
        echo Failed to install PostgreSQL client. Please install manually.
        pause
        exit /b 1
    )
    echo PostgreSQL client installed successfully.
    :: Refresh environment variables
    call refreshenv
) else (
    echo PostgreSQL client is already installed.
)

:: Create virtual environment
echo Creating virtual environment...
if not exist venv (
    python -m venv venv
    if %errorLevel% neq 0 (
        echo Failed to create virtual environment.
        pause
        exit /b 1
    )
) else (
    echo Virtual environment already exists.
)

:: Activate virtual environment and install dependencies
echo Activating virtual environment and installing dependencies...
call venv\Scripts\activate.bat
if %errorLevel% neq 0 (
    echo Failed to activate virtual environment.
    pause
    exit /b 1
)

:: Install dependencies
echo Installing Python dependencies...
pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo Installation completed successfully!
echo.
echo To activate the virtual environment:
echo   venv\Scripts\activate.bat
echo.
echo To run PGaudussy:
echo   python menu.py
echo.

pause
