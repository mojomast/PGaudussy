#!/bin/bash
# PGaudussy Installation Script
# Copyright 2025
# This script installs all dependencies for PGaudussy including Python, pip, and PostgreSQL client

# Text formatting
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BOLD}PGaudussy Installation Script${NC}"
echo -e "Copyright 2025"
echo "==============================================="
echo ""

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="MacOS"
elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="Windows"
else
    OS="Unknown"
fi

echo -e "${BOLD}Detected operating system:${NC} $OS"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Python on Linux
install_python_linux() {
    echo -e "${BOLD}Installing Python on Linux...${NC}"
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv
    elif command_exists dnf; then
        sudo dnf install -y python3 python3-pip python3-virtualenv
    elif command_exists yum; then
        sudo yum install -y python3 python3-pip python3-virtualenv
    elif command_exists pacman; then
        sudo pacman -Sy python python-pip python-virtualenv
    else
        echo -e "${RED}Unsupported Linux distribution. Please install Python 3.8+ and pip manually.${NC}"
        exit 1
    fi
}

# Function to install PostgreSQL client on Linux
install_postgres_client_linux() {
    echo -e "${BOLD}Installing PostgreSQL client on Linux...${NC}"
    if command_exists apt-get; then
        sudo apt-get install -y postgresql-client
    elif command_exists dnf; then
        sudo dnf install -y postgresql
    elif command_exists yum; then
        sudo yum install -y postgresql
    elif command_exists pacman; then
        sudo pacman -Sy postgresql
    else
        echo -e "${RED}Unsupported Linux distribution. Please install PostgreSQL client manually.${NC}"
        exit 1
    fi
}

# Function to install Python on Windows using Chocolatey
install_python_windows() {
    echo -e "${BOLD}Installing Python on Windows...${NC}"
    
    # Check if Chocolatey is installed
    if ! command_exists choco; then
        echo -e "${YELLOW}Chocolatey not found. Installing Chocolatey...${NC}"
        powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
    fi
    
    # Install Python using Chocolatey
    choco install -y python
    
    # Refresh environment variables
    export PATH="$PATH:/c/Python310:/c/Python310/Scripts"
}

# Function to install PostgreSQL client on Windows using Chocolatey
install_postgres_client_windows() {
    echo -e "${BOLD}Installing PostgreSQL client on Windows...${NC}"
    choco install -y postgresql
}

# Main installation logic
if [[ "$OS" == "Linux" || "$OS" == "MacOS" ]]; then
    # Check if Python is installed
    if ! command_exists python3; then
        install_python_linux
    else
        echo -e "${GREEN}Python is already installed.${NC}"
    fi
    
    # Check if pip is installed
    if ! command_exists pip3; then
        echo -e "${YELLOW}pip not found. Installing pip...${NC}"
        if [[ "$OS" == "Linux" ]]; then
            install_python_linux
        else
            sudo easy_install pip
        fi
    else
        echo -e "${GREEN}pip is already installed.${NC}"
    fi
    
    # Check if PostgreSQL client is installed
    if ! command_exists psql; then
        install_postgres_client_linux
    else
        echo -e "${GREEN}PostgreSQL client is already installed.${NC}"
    fi
    
    # Create virtual environment
    echo -e "${BOLD}Creating virtual environment...${NC}"
    python3 -m venv venv
    
    # Activate virtual environment
    echo -e "${BOLD}Activating virtual environment...${NC}"
    source venv/bin/activate
    
    # Install Python dependencies
    echo -e "${BOLD}Installing Python dependencies...${NC}"
    pip install -r requirements.txt
    
elif [[ "$OS" == "Windows" ]]; then
    # Check if Python is installed
    if ! command_exists python; then
        install_python_windows
    else
        echo -e "${GREEN}Python is already installed.${NC}"
    fi
    
    # Check if pip is installed
    if ! command_exists pip; then
        echo -e "${YELLOW}pip not found. Installing pip...${NC}"
        install_python_windows
    else
        echo -e "${GREEN}pip is already installed.${NC}"
    fi
    
    # Check if PostgreSQL client is installed
    if ! command_exists psql; then
        install_postgres_client_windows
    else
        echo -e "${GREEN}PostgreSQL client is already installed.${NC}"
    fi
    
    # Create virtual environment
    echo -e "${BOLD}Creating virtual environment...${NC}"
    python -m venv venv
    
    # Activate virtual environment
    echo -e "${BOLD}Activating virtual environment...${NC}"
    . venv/Scripts/activate
    
    # Install Python dependencies
    echo -e "${BOLD}Installing Python dependencies...${NC}"
    pip install -r requirements.txt
else
    echo -e "${RED}Unsupported operating system: $OS${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}${BOLD}Installation completed successfully!${NC}"
echo -e "${BOLD}To activate the virtual environment:${NC}"
if [[ "$OS" == "Linux" || "$OS" == "MacOS" ]]; then
    echo "  source venv/bin/activate"
else
    echo "  .\\venv\\Scripts\\activate"
fi
echo -e "${BOLD}To run PGaudussy:${NC}"
echo "  python menu.py"
echo ""
