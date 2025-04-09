#!/usr/bin/env python3
"""
PostgreSQL Database Permissions Audit Tool - Interactive Menu

This module provides an interactive menu for the PostgreSQL database permissions audit tool.
"""

import os
import sys
import pathlib
import logging
import subprocess
import configparser
from dataclasses import dataclass
from typing import Optional, List
from datetime import datetime as dt

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.markdown import Markdown
from rich.logging import RichHandler

from pg_service import ServiceConfig
from utils.backup import BackupManager, BackupInfo
from utils.reports import ReportGenerator

# Simplified PgServiceConfigParser implementation
class PgServiceConfigParser:
    def __init__(self, config_path=None):
        # If a specific path is provided, use it
        if config_path:
            self.config_path = config_path
        else:
            # Otherwise, always use the pg_service.conf in the project directory
            self.config_path = os.path.join(os.getcwd(), 'pg_service.conf')
            
            # Create the file if it doesn't exist
            if not os.path.exists(self.config_path):
                with open(self.config_path, 'w') as f:
                    f.write("""# PostgreSQL Service Configuration File
# Format: [service_name]
#         host=hostname
#         port=port
#         dbname=database_name
#         user=username
#         password=password (optional)
""")
                console.print(f"[yellow]Created new pg_service.conf file at: {self.config_path}[/yellow]")
        
        self.config = configparser.ConfigParser()
        if os.path.exists(self.config_path):
            # Read the config file
            self.config.read(self.config_path)
    
    def get_services(self):
        services = []
        for section in self.config.sections():
            # Create a ServiceConfig object with the service parameters
            # Store the service name separately since ServiceConfig doesn't have a name field
            service = ServiceConfig(
                host=self.config.get(section, 'host', fallback='localhost').strip(),
                port=self.config.get(section, 'port', fallback='5432').strip(),
                dbname=self.config.get(section, 'dbname', fallback='').strip(),
                user=self.config.get(section, 'user', fallback='').strip(),
                password=self.config.get(section, 'password', fallback=None)
            )
            # Add the service name as an attribute
            service.name = section
            services.append(service)
        return services
    
    def get_service(self, service_name):
        if service_name in self.config:
            section = self.config[service_name]
            service = ServiceConfig(
                host=section.get('host', 'localhost').strip(),
                port=section.get('port', '5432').strip(),
                dbname=section.get('dbname', '').strip(),
                user=section.get('user', '').strip(),
                password=section.get('password', None)
            )
            # Add the service name as an attribute
            service.name = service_name
            return service
        return None

    def add_service(self, service_name, host, port, dbname, user, password=None):
        if not service_name in self.config:
            self.config.add_section(service_name)
        
        self.config[service_name]['host'] = host
        self.config[service_name]['port'] = port
        self.config[service_name]['dbname'] = dbname
        self.config[service_name]['user'] = user
        if password:
            self.config[service_name]['password'] = password
        
        # Save to file
        with open(self.config_path, 'w') as f:
            self.config.write(f)

# Function to get available services
def get_available_services():
    """Get list of available services from pg_service.conf"""
    pg_service_parser = PgServiceConfigParser()
    return [service.name for service in pg_service_parser.get_services()]

# Ensure necessary directories exist
def ensure_directories_exist():
    """Ensure that necessary directories exist and create required configuration files."""
    # Create directories
    directories = [
        'backups', 
        'config', 
        'data', 
        'data/logs', 
        'data/audit_results',
        'reports'  # Keep the original reports directory for backward compatibility
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"Ensured directory exists: {directory}")
    
    # Create default configuration files if they don't exist
    default_config_files = {
        'config/dbaudit.conf': '[DEFAULT]\nrisk_level = all\noutput_format = text\n'
    }
    
    for file_path, content in default_config_files.items():
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"Created default configuration file: {file_path}")

# Ensure directories exist at startup
ensure_directories_exist()

# Configure rich console for better output
console = Console()

# Configure logging with rich
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)
logger = logging.getLogger("dbaudit_menu")

# Also set up file logging
log_file_path = os.path.join("data", "logs", "dbaudit_menu.log")
file_handler = logging.FileHandler(log_file_path)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_header():
    """Display the application header"""
    clear_screen()
    console.print(Panel.fit(
        "[bold blue]PostgreSQL Database Permissions Audit Tool[/bold blue]",
        subtitle="[italic]PGaudussy - Copyright 2025 - Interactive Menu[/italic]"
    ))
    console.print()

def display_main_menu():
    """Display the main menu options"""
    console.print("[bold]Main Menu:[/bold]")
    console.print("1. Run Database Audit")
    console.print("2. Manage pg_service.conf")
    console.print("3. Configure Audit Settings")
    console.print("4. View Previous Audit Results")
    console.print("5. Backup and Restore Databases")
    console.print("6. Generate HTML Reports")
    console.print("7. Exit")
    console.print()
    
    choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6", "7"], default="1")
    return choice

def run_audit_menu():
    ensure_directories_exist()
    """Menu for running database audits"""
    display_header()
    console.print("[bold]Run Database Audit[/bold]")
    console.print()
    
    # Get available services
    pg_service_parser = PgServiceConfigParser()
    pg_services = pg_service_parser.get_services()
    
    if not pg_services:
        console.print("[yellow]No services found in pg_service.conf[/yellow]")
        console.print("Please set up your pg_service.conf file first.")
        if Confirm.ask("Would you like to create a new service now?", default=True):
            create_new_service()
        return
    
    # Display available services
    console.print("[bold]Available Services:[/bold]")
    for i, service in enumerate(pg_services, 1):
        console.print(f"{i}. {service.name} ({service.dbname})")
    console.print(f"{len(pg_services) + 1}. Cancel")
    console.print()
    
    # Get service selection
    choice = Prompt.ask(
        "Select a service", 
        choices=[str(i) for i in range(1, len(pg_services) + 2)],
        default="1"
    )
    
    if int(choice) == len(pg_services) + 1:
        return
    
    selected_service = pg_services[int(choice) - 1]
    
    # Get risk level
    console.print()
    console.print("[bold]Risk Level:[/bold]")
    console.print("1. High (only critical issues)")
    console.print("2. Medium (critical and moderate issues)")
    console.print("3. Low (all issues including informational)")
    console.print("4. All (include all findings)")
    console.print()
    
    risk_choice = Prompt.ask("Select risk level", choices=["1", "2", "3", "4"], default="4")
    risk_levels = {
        "1": "high",
        "2": "medium",
        "3": "low",
        "4": "all"
    }
    risk_level = risk_levels[risk_choice]
    
    # Get output format
    console.print()
    console.print("[bold]Output Format:[/bold]")
    console.print("1. Text (human-readable)")
    console.print("2. JSON (machine-readable)")
    console.print()
    
    format_choice = Prompt.ask("Select output format", choices=["1", "2"], default="1")
    output_format = "text" if format_choice == "1" else "json"
    
    # Generate output filename
    if output_format == "text":
        output_file = f"audit_{selected_service.name}_{risk_level}.txt"
    else:
        output_file = f"audit_{selected_service.name}_{risk_level}.json"
    
    # Confirm
    console.print()
    console.print("[bold]Audit Configuration:[/bold]")
    console.print(f"Service: [cyan]{selected_service.name}[/cyan]")
    console.print(f"Risk Level: [cyan]{risk_level}[/cyan]")
    console.print(f"Output Format: [cyan]{output_format}[/cyan]")
    console.print(f"Output File: [cyan]{output_file}[/cyan]")
    console.print()
    
    if Confirm.ask("Run audit with these settings?", default=True):
        # Run the audit
        try:
            cmd = ["python", "dbaudit.py", "--service", selected_service.name, "audit", "--risk-level", risk_level]
            
            if output_format == "json":
                cmd.extend(["--format", "json"])
            
            cmd.extend(["--output", output_file])
            
            logger.info(f"Starting audit for service: {selected_service.name}, risk level: {risk_level}")
            
            # Run the command
            console.print()
            console.print("[bold]Running audit...[/bold]")
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0:
                console.print()
                console.print("[green]Audit completed successfully![/green]")
                console.print(f"Results saved to: [cyan]{output_file}[/cyan]")
                
                # Display summary from the output
                if os.path.exists(output_file):
                    if output_format == "text":
                        with open(output_file, 'r') as f:
                            content = f.read()
                            console.print(Panel(Markdown(content[:500] + "..." if len(content) > 500 else content)))
                
                logger.info(f"Audit completed successfully for service: {selected_service.name}")
            else:
                console.print()
                console.print("[red]Audit failed![/red]")
                
                # Display error message
                if process.stderr:
                    console.print(process.stderr)
                    logger.error(f"Audit failed for service: {selected_service.name}")
                    logger.error(process.stderr)
                
                if Confirm.ask("View error details?", default=True):
                    console.print(process.stderr)
        except Exception as e:
            console.print(f"[red]Error running audit: {e}[/red]")
            logger.error(f"Error running audit: {e}")
    
    # Wait for user to acknowledge before returning to the main menu
    console.print()
    Prompt.ask("Press Enter to return to the main menu")

def manage_pg_service_menu():
    ensure_directories_exist()
    """Menu for managing pg_service.conf"""
    display_header()
    console.print("[bold]Manage pg_service.conf[/bold]")
    console.print()
    
    # Find pg_service.conf
    pg_service_path = PgServiceConfigParser().config_path
    
    console.print(f"Current pg_service.conf path: [cyan]{pg_service_path}[/cyan]")
    console.print()
    
    console.print("[bold]Options:[/bold]")
    console.print("1. View Current Services")
    console.print("2. Add New Service")
    console.print("3. Edit Existing Service")
    console.print("4. Create New pg_service.conf")
    console.print("5. Return to Main Menu")
    console.print()
    
    choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5"], default="1")
    
    if choice == "1":
        view_services(pg_service_path)
    elif choice == "2":
        add_service(pg_service_path)
    elif choice == "3":
        edit_service(pg_service_path)
    elif choice == "4":
        create_pg_service_conf()
    
    # Return to main menu
    if choice != "5":
        Prompt.ask("Press Enter to return to the manage pg_service menu")
        manage_pg_service_menu()

def view_services(pg_service_path):
    """View services in pg_service.conf"""
    console.print()
    console.print("[bold]Services in pg_service.conf:[/bold]")
    
    # Convert string path to Path object if needed
    if isinstance(pg_service_path, str):
        pg_service_path = pathlib.Path(pg_service_path)
    
    if not pg_service_path.exists():
        console.print("[yellow]pg_service.conf not found![/yellow]")
        return
    
    try:
        parser = PgServiceConfigParser(pg_service_path)
        services = parser.get_services()
        
        if not services:
            console.print("[yellow]No services found in pg_service.conf[/yellow]")
            return
        
        service_table = Table(show_header=True)
        service_table.add_column("Service", style="cyan")
        service_table.add_column("Host", style="green")
        service_table.add_column("Port", style="blue")
        service_table.add_column("Database", style="magenta")
        service_table.add_column("User", style="yellow")
        service_table.add_column("Password", style="red")
        
        for service in services:
            password_display = "********" if service.password else "None"
            service_table.add_row(
                service.name,
                service.host,
                service.port,
                service.dbname,
                service.user,
                password_display
            )
        
        console.print(service_table)
    except Exception as e:
        console.print(f"[red]Error reading pg_service.conf: {e}[/red]")

def add_service(pg_service_path):
    """Add a new service to pg_service.conf"""
    display_header()
    console.print("[bold]Add New Service[/bold]")
    console.print()
    
    # Convert string path to Path object if needed
    if isinstance(pg_service_path, str):
        pg_service_path = pathlib.Path(pg_service_path)
    
    if not pg_service_path.exists():
        if not Confirm.ask(f"pg_service.conf not found at {pg_service_path}. Create it?", default=True):
            return
        
        pg_service_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create empty pg_service.conf with comments
        with open(pg_service_path, 'w') as f:
            f.write("""# PostgreSQL Service Configuration File
# Format: [service_name]
#         host=hostname
#         port=port
#         dbname=database_name
#         user=username
#         password=password (optional)
""")
    
    # Get service details
    service_name = Prompt.ask("Service Name")
    host = Prompt.ask("Host", default="localhost")
    port = Prompt.ask("Port", default="5432")
    dbname = Prompt.ask("Database Name")
    user = Prompt.ask("Username")
    password = Prompt.ask("Password", password=True)
    
    # Confirm
    console.print()
    console.print(f"[bold]Service Details:[/bold]")
    console.print(f"Service Name: {service_name}")
    console.print(f"Host: {host}")
    console.print(f"Port: {port}")
    console.print(f"Database: {dbname}")
    console.print(f"Username: {user}")
    console.print(f"Password: {'*' * len(password) if password else 'Not set'}")
    console.print()
    
    if not Confirm.ask("Add this service?", default=True):
        console.print("[yellow]Service not added.[/yellow]")
        console.print()
        Prompt.ask("Press Enter to return to the pg_service.conf menu")
        return
    
    try:
        # Read existing content
        content = ""
        if pg_service_path.exists():
            with open(pg_service_path, 'r') as f:
                content = f.read()
        
        # Add new service
        with open(pg_service_path, 'w') as f:
            f.write(content)
            if content and not content.endswith('\n\n'):
                f.write('\n\n')
            
            f.write(f"[{service_name}]\n")
            f.write(f"host={host}\n")
            f.write(f"port={port}\n")
            f.write(f"dbname={dbname}\n")
            f.write(f"user={user}\n")
            f.write(f"password={password}\n")
            
            # Add sslmode if not localhost
            if host != "localhost" and host != "127.0.0.1":
                f.write("sslmode=require\n")
        
        console.print("[green]Service added successfully![/green]")
        
        # Log the action
        logger.info(f"Added new service: {service_name} for database {dbname} on {host}")
        
        # Display the service details
        console.print()
        console.print("[bold]Service Details:[/bold]")
        console.print(f"Service: [cyan]{service_name}[/cyan]")
        console.print(f"Host: [cyan]{host}[/cyan]")
        console.print(f"Port: [cyan]{port}[/cyan]")
        console.print(f"Database: [cyan]{dbname}[/cyan]")
        console.print(f"Username: [cyan]{user}[/cyan]")
        console.print("Password: [cyan]********[/cyan]")
        
        # Wait for user to acknowledge before returning to the pg_service.conf menu
        console.print()
        Prompt.ask("Press Enter to return to the pg_service.conf menu")
    except Exception as e:
        console.print(f"[red]Error adding service: {e}[/red]")
        logger.error(f"Error adding service: {e}")

def edit_service(pg_service_path):
    """Edit an existing service in pg_service.conf"""
    console.print()
    console.print("[bold]Edit Existing Service:[/bold]")
    
    # Convert string path to Path object if needed
    if isinstance(pg_service_path, str):
        pg_service_path = pathlib.Path(pg_service_path)
    
    if not pg_service_path.exists():
        console.print("[yellow]pg_service.conf not found![/yellow]")
        return
    
    try:
        parser = PgServiceConfigParser(pg_service_path)
        services = parser.get_services()
        
        if not services:
            console.print("[yellow]No services found in pg_service.conf[/yellow]")
            return
        
        # Display available services
        console.print("[bold]Available Services:[/bold]")
        for i, service in enumerate(services, 1):
            console.print(f"{i}. {service.name} ({service.dbname})")
        console.print(f"{len(services) + 1}. Cancel")
        console.print()
        
        # Get service selection
        choice = Prompt.ask(
            "Select a service to edit", 
            choices=[str(i) for i in range(1, len(services) + 2)],
            default="1"
        )
        
        if int(choice) == len(services) + 1:
            return
        
        selected_service = services[int(choice) - 1]
        
        # Display current settings
        console.print()
        console.print(f"[bold]Current Settings for {selected_service.name}:[/bold]")
        console.print(f"Host: [cyan]{selected_service.host}[/cyan]")
        console.print(f"Port: [cyan]{selected_service.port}[/cyan]")
        console.print(f"Database: [cyan]{selected_service.dbname}[/cyan]")
        console.print(f"Username: [cyan]{selected_service.user}[/cyan]")
        console.print()
        
        # Get new settings
        host = Prompt.ask("Host", default=selected_service.host)
        port = Prompt.ask("Port", default=selected_service.port)
        dbname = Prompt.ask("Database Name", default=selected_service.dbname)
        user = Prompt.ask("Username", default=selected_service.user)
        
        change_password = Confirm.ask("Change password?", default=False)
        password = selected_service.password
        if change_password:
            password = Prompt.ask("Password", password=True)
        
        # Confirm
        console.print()
        console.print("[bold]New Settings:[/bold]")
        console.print(f"Host: [cyan]{host}[/cyan]")
        console.print(f"Port: [cyan]{port}[/cyan]")
        console.print(f"Database: [cyan]{dbname}[/cyan]")
        console.print(f"Username: [cyan]{user}[/cyan]")
        console.print()
        
        if Confirm.ask("Save these changes?", default=True):
            try:
                # Read the file
                with open(pg_service_path, 'r') as f:
                    lines = f.readlines()
                
                # Find and update the service
                in_service = False
                updated_lines = []
                
                for line in lines:
                    if line.strip() == f"[{selected_service.name}]":
                        in_service = True
                        updated_lines.append(line)
                    elif in_service and line.strip().startswith('['):
                        # We've reached the next service
                        in_service = False
                        updated_lines.append(line)
                    elif in_service:
                        # Update the service parameters
                        if line.strip().startswith('host='):
                            updated_lines.append(f"host={host}\n")
                        elif line.strip().startswith('port='):
                            updated_lines.append(f"port={port}\n")
                        elif line.strip().startswith('dbname='):
                            updated_lines.append(f"dbname={dbname}\n")
                        elif line.strip().startswith('user='):
                            updated_lines.append(f"user={user}\n")
                        elif line.strip().startswith('password='):
                            updated_lines.append(f"password={password}\n")
                        else:
                            updated_lines.append(line)
                    else:
                        updated_lines.append(line)
                
                # Write back to the file
                with open(pg_service_path, 'w') as f:
                    f.writelines(updated_lines)
                
                console.print("[green]Service updated successfully![/green]")
                
                # Log the action
                logger.info(f"Updated service: {selected_service.name} for database {dbname} on {host}")
            except Exception as e:
                console.print(f"[red]Error updating service: {e}[/red]")
                logger.error(f"Error updating service: {e}")
    except Exception as e:
        console.print(f"[red]Error reading pg_service.conf: {e}[/red]")

def create_pg_service_conf():
    """Create a new pg_service.conf file"""
    console.print()
    console.print("[bold]Create New pg_service.conf:[/bold]")
    
    # Get location for the new file
    console.print("[bold]Select Location:[/bold]")
    console.print("1. Current Directory")
    console.print("2. User Home Directory")
    console.print("3. Custom Path")
    console.print("4. Cancel")
    console.print()
    
    choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4"], default="1")
    
    if choice == "4":
        return
    
    if choice == "1":
        path = pathlib.Path.cwd() / "pg_service.conf"
    elif choice == "2":
        path = pathlib.Path.home() / ".pg_service.conf"
    else:  # choice == "3"
        custom_path = Prompt.ask("Enter path for pg_service.conf")
        path = pathlib.Path(custom_path)
    
    # Check if file already exists
    if path.exists():
        if not Confirm.ask(f"File already exists at {path}. Overwrite?", default=False):
            return
    
    # Create parent directories if needed
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Create the file
    try:
        with open(path, 'w') as f:
            f.write("# PostgreSQL service configuration file\n")
            f.write("# Created by PostgreSQL Database Permissions Audit Tool\n")
            f.write("# Format: [service_name]\n")
            f.write("# host=hostname\n")
            f.write("# port=5432\n")
            f.write("# dbname=database_name\n")
            f.write("# user=username\n")
            f.write("# password=password\n")
            f.write("# sslmode=require  # For remote connections\n\n")
        
        console.print(f"[green]Created pg_service.conf at: {path}[/green]")
        console.print("You can now add services to this file.")
        
        # Log the action
        logger.info(f"Created new pg_service.conf at: {path}")
        
        # Ask if they want to add a service now
        if Confirm.ask("Add a service now?", default=True):
            add_service(path)
    except Exception as e:
        console.print(f"[red]Error creating file: {e}[/red]")
        logger.error(f"Error creating pg_service.conf: {e}")

def configure_audit_settings():
    ensure_directories_exist()
    """Configure audit settings"""
    display_header()
    console.print("[bold]Configure Audit Settings[/bold]")
    console.print()
    
    # Load current settings
    settings = load_settings()
    
    console.print("[bold]Current Settings:[/bold]")
    console.print(f"Default Risk Level: [cyan]{settings.get('default_risk_level', 'all')}[/cyan]")
    console.print(f"Default Output Format: [cyan]{settings.get('default_output_format', 'text')}[/cyan]")
    console.print(f"Log Results: [cyan]{settings.get('log_results', True)}[/cyan]")
    console.print()
    
    console.print("[bold]Options:[/bold]")
    console.print("1. Change Default Risk Level")
    console.print("2. Change Default Output Format")
    console.print("3. Toggle Result Logging")
    console.print("4. Return to Main Menu")
    console.print()
    
    choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4"], default="1")
    
    if choice == "1":
        change_risk_level(settings)
    elif choice == "2":
        change_output_format(settings)
    elif choice == "3":
        toggle_logging(settings)
    
    # Return to main menu
    if choice != "4":
        Prompt.ask("Press Enter to return to the settings menu")
        configure_audit_settings()

def load_settings():
    """Load settings from file"""
    settings_path = pathlib.Path("config/audit_settings.py")
    
    default_settings = {
        "default_risk_level": "all",
        "default_output_format": "text",
        "log_results": True
    }
    
    if not settings_path.exists():
        # Create default settings file
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        save_settings(default_settings)
        return default_settings
    
    try:
        # Load settings from file
        settings = {}
        with open(settings_path, 'r') as f:
            for line in f:
                if '=' in line and not line.strip().startswith('#'):
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')
                    
                    # Convert string to boolean for log_results
                    if key == "log_results":
                        value = value.lower() == "true"
                    
                    settings[key] = value
        
        return settings
    except Exception as e:
        logger.error(f"Error loading settings: {e}")
        return default_settings

def save_settings(settings):
    """Save settings to file"""
    settings_path = pathlib.Path("config/audit_settings.py")
    
    try:
        with open(settings_path, 'w') as f:
            f.write("# PostgreSQL Database Permissions Audit Tool Settings\n\n")
            
            for key, value in settings.items():
                if isinstance(value, bool):
                    f.write(f"{key} = {str(value)}\n")
                else:
                    f.write(f'{key} = "{value}"\n')
        
        logger.info("Settings saved successfully")
    except Exception as e:
        logger.error(f"Error saving settings: {e}")

def change_risk_level(settings):
    """Change the default risk level"""
    console.print()
    console.print("[bold]Change Default Risk Level:[/bold]")
    console.print("1. High (only critical issues)")
    console.print("2. Medium (critical and moderate issues)")
    console.print("3. Low (all issues including informational)")
    console.print("4. All (include all findings)")
    console.print()
    
    choice = Prompt.ask("Select default risk level", choices=["1", "2", "3", "4"], default="4")
    risk_levels = {
        "1": "high",
        "2": "medium",
        "3": "low",
        "4": "all"
    }
    risk_level = risk_levels[choice]
    
    settings["default_risk_level"] = risk_level
    save_settings(settings)
    
    console.print(f"[green]Default risk level set to: {risk_level}[/green]")

def change_output_format(settings):
    """Change the default output format"""
    console.print()
    console.print("[bold]Change Default Output Format:[/bold]")
    console.print("1. Text (human-readable)")
    console.print("2. JSON (machine-readable)")
    console.print()
    
    choice = Prompt.ask("Select default output format", choices=["1", "2"], default="1")
    output_format = "text" if choice == "1" else "json"
    
    settings["default_output_format"] = output_format
    save_settings(settings)
    
    console.print(f"[green]Default output format set to: {output_format}[/green]")

def toggle_logging(settings):
    """Toggle result logging"""
    current = settings.get("log_results", True)
    new_value = not current
    
    settings["log_results"] = new_value
    save_settings(settings)
    
    status = "enabled" if new_value else "disabled"
    console.print(f"[green]Result logging {status}[/green]")

def view_previous_results():
    ensure_directories_exist()
    """View previous audit results"""
    display_header()
    console.print("[bold]View Previous Audit Results[/bold]")
    console.print()
    
    # Check for log file
    log_file = pathlib.Path("data/logs/dbaudit_results.log")
    if not log_file.exists():
        console.print("[yellow]No previous audit results found[/yellow]")
        Prompt.ask("Press Enter to return to the main menu")
        return
    
    # Check for result files
    result_files = list(pathlib.Path.cwd().glob("audit_*.txt")) + list(pathlib.Path.cwd().glob("audit_*.json"))
    
    if not result_files:
        console.print("[yellow]No audit result files found[/yellow]")
        console.print("You can still view the log file.")
    else:
        console.print("[bold]Available Result Files:[/bold]")
        for i, file in enumerate(result_files, 1):
            console.print(f"{i}. {file.name}")
    
    console.print()
    console.print("[bold]Options:[/bold]")
    console.print("1. View Log File")
    if result_files:
        console.print("2. View Result File")
    console.print(f"{'3' if result_files else '2'}. Return to Main Menu")
    console.print()
    
    max_choice = 3 if result_files else 2
    choice = Prompt.ask("Select an option", choices=[str(i) for i in range(1, max_choice + 1)], default="1")
    
    if choice == "1":
        view_log_file(log_file)
    elif choice == "2" and result_files:
        view_result_file(result_files)
    
    if choice != str(max_choice):
        Prompt.ask("Press Enter to return to the results menu")
        view_previous_results()

def view_log_file(log_file):
    """View the log file"""
    console.print()
    console.print("[bold]Log File Contents:[/bold]")
    console.print()
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        # Display the last 20 lines by default
        num_lines = min(20, len(lines))
        
        console.print(f"[italic]Showing last {num_lines} lines of log file[/italic]")
        console.print()
        
        for line in lines[-num_lines:]:
            console.print(line.strip())
    except Exception as e:
        console.print(f"[red]Error reading log file: {e}[/red]")

def view_result_file(result_files):
    """View a result file"""
    console.print()
    console.print("[bold]Select Result File:[/bold]")
    
    for i, file in enumerate(result_files):
        file_name = os.path.basename(file)
        file_time = dt.fromtimestamp(os.path.getmtime(file)).strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"{i+1}. {file_name} (Created: {file_time})")
    console.print(f"{len(result_files) + 1}. Cancel")
    console.print()
    
    choice = Prompt.ask(
        "Select a file to view", 
        choices=[str(i) for i in range(1, len(result_files) + 2)],
        default="1"
    )
    
    if int(choice) == len(result_files) + 1:
        return
    
    selected_file = result_files[int(choice) - 1]
    
    console.print()
    console.print(f"[bold]Contents of {selected_file.name}:[/bold]")
    console.print()
    
    try:
        with open(selected_file, 'r') as f:
            content = f.read()
        
        console.print(content)
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")

def backup_and_restore_menu():
    ensure_directories_exist()
    """Menu for backup and restore"""
    display_header()
    console.print("[bold]Backup and Restore Databases[/bold]")
    console.print()
    
    console.print("[bold]Options:[/bold]")
    console.print("1. Backup Database")
    console.print("2. Restore Database to Same Service")
    console.print("3. Restore Database to New Service")
    console.print("4. List Available Backups")
    console.print("5. Delete Backup")
    console.print("6. Create New Service")
    console.print("7. Return to Main Menu")
    console.print()
    
    choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6", "7"], default="1")
    
    if choice == "1":
        backup_database()
    elif choice == "2":
        restore_database(same_service=True)
    elif choice == "3":
        restore_database(same_service=False)
    elif choice == "4":
        list_backups()
    elif choice == "5":
        delete_backup()
    elif choice == "6":
        create_new_service()
    
    if choice != "7":
        Prompt.ask("Press Enter to return to the backup and restore menu")
        backup_and_restore_menu()

def create_new_service():
    """Create a new PostgreSQL service configuration"""
    console.print()
    console.print("[bold]Create New PostgreSQL Service:[/bold]")
    
    # Get service details
    service_name = Prompt.ask("Service Name")
    host = Prompt.ask("Host", default="localhost")
    port = Prompt.ask("Port", default="5432")
    dbname = Prompt.ask("Database Name")
    user = Prompt.ask("Username")
    
    # Ask for password (optional)
    include_password = Confirm.ask("Include password in configuration?", default=False)
    password = None
    if include_password:
        password = Prompt.ask("Password", password=True)
    
    # Create service config
    try:
        pg_service_parser = PgServiceConfigParser()
        pg_service_parser.add_service(
            service_name,
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password
        )
        
        console.print(f"[green]Service '{service_name}' created successfully![/green]")
        logger.info(f"Created new service: {service_name}")
        
        # Display the service details
        console.print()
        console.print("[bold]Service Details:[/bold]")
        console.print(f"Service: [cyan]{service_name}[/cyan]")
        console.print(f"Host: [cyan]{host}[/cyan]")
        console.print(f"Port: [cyan]{port}[/cyan]")
        console.print(f"Database: [cyan]{dbname}[/cyan]")
        console.print(f"Username: [cyan]{user}[/cyan]")
        if include_password:
            console.print("Password: [cyan]********[/cyan]")
        
        # Wait for user to acknowledge before returning to the backup and restore menu
        console.print()
        Prompt.ask("Press Enter to return to the backup and restore menu")
        
        return True
    except Exception as e:
        console.print(f"[red]Error creating service: {e}[/red]")
        logger.error(f"Error creating service: {e}")
        
        # Wait for user to acknowledge before returning to the backup and restore menu
        console.print()
        Prompt.ask("Press Enter to return to the backup and restore menu")
        
        return False

def backup_database():
    """Backup a database"""
    console.print()
    console.print("[bold]Backup Database:[/bold]")
    
    # Get available services
    pg_service_parser = PgServiceConfigParser()
    pg_services = pg_service_parser.get_services()
    
    if not pg_services:
        console.print("[yellow]No services found in pg_service.conf[/yellow]")
        if Confirm.ask("Would you like to create a new service?", default=True):
            create_new_service()
        else:
            console.print()
            Prompt.ask("Press Enter to return to the backup and restore menu")
        return
    
    # Display available services
    console.print("[bold]Available Services:[/bold]")
    for i, service in enumerate(pg_services, 1):
        console.print(f"{i}. {service.name} ({service.dbname})")
    console.print(f"{len(pg_services) + 1}. Cancel")
    console.print()
    
    # Get service selection
    choice = Prompt.ask(
        "Select a service", 
        choices=[str(i) for i in range(1, len(pg_services) + 2)],
        default="1"
    )
    
    if int(choice) == len(pg_services) + 1:
        return
    
    selected_service = pg_services[int(choice) - 1]
    
    # Get backup type
    console.print()
    console.print("[bold]Backup Type:[/bold]")
    console.print("1. Full Backup (schema, data, and permissions)")
    console.print("2. Schema Only (structure without data)")
    console.print("3. Permissions Only (roles and grants)")
    console.print()
    
    backup_choice = Prompt.ask("Select backup type", choices=["1", "2", "3"], default="1")
    backup_types = {
        "1": "full",
        "2": "schema",
        "3": "permissions"
    }
    backup_type = backup_types[backup_choice]
    
    # Get custom name (optional)
    console.print()
    use_custom_name = Confirm.ask("Use custom name for backup?", default=False)
    custom_name = None
    if use_custom_name:
        custom_name = Prompt.ask("Enter custom name")
    
    # Confirm
    console.print()
    console.print("[bold]Backup Configuration:[/bold]")
    console.print(f"Service: [cyan]{selected_service.name}[/cyan]")
    console.print(f"Database: [cyan]{selected_service.dbname}[/cyan]")
    console.print(f"Backup Type: [cyan]{backup_type}[/cyan]")
    if custom_name:
        console.print(f"Custom Name: [cyan]{custom_name}[/cyan]")
    console.print()
    
    if Confirm.ask("Proceed with backup?", default=True):
        try:
            # Initialize backup manager with selected service
            backup_manager = BackupManager(selected_service, console=console)
            
            # Create backup
            backup_info = backup_manager.create_backup(
                backup_type=backup_type,
                custom_name=custom_name
            )
            
            if backup_info:
                console.print("[green]Backup completed successfully![/green]")
                console.print(f"Backup ID: [cyan]{backup_info.id}[/cyan]")
                console.print(f"Backup File: [cyan]{backup_info.file_path}[/cyan]")
                console.print(f"Size: [cyan]{backup_info.size_bytes / 1024 / 1024:.2f} MB[/cyan]")
                
                logger.info(f"Created {backup_type} backup of {selected_service.name} with ID {backup_info.id}")
            else:
                console.print("[red]Backup failed![/red]")
        except Exception as e:
            console.print(f"[red]Error creating backup: {e}[/red]")
            logger.error(f"Error creating backup: {e}")
    
    # Wait for user to acknowledge before returning to the backup and restore menu
    console.print()
    Prompt.ask("Press Enter to return to the backup and restore menu")

def list_backups():
    """List available backups"""
    console.print()
    console.print("[bold]Available Backups:[/bold]")
    
    # Get available services
    pg_service_parser = PgServiceConfigParser()
    pg_services = pg_service_parser.get_services()
    
    if not pg_services:
        console.print("[yellow]No services found in pg_service.conf[/yellow]")
        console.print()
        Prompt.ask("Press Enter to return to the backup and restore menu")
        return
    
    # Select a service to view backups for
    console.print("[bold]Select a service to view backups for:[/bold]")
    for i, service in enumerate(pg_services, 1):
        console.print(f"{i}. {service.name} ({service.dbname})")
    console.print(f"{len(pg_services) + 1}. All services")
    console.print(f"{len(pg_services) + 2}. Cancel")
    console.print()
    
    choice = Prompt.ask(
        "Select a service", 
        choices=[str(i) for i in range(1, len(pg_services) + 3)],
        default="1"
    )
    
    if int(choice) == len(pg_services) + 2:
        return
    
    # Initialize backup manager with the first service (just to access backup history)
    backup_manager = BackupManager(pg_services[0], console=console)
    backups = backup_manager.list_backups()
    
    if not backups:
        console.print("[yellow]No backups found[/yellow]")
        console.print()
        Prompt.ask("Press Enter to return to the backup and restore menu")
        return
    
    # Filter backups by service if needed
    if int(choice) <= len(pg_services):
        selected_service = pg_services[int(choice) - 1]
        backups = [b for b in backups if b.service == selected_service.name]
    
    # Display backups
    if not backups:
        console.print("[yellow]No backups found for the selected service[/yellow]")
        console.print()
        Prompt.ask("Press Enter to return to the backup and restore menu")
        return
    
    backup_table = Table(show_header=True)
    backup_table.add_column("ID", style="cyan")
    backup_table.add_column("Timestamp", style="green")
    backup_table.add_column("Service", style="blue")
    backup_table.add_column("Database", style="magenta")
    backup_table.add_column("Type", style="yellow")
    backup_table.add_column("Size", style="cyan")
    
    for backup in backups:
        backup_table.add_row(
            backup.id,
            backup.timestamp,
            backup.service,
            backup.database,
            backup.backup_type,
            f"{backup.size_bytes / 1024 / 1024:.2f} MB"
        )
    
    console.print(backup_table)
    
    # Wait for user to acknowledge before returning to the backup and restore menu
    console.print()
    Prompt.ask("Press Enter to return to the backup and restore menu")

def delete_backup():
    """Delete a backup"""
    console.print()
    console.print("[bold]Delete Backup:[/bold]")
    
    # Get available services
    pg_service_parser = PgServiceConfigParser()
    pg_services = pg_service_parser.get_services()
    
    if not pg_services:
        console.print("[yellow]No services found in pg_service.conf[/yellow]")
        return
    
    # Initialize backup manager with the first service (just to access backup history)
    backup_manager = BackupManager(pg_services[0], console=console)
    backups = backup_manager.list_backups()
    
    if not backups:
        console.print("[yellow]No backups found[/yellow]")
        return
    
    # Display backups
    backup_table = Table(show_header=True)
    backup_table.add_column("#", style="cyan")
    backup_table.add_column("ID", style="cyan")
    backup_table.add_column("Timestamp", style="green")
    backup_table.add_column("Service", style="blue")
    backup_table.add_column("Database", style="magenta")
    backup_table.add_column("Type", style="yellow")
    
    for i, backup in enumerate(backups, 1):
        backup_table.add_row(
            str(i),
            backup.id,
            backup.timestamp,
            backup.service,
            backup.database,
            backup.backup_type
        )
    
    console.print(backup_table)
    console.print()
    
    # Get backup selection
    choice = Prompt.ask(
        "Select a backup to delete", 
        choices=[str(i) for i in range(1, len(backups) + 1)] + ["c"],
        default="1"
    )
    
    if choice.lower() == "c":
        return
    
    selected_backup = backups[int(choice) - 1]
    
    # Confirm
    console.print()
    console.print("[bold]Delete Confirmation:[/bold]")
    console.print(f"Backup ID: [cyan]{selected_backup.id}[/cyan]")
    console.print(f"Timestamp: [cyan]{selected_backup.timestamp}[/cyan]")
    console.print(f"Service: [cyan]{selected_backup.service}[/cyan]")
    console.print(f"Database: [cyan]{selected_backup.database}[/cyan]")
    console.print(f"Type: [cyan]{selected_backup.backup_type}[/cyan]")
    console.print()
    
    if Confirm.ask("Are you sure you want to delete this backup?", default=False):
        try:
            # Delete backup using the current backup_manager
            # We don't need to find the original service, as the backup files are stored locally
            success = backup_manager.delete_backup(backup_id=selected_backup.id)
            
            if success:
                console.print("[green]Backup deleted successfully![/green]")
                logger.info(f"Deleted backup {selected_backup.id}")
            else:
                console.print("[red]Failed to delete backup![/red]")
        except Exception as e:
            console.print(f"[red]Error deleting backup: {e}[/red]")
            logger.error(f"Error deleting backup: {e}")
    
    # Wait for user to acknowledge before returning to the backup and restore menu
    console.print()
    Prompt.ask("Press Enter to return to the backup and restore menu")

def restore_database(same_service=True):
    """Restore a database"""
    console.print()
    console.print("[bold]Restore Database:[/bold]")
    
    # Get available services
    pg_service_parser = PgServiceConfigParser()
    pg_services = pg_service_parser.get_services()
    
    if not pg_services:
        console.print("[yellow]No services found in pg_service.conf[/yellow]")
        if Confirm.ask("Would you like to create a new service?", default=True):
            create_new_service()
        return
    
    # Initialize backup manager with the first service (just to access backup history)
    backup_manager = BackupManager(pg_services[0], console=console)
    backups = backup_manager.list_backups()
    
    if not backups:
        console.print("[yellow]No backups found[/yellow]")
        return
    
    # Display backups
    backup_table = Table(show_header=True)
    backup_table.add_column("#", style="cyan")
    backup_table.add_column("ID", style="cyan")
    backup_table.add_column("Timestamp", style="green")
    backup_table.add_column("Service", style="blue")
    backup_table.add_column("Database", style="magenta")
    backup_table.add_column("Type", style="yellow")
    
    for i, backup in enumerate(backups, 1):
        backup_table.add_row(
            str(i),
            backup.id,
            backup.timestamp,
            backup.service,
            backup.database,
            backup.backup_type
        )
    
    console.print(backup_table)
    console.print()
    
    # Get backup selection
    choice = Prompt.ask(
        "Select a backup to restore", 
        choices=[str(i) for i in range(1, len(backups) + 1)] + ["c"],
        default="1"
    )
    
    if choice.lower() == "c":
        console.print()
        Prompt.ask("Press Enter to return to the backup and restore menu")
        return
    
    selected_backup = backups[int(choice) - 1]
    
    # If restoring to same service, use the service from the backup
    if same_service:
        # Find the service that matches the backup
        target_pg_service = None
        for service in pg_services:
            if service.name == selected_backup.service:
                target_pg_service = service
                break
        
        if not target_pg_service:
            console.print(f"[yellow]Warning: Original service '{selected_backup.service}' not found in pg_service.conf[/yellow]")
            console.print("Please select a different service to restore to.")
            same_service = False
    
    # If not restoring to same service or original service not found, select a target service
    if not same_service:
        console.print()
        console.print("[bold]Select Target Service:[/bold]")
        
        service_table = Table(show_header=True)
        service_table.add_column("#", style="cyan")
        service_table.add_column("Service", style="green")
        service_table.add_column("Host", style="blue")
        service_table.add_column("Database", style="magenta")
        
        for i, service in enumerate(pg_services, 1):
            service_table.add_row(
                str(i), 
                service.name, 
                f"{service.host}:{service.port}", 
                service.dbname
            )
        
        console.print(service_table)
        console.print()
        console.print(f"{len(pg_services) + 1}. Create New Service")
        console.print()
        
        service_choice = Prompt.ask(
            "Select a service to restore to", 
            choices=[str(i) for i in range(1, len(pg_services) + 2)],
            default="1"
        )
        
        if int(service_choice) == len(pg_services) + 1:
            # Create new service
            create_new_service()
            console.print()
            Prompt.ask("Press Enter to return to the backup and restore menu")
            return
        
        target_pg_service = pg_services[int(service_choice) - 1]
    
    # Use the target_pg_service directly as it's already a ServiceConfig object
    target_service = target_pg_service
    
    # Ask if the database needs to be created
    create_db = False
    if not same_service:
        create_db = Confirm.ask(f"Create database '{target_service.dbname}' if it doesn't exist?", default=True)
    
    # Confirm
    console.print()
    console.print("[bold]Restore Configuration:[/bold]")
    console.print(f"Backup ID: [cyan]{selected_backup.id}[/cyan]")
    console.print(f"Backup Service: [cyan]{selected_backup.service}[/cyan]")
    console.print(f"Backup Database: [cyan]{selected_backup.database}[/cyan]")
    console.print(f"Target Service: [cyan]{target_service.name}[/cyan]")
    console.print(f"Target Database: [cyan]{target_service.dbname}[/cyan]")
    if create_db:
        console.print(f"[cyan]Will create database if it doesn't exist[/cyan]")
    console.print()
    
    if Confirm.ask("Proceed with restore?", default=False):
        try:
            # Create database if needed
            if create_db:
                console.print(f"[bold]Checking if database '{target_service.dbname}' exists...[/bold]")
                
                # Connect to postgres database to check if target database exists
                postgres_service = ServiceConfig(
                    host=target_service.host,
                    port=target_service.port,
                    dbname="postgres",  # Connect to postgres database
                    user=target_service.user,
                    password=target_service.password
                )
                # Add name attribute for compatibility
                postgres_service.name = target_service.name
                
                # Use psycopg to check if database exists and create it if needed
                try:
                    import psycopg
                    
                    # Create connection string
                    conn_string = f"host={postgres_service.host} port={postgres_service.port} dbname=postgres user={postgres_service.user}"
                    if postgres_service.password:
                        conn_string += f" password={postgres_service.password}"
                    
                    # Connect to postgres database
                    conn = psycopg.connect(conn_string)
                    conn.autocommit = True
                    cursor = conn.cursor()
                    
                    # Check if database exists
                    cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target_service.dbname,))
                    exists = cursor.fetchone()
                    
                    if not exists:
                        console.print(f"[yellow]Database '{target_service.dbname}' does not exist. Creating...[/yellow]")
                        
                        # Create database
                        cursor.execute(f"CREATE DATABASE {target_service.dbname}")
                        
                        console.print(f"[green]Database '{target_service.dbname}' created successfully![/green]")
                    else:
                        console.print(f"[green]Database '{target_service.dbname}' already exists.[/green]")
                    
                    # Close connection
                    cursor.close()
                    conn.close()
                    
                except Exception as e:
                    console.print(f"[red]Error checking/creating database: {e}[/red]")
                    logger.error(f"Error checking/creating database: {e}")
                    if not Confirm.ask("Continue with restore anyway?", default=False):
                        console.print()
                        Prompt.ask("Press Enter to return to the backup and restore menu")
                        return
            
            # Initialize backup manager with target service
            restore_manager = BackupManager(target_service, console=console)
            
            # Restore backup
            success = restore_manager.restore_backup(backup_id=selected_backup.id)
            
            if success:
                console.print("[green]Restore completed successfully![/green]")
                logger.info(f"Restored backup {selected_backup.id} to {target_service.name}")
            else:
                console.print("[red]Restore failed![/red]")
        except Exception as e:
            console.print(f"[red]Error restoring database: {e}[/red]")
            logger.error(f"Error restoring database: {e}")
    
    # Wait for user to acknowledge before returning to the backup and restore menu
    console.print()
    Prompt.ask("Press Enter to return to the backup and restore menu")

def generate_html_reports():
    ensure_directories_exist()
    """Generate HTML reports from audit results using Jinja2"""
    display_header()
    console.print("[bold]Generate HTML Reports[/bold]")
    console.print()
    
    # Check for audit result files in the data/audit_results directory
    result_files = []
    audit_results_dir = os.path.join("data", "audit_results")
    
    # Ensure the directories exist
    if not os.path.exists(audit_results_dir):
        os.makedirs(audit_results_dir, exist_ok=True)
    
    # Look for audit files in data/audit_results
    for file in os.listdir(audit_results_dir):
        if file.startswith("audit_") and (file.endswith(".txt") or file.endswith(".json")):
            result_files.append(os.path.join(audit_results_dir, file))
    
    # Also look for audit files in the root directory (for backward compatibility)
    for file in os.listdir():
        if file.startswith("audit_") and (file.endswith(".txt") or file.endswith(".json")):
            result_files.append(file)
    
    # Also look for audit files in the reports directory
    reports_dir = os.path.join("reports")
    if os.path.exists(reports_dir):
        for file in os.listdir(reports_dir):
            if file.startswith("audit_") and (file.endswith(".txt") or file.endswith(".json")):
                result_files.append(os.path.join(reports_dir, file))
    
    if not result_files:
        console.print("[yellow]No audit result files found in the data/audit_results directory.[/yellow]")
        console.print("[yellow]Run an audit first to generate results.[/yellow]")
        Prompt.ask("Press Enter to return to the main menu")
        return
    
    # Sort files by modification time (newest first)
    result_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    
    # Display available audit files
    console.print("[bold]Available Audit Result Files:[/bold]")
    for i, file in enumerate(result_files):
        file_name = os.path.basename(file)
        file_time = dt.fromtimestamp(os.path.getmtime(file)).strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"{i+1}. {file_name} (Created: {file_time})")
    console.print()
    choice = Prompt.ask("Select a file to generate an HTML report (or 'q' to quit)", default="1")
    
    if choice.lower() == 'q':
        return
    
    try:
        file_index = int(choice) - 1
        if file_index < 0 or file_index >= len(result_files):
            console.print("[red]Invalid selection[/red]")
            Prompt.ask("Press Enter to return to the main menu")
            return
        
        selected_file = result_files[file_index]
        
        # Check if it's a JSON file
        if selected_file.endswith(".json"):
            # Use the JSON file directly
            audit_file = selected_file
        else:
            # For text files, parse and convert to JSON
            with open(selected_file, 'r') as f:
                content = f.read()
            
            # Parse text content into structured data
            json_data = {}
            current_section = None
            current_recommendation = {}
            recommendations = []
            
            # Extract database name from filename
            file_name = os.path.basename(selected_file)
            db_name_match = re.search(r'audit_([^_]+)', file_name)
            if db_name_match:
                json_data["database"] = db_name_match.group(1)
            
            # Add timestamp
            json_data["timestamp"] = dt.now().isoformat()
            
            # Parse the text file
            for line in content.split('\n'):
                line = line.strip()
                
                if line.startswith("Database:"):
                    json_data["database"] = line.split(":", 1)[1].strip()
                
                elif line.startswith("Date:"):
                    # Already have timestamp
                    pass
                
                elif line == "SUPERUSER ROLES":
                    current_section = "roles"
                    json_data["roles"] = []
                
                elif line == "DANGEROUS PERMISSIONS":
                    current_section = "permissions"
                    json_data["dangerous_permissions"] = []
                
                elif line == "RECOMMENDATIONS":
                    current_section = "recommendations"
                    json_data["recommendations"] = []
                
                elif current_section == "roles" and line.startswith("- "):
                    role_name = line[2:].strip()
                    json_data["roles"].append({
                        "name": role_name,
                        "is_superuser": True
                    })
                
                elif current_section == "permissions" and line.startswith("- "):
                    # Parse permission line
                    # Format: "- TYPE NAME: PRIVILEGE granted to GRANTEE (Risk: LEVEL)"
                    perm_match = re.search(r'- (\w+) ([^:]+): (\w+) granted to (\w+) \(Risk: (\w+)\)', line)
                    if perm_match:
                        obj_type, name, privilege, grantee, risk = perm_match.groups()
                        json_data["dangerous_permissions"].append({
                            "type": obj_type,
                            "name": name.strip(),
                            "privilege": privilege,
                            "grantee": grantee,
                            "risk_level": risk.lower()
                        })
                
                elif current_section == "recommendations" and line.startswith("- "):
                    # Save previous recommendation if exists
                    if current_recommendation:
                        recommendations.append(current_recommendation)
                        current_recommendation = {}
                    
                    # Parse new recommendation
                    recommendation_text = line[2:].strip()
                    current_recommendation = {
                        "title": recommendation_text,
                        "details": []
                    }
                
                elif current_section == "recommendations" and line.startswith("  "):
                    # Add detail to current recommendation
                    if current_recommendation:
                        current_recommendation["details"].append(line.strip())
            
            # Add the last recommendation if exists
            if current_recommendation:
                recommendations.append(current_recommendation)
            
            if recommendations:
                json_data["recommendations"] = recommendations
            
            # Save as JSON file
            json_file = os.path.splitext(selected_file)[0] + ".json"
            with open(json_file, 'w') as f:
                json.dump(json_data, f, indent=2)
            
            audit_file = json_file
        
        # Generate HTML report
        from utils.reports import ReportGenerator
        report_gen = ReportGenerator(console=console)
        report_path = report_gen.generate_html_report(audit_file)
        
        if report_path:
            # Ask if user wants to open the report
            open_report = Prompt.ask("Open the report in your browser?", choices=["y", "n"], default="y")
            if open_report.lower() == "y":
                report_gen.open_report(report_path)
        else:
            console.print("[red]Failed to generate HTML report[/red]")
    
    except Exception as e:
        console.print(f"[red]Error generating HTML report: {e}[/red]")
        if "--debug" in sys.argv:
            console.print_exception()
    
    console.print()
    Prompt.ask("Press Enter to return to the main menu")

def main():
    """Main function for the interactive menu"""
    while True:
        display_header()
        choice = display_main_menu()
        
        if choice == "1":
            run_audit_menu()
        elif choice == "2":
            manage_pg_service_menu()
        elif choice == "3":
            configure_audit_settings()
        elif choice == "4":
            view_previous_results()
        elif choice == "5":
            backup_and_restore_menu()
        elif choice == "6":
            generate_html_reports()
        elif choice == "7":
            console.print("[bold blue]Thank you for using PostgreSQL Database Permissions Audit Tool![/bold blue]")
            sys.exit(0)

if __name__ == "__main__":
    main()
