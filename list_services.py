#!/usr/bin/env python3
"""
Helper script to list all PostgreSQL services defined in pg_service.conf
"""

import os
import sys
import pathlib
from rich.console import Console
from rich.table import Table

from pg_service import PgServiceConfigParser

console = Console()

def main():
    """Main function to display PostgreSQL services"""
    console.print("\n[bold blue]PostgreSQL Services Available[/bold blue]")
    console.print("==================================\n")
    
    # Find pg_service.conf
    from dbaudit import find_pg_service_conf
    pg_service_path = find_pg_service_conf()
    
    try:
        # Parse the configuration file
        pg_service_parser = PgServiceConfigParser(pg_service_path)
        available_services = pg_service_parser.get_available_services()
        
        if not available_services:
            console.print("[yellow]No services found in pg_service.conf[/yellow]")
            console.print("Add service configurations to your pg_service.conf file first.")
            return 1
        
        # Create a table for display
        table = Table(show_header=True, header_style="bold")
        table.add_column("Service Name")
        table.add_column("Host")
        table.add_column("Port")
        table.add_column("Database")
        table.add_column("User")
        
        for service_name in sorted(available_services):
            config = pg_service_parser.get_service_config(service_name)
            table.add_row(
                service_name,
                config.host,
                config.port,
                config.dbname,
                config.user
            )
        
        console.print(table)
        console.print(f"\n[green]Found {len(available_services)} PostgreSQL service(s)[/green]")
        
        # Display usage instructions
        console.print("\n[bold]To audit a database:[/bold]")
        console.print(f"python dbaudit.py --service <service_name> audit")
        
        console.print("\n[bold]To create a backup before fixing permissions:[/bold]")
        console.print(f"python dbaudit.py --service <service_name> backup")
        
        console.print("\n[bold]To fix permissions:[/bold]")
        console.print(f"python dbaudit.py --service <service_name> fix")
        
        return 0
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
