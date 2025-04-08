#!/usr/bin/env python3
"""
PostgreSQL Database Permissions Audit Tool

A tool for auditing and managing PostgreSQL database permissions with backup
and restore capabilities. Uses pg_service.conf for authentication.
"""

import os
import sys
import json
import logging
import pathlib
import datetime
import click
from rich.console import Console
from rich.logging import RichHandler

from pg_service import PgServiceConfigParser, ServiceConfig
from utils.connection import PostgresConnection
from utils.audit import PermissionAuditor, PermissionRisk
from utils.backup import BackupManager
from utils.fixes import PermissionFixer

# Create necessary directories
def ensure_directories_exist():
    """Ensure that necessary directories exist and create required configuration files."""
    # Create directories
    directories = ['backups', 'config']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Create config/__init__.py
    config_init = os.path.join('config', '__init__.py')
    if not os.path.exists(config_init):
        with open(config_init, 'w') as f:
            f.write("# PostgreSQL Database Permissions Audit Tool Configuration\n")
    
    # Create config/audit_settings.py
    audit_settings = os.path.join('config', 'audit_settings.py')
    if not os.path.exists(audit_settings):
        with open(audit_settings, 'w') as f:
            f.write("""# PostgreSQL Database Permissions Audit Tool Settings

default_risk_level = "all"
default_output_format = "text"
log_results = True
""")
    
    # Create pg_service.conf if it doesn't exist
    pg_service_conf = 'pg_service.conf'
    if not os.path.exists(pg_service_conf):
        with open(pg_service_conf, 'w') as f:
            f.write("""# PostgreSQL Service Configuration File
# Format: [service_name]
#         host=hostname
#         port=port
#         dbname=database_name
#         user=username
#         password=password (optional)
""")

# Ensure directories exist at startup
ensure_directories_exist()

# Set PGSERVICEFILE environment variable to use the project directory's pg_service.conf
project_pg_service_path = os.path.abspath('pg_service.conf')
os.environ['PGSERVICEFILE'] = project_pg_service_path
logger = logging.getLogger("dbaudit")
logger.debug(f"Setting PGSERVICEFILE to: {project_pg_service_path}")

# Configure rich console for better output
console = Console()

# Configure logging with rich
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)
logger = logging.getLogger("dbaudit")

# Also set up file logging
file_handler = logging.FileHandler("dbaudit_results.log")
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Function to find pg_service.conf in various locations
def find_pg_service_conf():
    """
    Look for pg_service.conf in multiple locations in order:
    1. Current directory (highest priority)
    2. Config subdirectory
    3. PGSERVICEFILE environment variable if set
    4. APPDATA/postgresql directory on Windows
    5. ~/.pg_service.conf
    6. /etc/postgresql-common/pg_service.conf on Unix
    """
    # Check current directory (highest priority)
    current_dir = pathlib.Path(".")
    current_path = current_dir / "pg_service.conf"
    if current_path.exists():
        logger.debug(f"Using pg_service.conf from current directory: {current_path.resolve()}")
        return current_path
    
    # Check config subdirectory
    config_dir = current_dir / "config"
    config_path = config_dir / "pg_service.conf"
    if config_path.exists():
        logger.debug(f"Using pg_service.conf from config directory: {config_path.resolve()}")
        return config_path
    
    # Check environment variable
    pg_service_env = os.environ.get('PGSERVICEFILE')
    if pg_service_env:
        env_path = pathlib.Path(pg_service_env)
        if env_path.exists():
            logger.debug(f"Using pg_service.conf from PGSERVICEFILE env: {env_path}")
            return env_path
    
    # Platform specific checks
    if os.name == 'nt':  # Windows
        # Check APPDATA/postgresql directory
        appdata = os.environ.get('APPDATA')
        if appdata:
            appdata_path = pathlib.Path(appdata) / "postgresql" / "pg_service.conf"
            if appdata_path.exists():
                logger.debug(f"Using pg_service.conf from APPDATA: {appdata_path}")
                return appdata_path
    else:  # Unix-like systems
        # Check /etc/postgresql-common/
        etc_path = pathlib.Path("/etc/postgresql-common/pg_service.conf")
        if etc_path.exists():
            logger.debug(f"Using pg_service.conf from system directory: {etc_path}")
            return etc_path
    
    # Fall back to home directory
    home_dir = pathlib.Path.home()
    home_path = home_dir / ".pg_service.conf"  # Standard dot-prefixed location
    if home_path.exists():
        logger.debug(f"Using pg_service.conf from home directory: {home_path}")
        return home_path
    
    # Also check for non-dot-prefixed version in home
    alt_home_path = home_dir / "pg_service.conf"
    if alt_home_path.exists():
        logger.debug(f"Using pg_service.conf from home directory: {alt_home_path}")
        return alt_home_path
    
    # If we get here, we couldn't find the file
    # Return the default location in the current directory
    logger.warning("pg_service.conf not found in any standard location, using current directory")
    return current_path  # Return the current directory location even if it doesn't exist

# Function to get a database connection based on CLI parameters
def get_connection(ctx_obj):
    """Get database connection from context object"""
    service = ctx_obj.get("service")
    
    # If service name is provided, use pg_service.conf
    if service:
        pg_service_path = find_pg_service_conf()
        if not pg_service_path.exists():
            raise FileNotFoundError(
                f"pg_service.conf not found at {pg_service_path}. "
                "Please create this file or specify connection parameters directly."
            )
            
        try:
            pg_service_parser = PgServiceConfigParser(pg_service_path)
            service_config = pg_service_parser.get_service_config(service)
            
            # Store in context for other commands to use
            ctx_obj["service_config"] = service_config
            
            return PostgresConnection(service_config)
        except KeyError:
            available = ", ".join(pg_service_parser.get_available_services())
            raise KeyError(
                f"Service '{service}' not found in pg_service.conf. "
                f"Available services: {available or 'none'}"
            )
        except Exception as e:
            logger.error(f"Error connecting using service '{service}': {e}")
            raise
    
    # Otherwise, use individual connection parameters
    host = ctx_obj.get("host")
    port = ctx_obj.get("port", 5432)
    dbname = ctx_obj.get("dbname")
    username = ctx_obj.get("username")
    password = ctx_obj.get("password")
    
    # Validate required parameters
    missing = []
    if not host:
        missing.append("host")
    if not dbname:
        missing.append("dbname")
    if not username:
        missing.append("username")
    
    if missing:
        raise ValueError(
            f"Missing required connection parameters: {', '.join(missing)}. "
            "Please provide these parameters or use a service name."
        )
    
    # Create ServiceConfig manually
    service_config = ServiceConfig(
        host=host,
        port=str(port),
        dbname=dbname,
        user=username,
        password=password
    )
    
    # Store in context for other commands to use
    ctx_obj["service_config"] = service_config
    
    return PostgresConnection(service_config)

# Click group for command-line interface
@click.group(name="cli")
@click.option(
    "--service",
    help="Service name from pg_service.conf",
)
@click.option(
    "--host",
    help="Database server hostname",
)
@click.option(
    "--port",
    type=int,
    default=5432,
    help="Database server port",
)
@click.option(
    "--dbname",
    help="Database name",
)
@click.option(
    "--username",
    help="Database user",
)
@click.option(
    "--password",
    help="Database password",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show actions without executing them",
)
@click.option(
    "--risk-level",
    type=click.Choice(["all", "high", "medium", "low"]),
    default="all",
    help="Global risk level filter for audit results",
)
@click.pass_context
def cli(ctx, service, host, port, dbname, username, password, verbose, dry_run, risk_level):
    """PostgreSQL Database Permissions Audit Tool"""
    # Initialize context if needed
    ctx.ensure_object(dict)
    
    # Store connection parameters in context
    ctx.obj["service"] = service
    ctx.obj["host"] = host
    ctx.obj["port"] = port
    ctx.obj["dbname"] = dbname
    ctx.obj["username"] = username
    ctx.obj["password"] = password
    
    # Store execution parameters
    ctx.obj["verbose"] = verbose
    ctx.obj["dry_run"] = dry_run
    ctx.obj["risk_level"] = risk_level
    
    # Set up verbose logging if requested
    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")

@cli.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False),
    help="Export audit results to file",
)
@click.option(
    "--format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format for the report",
)
@click.option(
    "--risk-level",
    type=click.Choice(["all", "high", "medium", "low"]),
    default=None,
    help="Filter results by risk level (overrides global setting)",
)
@click.option(
    "--summary/--detailed",
    default=True,
    help="Show summary or detailed report",
)
@click.option(
    "--focus",
    type=click.Choice(["all", "roles", "schemas", "tables", "dangerous"]),
    default="all",
    help="Focus on specific object types",
)
@click.option('--verbose', is_flag=True, help='Enable verbose output')
@click.pass_context
def audit(ctx, output, format, risk_level, summary, focus, verbose):
    """Audit database permissions and generate a report"""
    # If command-line verbose flag is set, override context
    if verbose:
        ctx.obj['verbose'] = True
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")
    
    # Use risk_level from command line, or fall back to global setting
    if risk_level is None:
        risk_level = ctx.obj.get('risk_level', 'all')
    
    # Configure risk levels for filtering
    risk_levels = []
    if risk_level == 'high' or risk_level == 'all':
        risk_levels.append(PermissionRisk.HIGH)
    if risk_level == 'medium' or risk_level == 'all':
        risk_levels.append(PermissionRisk.MEDIUM)
    if risk_level == 'low' or risk_level == 'all':
        risk_levels.append(PermissionRisk.LOW)
    
    # Run the audit
    try:
        # Get connection
        conn_manager = get_connection(ctx.obj)
        
        # Ensure connection is open and stays open
        conn = conn_manager.connect()
        
        logger.info(f"Connecting to database using service: {ctx.obj.get('service', '')}")
        
        # Create auditor with the connection
        auditor = PermissionAuditor(conn, console=console)
        if ctx.obj.get('verbose', False):
            auditor.verbose = True
        
        logger.info(f"Starting permission audit for {ctx.obj.get('service', '')}...")
        
        # Run the audit with filtered risk levels
        audit_result = auditor.run_audit(risk_levels=risk_levels)
        
        # Filter by risk level if needed
        if risk_level != "all":
            if risk_level == "high":
                audit_result.dangerous_permissions = [
                    p for p in audit_result.dangerous_permissions 
                    if p["risk_level"] == "high"
                ]
            elif risk_level == "medium":
                audit_result.dangerous_permissions = [
                    p for p in audit_result.dangerous_permissions 
                    if p["risk_level"] == "medium"
                ]
            elif risk_level == "low":
                audit_result.dangerous_permissions = [
                    p for p in audit_result.dangerous_permissions 
                    if p["risk_level"] == "low"
                ]
        
        # Display results
        logger.info(f"Audit complete. Found {len(audit_result.dangerous_permissions)} potential security issues.")
        
        # Log detailed results
        high_risk = [p for p in audit_result.dangerous_permissions if p["risk_level"] == "high"]
        medium_risk = [p for p in audit_result.dangerous_permissions if p["risk_level"] == "medium"]
        low_risk = [p for p in audit_result.dangerous_permissions if p["risk_level"] == "low"]
        
        logger.info(f"High Risk Issues: {len(high_risk)}")
        logger.info(f"Medium Risk Issues: {len(medium_risk)}")
        logger.info(f"Low Risk Issues: {len(low_risk)}")
        
        # Log superusers
        superusers = [name for name, role in audit_result.roles.items() if role.is_superuser]
        logger.info(f"Superuser Roles: {', '.join(superusers)}")
        
        # Log top 5 high risk issues as examples
        if high_risk:
            logger.info("Sample High Risk Issues:")
            for i, issue in enumerate(high_risk[:5]):
                logger.info(f"  {i+1}. {issue['type']} {issue['name']}: {issue['privilege']} granted to {issue['grantee']}")
        
        # Display report to console
        if summary:
            console.print("\n[bold blue]AUDIT SUMMARY[/bold blue]")
            console.print("=" * 50)
            
            # Display superusers
            console.print("\n[bold]Superuser Roles:[/bold]")
            for role_name, role in audit_result.roles.items():
                if role.is_superuser:
                    console.print(f"  - {role_name}")
            
            # Display dangerous permissions by risk level
            high_risk = [p for p in audit_result.dangerous_permissions if p["risk_level"] == "high"]
            medium_risk = [p for p in audit_result.dangerous_permissions if p["risk_level"] == "medium"]
            low_risk = [p for p in audit_result.dangerous_permissions if p["risk_level"] == "low"]
            
            console.print(f"\n[bold]Permission Issues:[/bold]")
            console.print(f"  [bold red]High Risk:[/bold red] {len(high_risk)}")
            console.print(f"  [bold yellow]Medium Risk:[/bold yellow] {len(medium_risk)}")
            console.print(f"  [bold green]Low Risk:[/bold green] {len(low_risk)}")
            
            # Display focused information based on the focus parameter
            if focus != "all":
                console.print(f"\n[bold]Focus: {focus.upper()}[/bold]")
                if focus == "roles":
                    for role_name, role in audit_result.roles.items():
                        console.print(f"  - {role_name} (Superuser: {role.is_superuser})")
                elif focus == "schemas":
                    for schema_name, schema in audit_result.schemas.items():
                        console.print(f"  - {schema_name} (Owner: {schema.owner})")
                elif focus == "tables":
                    for table_name, table in audit_result.tables.items():
                        console.print(f"  - {table_name} (Owner: {table.owner})")
                elif focus == "dangerous":
                    for perm in audit_result.dangerous_permissions:
                        console.print(f"  - {perm['type']} {perm['name']}: {perm['privilege']} granted to {perm['grantee']} (Risk: {perm['risk_level']})")
        else:
            # Detailed report
            console.print("\n[bold blue]DETAILED AUDIT REPORT[/bold blue]")
            console.print("=" * 50)
            
            # Display all information
            console.print("\n[bold]Database Roles:[/bold]")
            for role_name, role in audit_result.roles.items():
                console.print(f"  - {role_name}")
                console.print(f"    Superuser: {role.is_superuser}")
                console.print(f"    Can login: {role.can_login}")
                console.print(f"    Can create DB: {role.can_create_db}")
                console.print(f"    Can create role: {role.can_create_role}")
                if role.member_of:
                    console.print(f"    Member of: {', '.join(role.member_of)}")
            
            console.print("\n[bold]Schemas:[/bold]")
            for schema_name, schema in audit_result.schemas.items():
                console.print(f"  - {schema_name} (Owner: {schema.owner})")
                if schema.permissions:
                    console.print("    Permissions:")
                    for grantee, privs in schema.permissions.items():
                        console.print(f"      {grantee}: {', '.join(privs)}")
            
            console.print("\n[bold]Tables with Dangerous Permissions:[/bold]")
            dangerous_tables = set(p["name"] for p in audit_result.dangerous_permissions if p["type"] == "table")
            for table_name in dangerous_tables:
                if table_name in audit_result.tables:
                    table = audit_result.tables[table_name]
                    console.print(f"  - {table_name} (Owner: {table.owner})")
                    if table.permissions:
                        console.print("    Permissions:")
                        for grantee, privs in table.permissions.items():
                            console.print(f"      {grantee}: {', '.join(privs)}")
        
        # Export if requested
        if output:
            try:
                # Export report to file
                with open(output, 'w') as f:
                    if format == "json":
                        # Export as JSON
                        report_data = {
                            "database": audit_result.database,
                            "timestamp": datetime.datetime.now().isoformat(),
                            "roles": [{"name": name, "is_superuser": role.is_superuser} 
                                     for name, role in audit_result.roles.items()],
                            "dangerous_permissions": audit_result.dangerous_permissions,
                            "schemas": [{"name": name, "owner": schema.owner} 
                                       for name, schema in audit_result.schemas.items()],
                            "tables": [{"name": name, "owner": table.owner} 
                                      for name, table in audit_result.tables.items()]
                        }
                        json.dump(report_data, f, indent=2)
                    else:
                        # Export as text
                        f.write(f"PostgreSQL Database Permissions Audit Report\n")
                        f.write(f"Database: {audit_result.database}\n")
                        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        
                        f.write("SUPERUSER ROLES\n")
                        f.write("==============\n")
                        for role_name, role in audit_result.roles.items():
                            if role.is_superuser:
                                f.write(f"- {role_name}\n")
                        
                        f.write("\nDANGEROUS PERMISSIONS\n")
                        f.write("====================\n")
                        for perm in audit_result.dangerous_permissions:
                            f.write(f"- {perm['type']} {perm['name']}: {perm['privilege']} granted to {perm['grantee']} (Risk: {perm['risk_level']})\n")
                
                logger.info(f"Report exported to {output}")
            except Exception as e:
                logger.error(f"Failed to export report: {e}")
                if ctx.obj.get('verbose'):
                    console.print_exception()
    
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        if ctx.obj.get('verbose'):
            console.print_exception()
        sys.exit(1)

@cli.command()
@click.option(
    "--id",
    "backup_id",
    help="ID of the backup to restore",
)
@click.option(
    "--file",
    "backup_file",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to backup file to restore from",
)
@click.option(
    "--backup-dir",
    "-d",
    help="Directory containing backups",
    default="./backups",
)
@click.option(
    "--no-confirm",
    is_flag=True,
    help="Skip confirmation prompt",
)
@click.pass_context
def restore(ctx, backup_id, backup_file, backup_dir, no_confirm):
    """Restore database from a backup
    
    Restores a PostgreSQL database from a previously created backup.
    You can specify either a backup ID (from the backup history) or
    the path to a backup file.
    
    CAUTION: This will overwrite data in the target database!
    """
    service = ctx.obj.get("service")
    if not service:
        logger.error("No service specified. Use --service option.")
        sys.exit(1)
    
    if not backup_id and not backup_file:
        console.print("[yellow]Please specify either --id or --file to restore a backup[/yellow]")
        console.print("Use the following command to list available backups:")
        console.print(f"  [bold]python dbaudit.py --service {service} backup --list[/bold]")
        return
    
    service_config = ctx.obj.get("service_config")
    dry_run = ctx.obj.get("dry_run", False)
    
    try:
        # Create backup manager
        backup_manager = BackupManager(service_config, backup_dir, console)
        
        # Get information about the backup being restored
        if backup_id:
            backup_info = backup_manager.get_backup_info(backup_id)
            if not backup_info:
                console.print(f"[bold red]Error:[/bold red] Backup ID '{backup_id}' not found")
                console.print("Use the following command to list available backups:")
                console.print(f"  [bold]python dbaudit.py --service {service} backup --list[/bold]")
                sys.exit(1)
            
            source = f"backup ID '{backup_id}'"
            target = f"database '{service_config.dbname}' on {service_config.host}"
        else:
            source = f"file '{backup_file}'"
            target = f"database '{service_config.dbname}' on {service_config.host}"
        
        # Confirm before proceeding
        if not no_confirm and not dry_run:
            console.print(f"[bold yellow]WARNING: You are about to restore {source} to {target}.[/bold yellow]")
            console.print("[bold red]This will overwrite existing data in the target database![/bold red]")
            
            confirm = click.confirm("Do you want to continue?", default=False)
            if not confirm:
                console.print("Restore operation cancelled.")
                return
        
        # Perform the restore
        logger.info(f"Restoring {source} to {target}...")
        
        if backup_manager.restore_backup(
            backup_id=backup_id, 
            backup_file=backup_file,
            dry_run=dry_run
        ):
            if not dry_run:
                console.print(f"[green]✓ Database restored successfully[/green]")
        else:
            console.print(f"[bold red]✗ Database restore failed[/bold red]")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Restore operation failed: {e}")
        if ctx.obj.get("verbose"):
            import traceback
            console.print_exception()
        sys.exit(1)

@cli.command()
@click.option(
    "--fix-type",
    type=click.Choice(["remove_dangerous", "apply_template", "restrict_public"]),
    default="remove_dangerous",
    help="Type of permission fix to apply",
)
@click.option(
    "--template",
    type=click.Choice(["read_only", "read_write", "developer", "admin"]),
    help="Permission template to apply (used with apply_template)",
)
@click.option(
    "--role",
    multiple=True,
    help="Target specific role(s) (can be specified multiple times)",
)
@click.option(
    "--auto",
    is_flag=True,
    help="Apply fixes automatically without confirmation (use with caution)",
)
@click.option(
    "--backup/--no-backup",
    default=True,
    help="Automatically create a backup before applying fixes",
)
@click.option(
    "--backup-type",
    type=click.Choice(["full", "schema"]),
    default="schema",
    help="Type of backup to create before fixing",
)
@click.option(
    "--export-scripts/--no-export-scripts",
    default=True,
    help="Export SQL scripts for fix and rollback",
)
@click.option(
    "--export-dir",
    type=click.Path(file_okay=False, dir_okay=True),
    default="./fixes",
    help="Directory to export SQL scripts to",
)
@click.pass_context
def fix(ctx, fix_type, template, role, auto, backup, backup_type, export_scripts, export_dir):
    """Fix permissions according to best practices or templates
    
    This command analyzes and fixes permission issues in the database.
    Several fix types are available:
    
    - remove_dangerous: Revoke dangerous permissions (DROP, TRUNCATE, etc.)
    - apply_template: Apply a predefined permission template
    - restrict_public: Restrict access to the public schema
    
    Permission templates:
    - read_only: Read-only access to all objects
    - read_write: Read-write without destructive permissions
    - developer: Developer access with some schema modification rights
    - admin: Admin access with all permissions except superuser
    
    By default, a backup is created before applying fixes, and
    SQL scripts are exported for both the fix and rollback operations.
    """
    service = ctx.obj.get("service")
    if not service:
        logger.error("No service specified. Use --service option.")
        sys.exit(1)
    
    service_config = ctx.obj.get("service_config")
    dry_run = ctx.obj.get("dry_run", False)
    
    # Validate template if using apply_template
    if fix_type == "apply_template" and not template:
        console.print("[bold red]Error:[/bold red] You must specify a --template when using apply_template")
        console.print("Available templates: read_only, read_write, developer, admin")
        sys.exit(1)
    
    try:
        # Create a backup first if requested
        backup_id = None
        if backup and not dry_run:
            from utils.backup import BackupManager
            
            console.print(f"\n[bold]Creating {backup_type} backup before applying fixes...[/bold]")
            backup_manager = BackupManager(service_config, console=console)
            
            backup_info = backup_manager.create_backup(
                backup_type=backup_type,
                custom_name=f"pre_fix_{fix_type}",
                dry_run=dry_run
            )
            
            if backup_info:
                backup_id = backup_info.id
                console.print(f"[green]✓ Backup created with ID: [bold]{backup_id}[/bold][/green]")
                console.print(f"  To restore this backup if needed, use:")
                console.print(f"  [bold]python dbaudit.py --service {service} restore --id {backup_id}[/bold]\n")
            else:
                console.print("[yellow]⚠️ Backup failed, proceeding without backup[/yellow]")
        # Connect to database and run audit
        with PostgresConnection(service_config) as conn:
            # First run an audit to identify permissions issues
            logger.info(f"Running permission audit for {service}...")
            
            auditor = PermissionAuditor(conn, console)
            if ctx.obj.get("verbose", False):
                auditor.set_verbose(True)
            
            audit_result = auditor.run_audit()
            
            # Initialize permission fixer
            logger.info(f"Analyzing permission fixes for {service}...")
            fixer = PermissionFixer(conn, console)
            
            # Determine changes based on fix type
            changes = []
            
            if fix_type == "remove_dangerous":
                # Identify dangerous permissions to remove
                changes = fixer.identify_dangerous_permissions(
                    audit_result=audit_result,
                    roles=role if role else None
                )
            elif fix_type == "apply_template":
                # Apply permission template
                changes = fixer.generate_template_changes(
                    template_name=template,
                    roles=role if role else None
                )
            elif fix_type == "restrict_public":
                # Restrict public schema permissions
                changes = fixer.generate_public_schema_fixes()
            
            # No changes to apply
            if not changes:
                console.print("[yellow]No changes to apply. Database permissions already match requirements.[/yellow]")
                return
            
            # Apply fixes
            fix_result = fixer.apply_fixes(
                changes=changes,
                interactive=not auto,
                dry_run=dry_run,
                export_scripts=export_scripts,
                export_dir=export_dir
            )
            
            # Show summary of results
            
            # Show summary of results
            if not dry_run and fix_result.changes_applied:
                console.print(f"\n[bold green]✓ Successfully applied {len(fix_result.changes_applied)} permission changes[/bold green]")
                
                if fix_result.errors:
                    console.print(f"[yellow]⚠️ {len(fix_result.errors)} errors occurred[/yellow]")
                
                # Remind about backup
                if backup_id:
                    console.print(f"\n[bold]If you need to restore the database to its previous state:[/bold]")
                    console.print(f"  [bold]python dbaudit.py --service {service} restore --id {backup_id}[/bold]")
                
                # Suggest running audit again
                console.print(f"\n[blue]Tip: Run an audit again to verify the changes:[/blue]")
                console.print(f"  [bold]python dbaudit.py --service {service} audit[/bold]")
    
    except Exception as e:
        logger.error(f"Fix operation failed: {e}")
        if ctx.obj.get("verbose"):
            import traceback
            console.print_exception()
        sys.exit(1)

if __name__ == "__main__":
    cli(obj={})
