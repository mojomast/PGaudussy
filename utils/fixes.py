"""
PostgreSQL permission fixing utilities

Provides functionality to fix permission issues in PostgreSQL databases
based on audit results.
"""

import os
import sys
import logging
import datetime
import pathlib
import tempfile
import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple, Union
from enum import Enum

import psycopg
from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm, Prompt
from rich.panel import Panel
from rich.syntax import Syntax

from utils.audit import PermissionAuditor, PermissionRisk, AuditResult

logger = logging.getLogger("dbaudit")


@dataclass
class PermissionChange:
    """A permission change to be applied"""
    sql: str
    target_type: str  # "role", "schema", "table", etc.
    target_name: str
    description: str
    rollback_sql: str
    risk_level: str = "LOW"


@dataclass
class FixResult:
    """Results of permission fixes"""
    changes_applied: List[PermissionChange] = field(default_factory=list)
    changes_skipped: List[PermissionChange] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)


class PermissionFixer:
    """Fixes permission issues in PostgreSQL databases"""
    
    def __init__(
        self, 
        connection: psycopg.Connection, 
        audit_result: Optional[AuditResult] = None,
        console: Optional[Console] = None
    ):
        """
        Initialize with a database connection and optional audit result
        
        Args:
            connection: PostgreSQL database connection
            audit_result: Optional audit result to use
            console: Rich console for output
        """
        self.connection = connection
        self.audit_result = audit_result
        self.console = console or Console()
        self.fix_result = FixResult()
        
        # Define templates for permission profiles
        self.templates = {
            "read_only": {
                "description": "Read-only access",
                "permissions": {
                    "database": ["CONNECT"],
                    "schema": ["USAGE"],
                    "table": ["SELECT"],
                    "sequence": ["SELECT"],
                    "function": ["EXECUTE"]
                },
                "revoke": {
                    "database": ["CREATE"],
                    "schema": ["CREATE"],
                    "table": ["INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
                }
            },
            "read_write": {
                "description": "Read-write access without destructive permissions",
                "permissions": {
                    "database": ["CONNECT"],
                    "schema": ["USAGE"],
                    "table": ["SELECT", "INSERT", "UPDATE"],
                    "sequence": ["SELECT", "UPDATE"],
                    "function": ["EXECUTE"]
                },
                "revoke": {
                    "database": ["CREATE"],
                    "schema": ["CREATE"],
                    "table": ["DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
                }
            },
            "developer": {
                "description": "Developer access with some schema modification rights",
                "permissions": {
                    "database": ["CONNECT"],
                    "schema": ["USAGE", "CREATE"],
                    "table": ["SELECT", "INSERT", "UPDATE", "DELETE", "REFERENCES"],
                    "sequence": ["SELECT", "UPDATE", "USAGE"],
                    "function": ["EXECUTE"]
                },
                "revoke": {
                    "table": ["TRUNCATE"]
                }
            },
            "admin": {
                "description": "Admin access with all permissions except superuser",
                "permissions": {
                    "database": ["CONNECT", "CREATE", "TEMPORARY"],
                    "schema": ["USAGE", "CREATE"],
                    "table": ["ALL"],
                    "sequence": ["ALL"],
                    "function": ["ALL"]
                },
                "revoke": {}
            }
        }
    
    def generate_fixes(
        self, 
        fix_type: str = "remove_dangerous", 
        interactive: bool = True,
        template: Optional[str] = None,
        target_roles: Optional[List[str]] = None
    ) -> List[PermissionChange]:
        """
        Generate fixes for permission issues
        
        Args:
            fix_type: Type of fix to apply 
                     ("remove_dangerous", "apply_template", "restrict_public")
            interactive: Whether to interactively prompt for confirmation
            template: Permission template to apply (if fix_type is "apply_template")
            target_roles: List of roles to target (if None, all roles)
            
        Returns:
            List of permission changes to apply
        """
        if not self.audit_result:
            raise ValueError("No audit result provided. Run an audit first.")
        
        changes: List[PermissionChange] = []
        
        if fix_type == "remove_dangerous":
            changes.extend(self._generate_dangerous_permission_fixes(target_roles))
        elif fix_type == "apply_template":
            if not template or template not in self.templates:
                available = ", ".join(self.templates.keys())
                raise ValueError(f"Invalid template: {template}. Available templates: {available}")
            
            changes.extend(self._generate_template_fixes(template, target_roles))
        elif fix_type == "restrict_public":
            changes.extend(self._generate_public_schema_fixes())
        else:
            raise ValueError(f"Invalid fix type: {fix_type}")
        
        return changes
    
    def _generate_dangerous_permission_fixes(self, target_roles: Optional[List[str]] = None) -> List[PermissionChange]:
        """Generate fixes for dangerous permissions"""
        changes = []
        
        # Filter dangerous permissions to target_roles if specified
        dangerous_perms = self.audit_result.dangerous_permissions
        if target_roles:
            dangerous_perms = [
                p for p in dangerous_perms 
                if p.get("type") in ("role", "table", "schema") and
                (p.get("name") in target_roles or p.get("grantee") in target_roles)
            ]
        
        # Generate fixes for each dangerous permission
        for perm in dangerous_perms:
            perm_type = perm["type"]
            
            if perm_type == "table" and perm.get("privilege") in ("DROP", "TRUNCATE", "DELETE"):
                # Fix for dangerous table permissions
                table_name = perm["name"]
                grantee = perm["grantee"]
                privilege = perm["privilege"]
                
                # Create revoke statement
                sql = f"REVOKE {privilege} ON TABLE {table_name} FROM {grantee};"
                
                # Create rollback statement
                rollback_sql = f"GRANT {privilege} ON TABLE {table_name} TO {grantee};"
                
                changes.append(PermissionChange(
                    sql=sql,
                    target_type="table",
                    target_name=table_name,
                    description=f"Revoke {privilege} from {grantee} on {table_name}",
                    rollback_sql=rollback_sql,
                    risk_level="MEDIUM"  # Medium risk because it might impact existing applications
                ))
            
            elif perm_type == "schema" and perm.get("privilege") in ("CREATE", "USAGE"):
                # Only revoke CREATE, not USAGE which is needed for basic access
                if perm.get("privilege") == "CREATE":
                    schema_name = perm["name"]
                    grantee = perm["grantee"]
                    privilege = perm["privilege"]
                    
                    # Create revoke statement
                    sql = f"REVOKE {privilege} ON SCHEMA {schema_name} FROM {grantee};"
                    
                    # Create rollback statement
                    rollback_sql = f"GRANT {privilege} ON SCHEMA {schema_name} TO {grantee};"
                    
                    changes.append(PermissionChange(
                        sql=sql,
                        target_type="schema",
                        target_name=schema_name,
                        description=f"Revoke {privilege} from {grantee} on schema {schema_name}",
                        rollback_sql=rollback_sql,
                        risk_level="MEDIUM"
                    ))
            
            elif perm_type == "role" and "Superuser" in perm.get("issue", ""):
                # Can't revoke superuser directly with SQL; provide instructions
                role_name = perm["name"]
                if role_name != "postgres":  # Don't suggest revoking from postgres
                    # Need to use ALTER ROLE outside of transaction
                    sql = f"ALTER ROLE {role_name} NOSUPERUSER;"
                    rollback_sql = f"ALTER ROLE {role_name} SUPERUSER;"
                    
                    changes.append(PermissionChange(
                        sql=sql,
                        target_type="role",
                        target_name=role_name,
                        description=f"Remove superuser privilege from role {role_name}",
                        rollback_sql=rollback_sql,
                        risk_level="HIGH"  # High risk because it may break admin functionality
                    ))
        
        return changes
    
    def _generate_template_fixes(self, template_name: str, target_roles: Optional[List[str]] = None) -> List[PermissionChange]:
        """Generate fixes to apply a permission template"""
        changes = []
        template = self.templates[template_name]
        
        if not target_roles:
            # If no target roles specified, get regular user roles (non-superuser)
            target_roles = [
                role_name for role_name, role in self.audit_result.roles.items()
                if not role.is_superuser and role_name != "public"
            ]
        
        # Process each role
        for role_name in target_roles:
            if role_name not in self.audit_result.roles:
                logger.warning(f"Role {role_name} not found in audit results")
                continue
            
            # Apply schema permissions from template
            for schema_name in self.audit_result.schemas:
                # Grant permissions
                for perm in template["permissions"].get("schema", []):
                    sql = f"GRANT {perm} ON SCHEMA {schema_name} TO {role_name};"
                    rollback_sql = f"REVOKE {perm} ON SCHEMA {schema_name} FROM {role_name};"
                    
                    changes.append(PermissionChange(
                        sql=sql,
                        target_type="schema",
                        target_name=schema_name,
                        description=f"Grant {perm} to {role_name} on schema {schema_name}",
                        rollback_sql=rollback_sql,
                        risk_level="LOW"
                    ))
                
                # Revoke permissions
                for perm in template["revoke"].get("schema", []):
                    sql = f"REVOKE {perm} ON SCHEMA {schema_name} FROM {role_name};"
                    rollback_sql = f"GRANT {perm} ON SCHEMA {schema_name} TO {role_name};"
                    
                    changes.append(PermissionChange(
                        sql=sql,
                        target_type="schema",
                        target_name=schema_name,
                        description=f"Revoke {perm} from {role_name} on schema {schema_name}",
                        rollback_sql=rollback_sql,
                        risk_level="MEDIUM"
                    ))
            
            # Apply table permissions from template
            for table_key, table in self.audit_result.tables.items():
                # Grant permissions
                for perm in template["permissions"].get("table", []):
                    sql = f"GRANT {perm} ON TABLE {table_key} TO {role_name};"
                    rollback_sql = f"REVOKE {perm} ON TABLE {table_key} FROM {role_name};"
                    
                    changes.append(PermissionChange(
                        sql=sql,
                        target_type="table",
                        target_name=table_key,
                        description=f"Grant {perm} to {role_name} on table {table_key}",
                        rollback_sql=rollback_sql,
                        risk_level="LOW"
                    ))
                
                # Revoke permissions
                for perm in template["revoke"].get("table", []):
                    sql = f"REVOKE {perm} ON TABLE {table_key} FROM {role_name};"
                    rollback_sql = f"GRANT {perm} ON TABLE {table_key} TO {role_name};"
                    
                    changes.append(PermissionChange(
                        sql=sql,
                        target_type="table",
                        target_name=table_key,
                        description=f"Revoke {perm} from {role_name} on table {table_key}",
                        rollback_sql=rollback_sql,
                        risk_level="MEDIUM"
                    ))
        
        return changes
    
    def _generate_public_schema_fixes(self) -> List[PermissionChange]:
        """Generate fixes to restrict public schema access"""
        changes = []
        
        # Revoke CREATE on public schema from PUBLIC role
        sql = "REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
        rollback_sql = "GRANT CREATE ON SCHEMA public TO PUBLIC;"
        
        changes.append(PermissionChange(
            sql=sql,
            target_type="schema",
            target_name="public",
            description="Revoke CREATE on public schema from PUBLIC role",
            rollback_sql=rollback_sql,
            risk_level="MEDIUM"
        ))
        
        # For all tables in public schema
        for table_key, table in self.audit_result.tables.items():
            if table.schema == "public":
                # Revoke all permissions from PUBLIC role
                sql = f"REVOKE ALL ON TABLE {table_key} FROM PUBLIC;"
                rollback_sql = f"GRANT ALL ON TABLE {table_key} TO PUBLIC;"
                
                changes.append(PermissionChange(
                    sql=sql,
                    target_type="table",
                    target_name=table_key,
                    description=f"Revoke all permissions on {table_key} from PUBLIC role",
                    rollback_sql=rollback_sql,
                    risk_level="MEDIUM"
                ))
        
        return changes
    
    def generate_fix_script(self, changes: List[PermissionChange]) -> str:
        """
        Generate a SQL script for applying fixes
        
        Args:
            changes: List of permission changes to include
            
        Returns:
            SQL script as string
        """
        script = [
            "-- PostgreSQL Permission Fix Script",
            f"-- Generated by dbaudit on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "-- Database: " + self.connection.info.dbname,
            "",
            "BEGIN;"
        ]
        
        # Add each change
        for change in changes:
            script.append("")
            script.append(f"-- {change.description}")
            script.append(change.sql)
        
        script.append("")
        script.append("COMMIT;")
        
        return "\n".join(script)
        return "\n".join(script)
    
    def generate_rollback_script(self, changes: List[PermissionChange]) -> str:
        """
        Generate a SQL script for rolling back fixes
        
        Args:
            changes: List of permission changes to roll back
            
        Returns:
            SQL script as string
        """
        script = [
            "-- PostgreSQL Permission Rollback Script",
            f"-- Generated by dbaudit on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "-- Database: " + self.connection.info.dbname,
            "",
            "BEGIN;"
        ]
        
        # Add rollback for each change (in reverse order)
        for change in reversed(changes):
            script.append("")
            script.append(f"-- Rollback: {change.description}")
            script.append(change.rollback_sql)
        
        script.append("")
        script.append("COMMIT;")
        
        return "\n".join(script)
    
    def preview_changes(self, changes: List[PermissionChange]) -> None:
        """
        Preview permission changes in a formatted table
        
        Args:
            changes: List of permission changes to preview
        """
        if not changes:
            self.console.print("[yellow]No changes to preview.[/yellow]")
            return
        
        # Group changes by risk level
        high_risk = [c for c in changes if c.risk_level == "HIGH"]
        medium_risk = [c for c in changes if c.risk_level == "MEDIUM"]
        low_risk = [c for c in changes if c.risk_level == "LOW"]
        
        self.console.print(f"\n[bold]Preview of Permission Changes[/bold] ({len(changes)} total)")
        
        # Show summary by risk
        self.console.print("\n[bold]Summary by Risk Level:[/bold]")
        if high_risk:
            self.console.print(f"[bold red]HIGH risk changes:[/bold red] {len(high_risk)}")
        if medium_risk:
            self.console.print(f"[yellow]MEDIUM risk changes:[/yellow] {len(medium_risk)}")
        if low_risk:
            self.console.print(f"[green]LOW risk changes:[/green] {len(low_risk)}")
        
        # Show high risk changes in detail
        if high_risk:
            table = Table(title="HIGH Risk Changes")
            table.add_column("Type", style="bold")
            table.add_column("Target", style="cyan")
            table.add_column("Description", style="red")
            table.add_column("SQL", style="yellow")
            
            for change in high_risk:
                table.add_row(
                    change.target_type.capitalize(),
                    change.target_name,
                    change.description,
                    change.sql
                )
            
            self.console.print("\n")
            self.console.print(table)
        
        # Show medium risk changes (summarized by type)
        if medium_risk:
            table = Table(title="MEDIUM Risk Changes")
            table.add_column("Type", style="bold")
            table.add_column("Count", style="cyan")
            table.add_column("Example", style="yellow")
            
            # Group by type and target for summary
            by_type = {}
            for change in medium_risk:
                key = (change.target_type, change.sql.split()[0])  # REVOKE/GRANT
                by_type.setdefault(key, []).append(change)
            
            for (target_type, operation), changes_group in by_type.items():
                table.add_row(
                    f"{operation} on {target_type}",
                    str(len(changes_group)),
                    changes_group[0].description
                )
            
            self.console.print("\n")
            self.console.print(table)
        
        # Show SQL script preview
        sql_script = self.generate_fix_script(changes)
        self.console.print("\n[bold]SQL Script Preview:[/bold]")
        self.console.print(Panel(Syntax(sql_script, "sql", theme="monokai", line_numbers=True), 
                               title="Fix Script", border_style="green"))
    
    def apply_fixes(
        self,
        changes: List[PermissionChange],
        interactive: bool = True,
        dry_run: bool = False,
        export_scripts: bool = False,
        export_dir: str = "./fixes"
    ) -> FixResult:
        """
        Apply permission fixes to the database
        
        Args:
            changes: List of permission changes to apply
            interactive: Whether to prompt for confirmation
            dry_run: If True, don't actually apply changes
            export_scripts: Whether to export SQL scripts
            export_dir: Directory to export scripts to
            
        Returns:
            FixResult with details of applied changes
        """
        if not changes:
            self.console.print("[yellow]No changes to apply.[/yellow]")
            return self.fix_result
        
        # Preview changes
        self.preview_changes(changes)
        
        # Export scripts if requested
        if export_scripts:
            self._export_scripts(changes, export_dir)
        
        # Confirm before proceeding
        if interactive and not dry_run:
            confirmed = Confirm.ask("\nDo you want to apply these changes?", default=False)
            if not confirmed:
                self.console.print("[yellow]Operation cancelled.[/yellow]")
                return self.fix_result
        
        if dry_run:
            self.console.print("[yellow]DRY RUN: Changes would be applied[/yellow]")
            return self.fix_result
        
        # Apply changes in a transaction
        try:
            self.console.print("\n[bold]Applying permission changes...[/bold]")
            
            # Start transaction
            self.connection.autocommit = False
            
            # Execute each change
            for i, change in enumerate(changes):
                try:
                    self.console.print(f"Executing ({i+1}/{len(changes)}): {change.description}")
                    cursor = self.connection.cursor()
                    cursor.execute(change.sql)
                    
                    # Add to successful changes
                    self.fix_result.changes_applied.append(change)
                    
                except Exception as e:
                    # Record error
                    error_info = {
                        "change": change,
                        "error": str(e),
                        "index": i
                    }
                    self.fix_result.errors.append(error_info)
                    self.console.print(f"[bold red]Error applying change:[/bold red] {e}")
                    
                    # Ask whether to continue or rollback
                    if interactive:
                        continue_anyway = Confirm.ask("Continue with remaining changes?", default=False)
                        if not continue_anyway:
                            raise Exception("Operation cancelled by user after error")
                    else:
                        raise
            
            # Commit transaction if no errors occurred
            if not self.fix_result.errors:
                self.connection.commit()
                self.console.print("[bold green]All changes applied successfully![/bold green]")
            else:
                # If we reach here with errors, it means user chose to continue
                self.connection.commit()
                self.console.print(f"[bold yellow]Applied {len(self.fix_result.changes_applied)} changes with {len(self.fix_result.errors)} errors.[/bold yellow]")
                
        except Exception as e:
            # Rollback transaction
            self.connection.rollback()
            self.console.print(f"[bold red]Transaction rolled back: {str(e)}[/bold red]")
        
        finally:
            # Restore autocommit mode
            self.connection.autocommit = True
        
        return self.fix_result
    
    def _export_scripts(self, changes: List[PermissionChange], export_dir: str) -> Tuple[str, str]:
        """
        Export fix and rollback scripts to files
        
        Args:
            changes: List of permission changes
            export_dir: Directory to export to
            
        Returns:
            Tuple of (fix_script_path, rollback_script_path)
        """
        # Create export directory if it doesn't exist
        export_path = pathlib.Path(export_dir)
        export_path.mkdir(parents=True, exist_ok=True)
        
        # Generate timestamp for filenames
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        db_name = self.connection.info.dbname
        
        # Generate scripts
        fix_script = self.generate_fix_script(changes)
        rollback_script = self.generate_rollback_script(changes)
        
        # Write to files
        fix_file_path = export_path / f"{db_name}_fix_{timestamp}.sql"
        rollback_file_path = export_path / f"{db_name}_rollback_{timestamp}.sql"
        
        with open(fix_file_path, 'w') as f:
            f.write(fix_script)
            
        with open(rollback_file_path, 'w') as f:
            f.write(rollback_script)
            
        self.console.print(f"[green]Fix script exported to:[/green] {fix_file_path}")
        self.console.print(f"[green]Rollback script exported to:[/green] {rollback_file_path}")
        
        return str(fix_file_path), str(rollback_file_path)
