#!/usr/bin/env python3
"""
PostgreSQL Database Permission Auditor

This module provides functionality to audit PostgreSQL database permissions
and identify security issues based on risk levels.
"""

import os
import time
import datetime
import enum
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
import json
import psycopg
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

# Ensure log directory exists
log_dir = os.path.join("data", "logs")
os.makedirs(log_dir, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, "audit.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

console = Console()

class PermissionRisk(enum.Enum):
    """Risk levels for permission issues"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"

# Map of PostgreSQL permissions to risk levels
PERMISSION_RISK_MAP = {
    # High risk permissions that can modify data or structure
    "ALL": PermissionRisk.HIGH,
    "INSERT": PermissionRisk.HIGH,
    "UPDATE": PermissionRisk.HIGH,
    "DELETE": PermissionRisk.HIGH,
    "TRUNCATE": PermissionRisk.HIGH,
    "REFERENCES": PermissionRisk.HIGH,
    "TRIGGER": PermissionRisk.HIGH,
    
    # Medium risk permissions
    "CREATE": PermissionRisk.MEDIUM,
    "CONNECT": PermissionRisk.MEDIUM,
    "TEMPORARY": PermissionRisk.MEDIUM,
    "TEMP": PermissionRisk.MEDIUM,
    "EXECUTE": PermissionRisk.MEDIUM,
    
    # Low risk permissions (mostly read-only)
    "SELECT": PermissionRisk.LOW,
    "USAGE": PermissionRisk.LOW,
    
    # Default for unrecognized permissions
    "DEFAULT": PermissionRisk.SAFE
}


class PermissionIssue:
    """Represents a permission issue found during audit"""
    
    def __init__(self, 
                 object_type: str, 
                 object_name: str, 
                 grantee: str, 
                 permission: str, 
                 risk_level: PermissionRisk,
                 recommendation: str,
                 details: Optional[Dict[str, Any]] = None):
        self.object_type = object_type
        self.object_name = object_name
        self.grantee = grantee
        self.permission = permission
        self.risk_level = risk_level
        self.recommendation = recommendation
        self.details = details or {}
        self.timestamp = datetime.datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert issue to dictionary for serialization"""
        return {
            "object_type": self.object_type,
            "object_name": self.object_name,
            "grantee": self.grantee,
            "permission": self.permission,
            "risk_level": self.risk_level.value,
            "recommendation": self.recommendation,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PermissionIssue':
        """Create issue instance from dictionary"""
        risk_level = PermissionRisk(data.get("risk_level", "medium"))
        timestamp = data.get("timestamp")
        issue = cls(
            object_type=data.get("object_type", ""),
            object_name=data.get("object_name", ""),
            grantee=data.get("grantee", ""),
            permission=data.get("permission", ""),
            risk_level=risk_level,
            recommendation=data.get("recommendation", ""),
            details=data.get("details", {})
        )
        if timestamp:
            try:
                issue.timestamp = datetime.datetime.fromisoformat(timestamp)
            except (ValueError, TypeError):
                pass
        return issue


class DatabaseRole:
    """Represents a PostgreSQL database role with its permissions"""
    
    def __init__(self, name: str):
        self.name = name
        self.is_superuser = False
        self.can_login = False
        self.can_create_db = False
        self.can_create_role = False
        self.member_of: List[str] = []


class SchemaInfo:
    """Represents a PostgreSQL schema with its permissions"""
    
    def __init__(self, name: str, owner: str):
        self.name = name
        self.owner = owner
        self.permissions: Dict[str, List[str]] = {}  # grantee -> list of privileges


class TableInfo:
    """Represents a PostgreSQL table with its permissions"""
    
    def __init__(self, schema: str, name: str, owner: str):
        self.schema = schema
        self.name = name
        self.full_name = f"{schema}.{name}"
        self.owner = owner
        self.permissions: Dict[str, List[str]] = {}  # grantee -> list of privileges
        self.is_sensitive = False


class AuditResult:
    """Container for audit results"""
    
    def __init__(self, database: str):
        self.database = database
        self.timestamp = datetime.datetime.now()
        self.roles: Dict[str, DatabaseRole] = {}
        self.schemas: Dict[str, SchemaInfo] = {}
        self.tables: Dict[str, TableInfo] = {}
        self.dangerous_permissions: List[Dict[str, Any]] = []
        self.default_acls: List[Dict[str, Any]] = []
        self.issues: List[PermissionIssue] = []

    def add_issue(self, issue: PermissionIssue):
        """Add a permission issue to the results"""
        self.issues.append(issue)
        
        # Also add to dangerous_permissions for backward compatibility
        dangerous_perm = {
            "type": issue.object_type,
            "name": issue.object_name,
            "grantee": issue.grantee,
            "privilege": issue.permission,
            "risk_level": issue.risk_level.value,  # Store the string value
            "recommendation": issue.recommendation
        }
        self.dangerous_permissions.append(dangerous_perm)


class PermissionAuditor:
    """
    Audits PostgreSQL database permissions and identifies security issues
    
    This class connects to a PostgreSQL database and analyzes permissions
    on various database objects, identifying potential security risks and
    providing recommendations for remediation.
    """
    
    def __init__(self, conn: psycopg.Connection, console: Optional[Console] = None):
        """
        Initialize the auditor with a database connection
        
        Args:
            conn: PostgreSQL connection object
            console: Rich console for output (optional)
        """
        self.conn = conn
        self.console = console or Console()
        self.verbose = False
        self.public_schema_permissions = {}
        self.superusers = []
        # Initialize empty issues list (for backward compatibility)
        # Get database name from connection info
        try:
            self.database_name = conn.info.dbname
        except Exception:
            self.database_name = "unknown"
            
        # Initialize the audit result object
        self.audit_result = AuditResult(self.database_name)
            
            
    def run_audit(self, 
                 risk_levels: List[PermissionRisk] = None, 
                 object_types: List[str] = None) -> AuditResult:
        """
        Run a comprehensive audit of database permissions
        
        Args:
            risk_levels: List of risk levels to include in results
            object_types: List of object types to audit
            
        """
        if risk_levels is None or not risk_levels:
            # Default to all risk levels if none provided
            risk_levels = [PermissionRisk.HIGH, PermissionRisk.MEDIUM, PermissionRisk.LOW]
            
        if self.verbose:
            level_names = [level.value.upper() for level in risk_levels]
            self.console.print(f"Filtering audit results to show: {', '.join(level_names)} risk levels")
            
        if object_types is None:
            object_types = ["table", "schema", "function", "database", "role"]
        
        # Verify connection is active
        if self.conn.closed:
            raise RuntimeError("Database connection is closed. Cannot run audit.")
        
        # Reset audit result
        # Reset audit result
        self.audit_result = AuditResult(self.database_name)
        self.issues = []
        with Progress() as progress:
            total_steps = len(object_types) + 2  # +2 for preparation tasks
            task = progress.add_task("[cyan]Running permission audit...", total=total_steps)
            
            # Preparation steps
            progress.update(task, advance=1, description="[cyan]Identifying superusers...")
            self._identify_superusers()
            
            progress.update(task, advance=1, description="[cyan]Analyzing public schema...")
            self._check_public_schema_permissions()
            
            # Audit different object types
            for obj_type in object_types:
                progress.update(task, description=f"[cyan]Auditing {obj_type} permissions...")
                if obj_type == "table":
                    self._audit_table_permissions()
                elif obj_type == "schema":
                    self._audit_schema_permissions()
                elif obj_type == "function":
                    self._audit_function_permissions()
                elif obj_type == "database":
                    self._audit_database_permissions()
                elif obj_type == "role":
                    self._audit_role_permissions()
                progress.update(task, advance=1)
        
        # Filter issues by risk level
        if risk_levels != [PermissionRisk.HIGH, PermissionRisk.MEDIUM, PermissionRisk.LOW]:
            self.audit_result.issues = [
                issue for issue in self.audit_result.issues
                if issue.risk_level in risk_levels
            ]
        
        if self.verbose:
            self.console.print(f"[green]Audit complete. Found {len(self.audit_result.issues)} issues.[/green]")
        
        return self.audit_result
        
    def _identify_superusers(self):
        """Identify superuser roles in the database"""
        try:
            # Ensure we start with a clean transaction
            self.conn.rollback()
            with self.conn.cursor() as cur:
                cur.execute("SELECT rolname FROM pg_roles WHERE rolsuper = true;")
                self.superusers = [row[0] for row in cur.fetchall()]
                
                # Also store roles in the audit result
                for superuser in self.superusers:
                    role = DatabaseRole(superuser)
                    role.is_superuser = True
                    self.audit_result.roles[superuser] = role
                
                if self.verbose:
                    self.console.print(f"Identified superusers: {', '.join(self.superusers)}")
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not identify superusers: {e}[/yellow]")
            logger.warning(f"Error identifying superusers: {e}")
    def _check_public_schema_permissions(self):
        """Check permissions on the public schema"""
        try:
            # Start with a clean transaction
            self.conn.rollback()
            # Initialize permissions dictionary if not already done
            self.public_schema_permissions = {}
            
            with self.conn.cursor() as cur:
                cur.execute("""
                    SELECT grantee, privilege_type 
                    FROM information_schema.role_usage_grants 
                    WHERE object_schema = 'public';
                """)
                
                # Process query results
                for grantee, privilege in cur.fetchall():
                    # Track permissions in the dictionary
                    self.public_schema_permissions[privilege] = True
                    
                    # If PUBLIC has permissions, add an issue
                    if grantee.upper() == 'PUBLIC':
                        # Public has USAGE on public schema (common but can be a risk)
                        issue = PermissionIssue(
                            object_type="schema",
                            object_name="public",
                            grantee="PUBLIC",
                            permission=privilege,
                            risk_level=PermissionRisk.MEDIUM,
                            recommendation="Restrict PUBLIC usage on public schema if not needed",
                            details={"schema": "public"}
                        )
                        self.audit_result.add_issue(issue)
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not check public schema permissions: {e}[/yellow]")
            logger.warning(f"Error checking public schema permissions: {e}")
    
    def _audit_table_permissions(self):
        """Audit permissions on tables"""
        try:
            with self.conn.cursor() as cur:
                # Check tables with PUBLIC access
                cur.execute("""
                    SELECT table_schema, table_name, privilege_type
                    FROM information_schema.role_table_grants 
                    WHERE grantee = 'PUBLIC'
                    ORDER BY table_schema, table_name;
                """)
                
                for schema, table, privilege in cur.fetchall():
                    risk_level = PermissionRisk.MEDIUM
                    
                    # Determine risk level based on privilege
                    if privilege in ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE'):
                        risk_level = PermissionRisk.HIGH
                    elif privilege in ('REFERENCES', 'TRIGGER'):
                        risk_level = PermissionRisk.MEDIUM
                    
                    issue = PermissionIssue(
                        object_type="table",
                        object_name=f"{schema}.{table}",
                        grantee="PUBLIC",
                        permission=privilege,
                        risk_level=risk_level,
                        recommendation=f"Revoke {privilege} from PUBLIC on {schema}.{table}",
                        details={
                            "schema": schema,
                            "table": table
                        }
                    )
                    self.audit_result.add_issue(issue)
                # This could be extended based on naming conventions or schema organization
                cur.execute("""
                    SELECT table_schema, table_name, grantee, privilege_type
                    FROM information_schema.role_table_grants 
                    WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
                    AND grantee <> 'postgres'
                    AND grantee <> current_user
                    AND grantee <> table_schema
                    ORDER BY table_schema, table_name;
                """)
                
                for schema, table, grantee, privilege in cur.fetchall():
                    # Skip superusers as grantees - expected to have access
                    if grantee in self.superusers:
                        continue
                        
                    # Detect potentially sensitive tables by name pattern
                    is_sensitive = any(pattern in table.lower() for pattern in 
                                     ['user', 'account', 'auth', 'password', 'credential', 
                                      'secret', 'key', 'token', 'payment', 'credit', 'ssn', 
                                      'customer', 'employee', 'salary', 'address'])
                    
                    if is_sensitive:
                        risk_level = PermissionRisk.HIGH if privilege in ('SELECT', 'INSERT', 'UPDATE', 'DELETE') else PermissionRisk.MEDIUM
                        
                        issue = PermissionIssue(
                            object_type="table",
                            object_name=f"{schema}.{table}",
                            grantee=grantee,
                            permission=privilege,
                            risk_level=risk_level,
                            recommendation=f"Review {privilege} for {grantee} on sensitive table {schema}.{table}",
                            details={
                                "schema": schema,
                                "table": table,
                                "sensitive": True
                            }
                        )
                        self.audit_result.add_issue(issue)
        except Exception as e:
            self.console.print(f"[yellow]Warning: Error during table permission audit: {e}[/yellow]")
    
    def _audit_schema_permissions(self):
        """Audit permissions on schemas"""
        try:
            with self.conn.cursor() as cur:
                # Check for non-standard schemas with public access
                cur.execute("""
                    SELECT object_schema as schema_name, grantee, privilege_type
                    FROM information_schema.role_usage_grants
                    WHERE object_schema NOT IN ('pg_catalog', 'information_schema')
                    AND grantee = 'PUBLIC'
                    ORDER BY object_schema;
                """)
                
                for schema, grantee, privilege in cur.fetchall():
                    issue = PermissionIssue(
                        object_type="schema",
                        object_name=schema,
                        grantee=grantee,
                        permission=privilege,
                        risk_level=PermissionRisk.MEDIUM,
                        recommendation=f"Consider restricting PUBLIC {privilege} on schema {schema}",
                        details={"schema": schema}
                    )
                    self.audit_result.add_issue(issue)
                
                # Check for CREATE privilege on schemas
                cur.execute("""
                    SELECT n.nspname as schema, 
                           r.rolname as grantee
                    FROM pg_namespace n, pg_roles r, aclexplode(n.nspacl) a
                    WHERE a.grantee = r.oid 
                    AND a.privilege_type = 'CREATE'
                    AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                    ORDER BY n.nspname;
                """)
                
                for schema, grantee in cur.fetchall():
                    # Skip superusers - expected to have CREATE
                    if grantee in self.superusers:
                        continue
                        
                    if grantee == 'PUBLIC':
                        risk_level = PermissionRisk.HIGH
                    else:
                        risk_level = PermissionRisk.MEDIUM
                        
                    issue = PermissionIssue(
                        object_type="schema",
                        object_name=schema,
                        grantee=grantee,
                        permission="CREATE",
                        risk_level=risk_level,
                        recommendation=f"Review CREATE privilege for {grantee} on schema {schema}",
                        details={"schema": schema}
                    )
                    self.audit_result.add_issue(issue)
        except Exception as e:
            self.console.print(f"[yellow]Warning: Error during schema permission audit: {e}[/yellow]")
    
    def _audit_function_permissions(self):
        """Audit permissions on functions"""
        try:
            with self.conn.cursor() as cur:
                # Check for functions with EXECUTE privilege granted to PUBLIC
                cur.execute("""
                    SELECT n.nspname as schema_name,
                           p.proname as function_name,
                           'PUBLIC' as grantee
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    JOIN LATERAL aclexplode(p.proacl) a ON TRUE
                    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                    AND a.grantee = 0
                    ORDER BY n.nspname;
                """)
                
                for schema_name, function_name, grantee in cur.fetchall():
                    # PUBLIC execution permissions on functions can be a risk in certain cases
                    risk_level = PermissionRisk.MEDIUM
                    
                    issue = PermissionIssue(
                        object_type="function",
                        object_name=f"{schema_name}.{function_name}",
                        grantee=grantee,
                        permission="EXECUTE",
                        risk_level=risk_level,
                        recommendation=f"Review if PUBLIC should have EXECUTE on {schema_name}.{function_name}",
                        details={"schema": schema_name, "function": function_name}
                    )
                    self.audit_result.add_issue(issue)
                
                # Check for sensitive functions
                cur.execute("""
                    SELECT n.nspname as schema_name,
                           p.proname as function_name,
                           r.rolname as grantee,
                           a.privilege_type
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    JOIN LATERAL aclexplode(p.proacl) a ON TRUE
                    JOIN pg_roles r ON a.grantee = r.oid
                    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                    AND (
                        p.proname LIKE '%password%' OR
                        p.proname LIKE '%auth%' OR
                        p.proname LIKE '%crypt%' OR
                        p.proname LIKE '%key%' OR
                        p.proname LIKE '%secret%' OR
                        p.proname LIKE '%token%' OR
                        p.proname LIKE '%hash%'
                    )
                    ORDER BY n.nspname, p.proname;
                """)
                
                for schema_name, function_name, grantee, privilege in cur.fetchall():
                    # Skip superusers as grantees - expected to have access
                    if grantee in self.superusers:
                        continue
                        
                    # Sensitive functions should be carefully reviewed
                    issue = PermissionIssue(
                        object_type="function",
                        object_name=f"{schema_name}.{function_name}",
                        grantee=grantee,
                        permission=privilege,
                        risk_level=PermissionRisk.HIGH,
                        recommendation=f"Review {grantee}'s {privilege} access to sensitive function {schema_name}.{function_name}",
                        details={
                            "schema": schema_name,
                            "function": function_name,
                            "sensitive": True
                        }
                    )
                    self.audit_result.add_issue(issue)
        except Exception as e:
            self.console.print(f"[yellow]Warning: Error during function permission audit: {e}[/yellow]")
            logger.warning(f"Error during function permission audit: {e}")
            
    def _audit_database_permissions(self):
        """Audit database-level permissions"""
        try:
            # Start a fresh transaction to avoid any previous errors affecting this query
            self.conn.rollback()
            with self.conn.cursor() as cur:
                # List database-level permissions
                cur.execute("""
                    SELECT d.datname, 
                           r.rolname, 
                           pg_catalog.has_database_privilege(r.oid, d.oid, 'CREATE') as create_perm,
                           pg_catalog.has_database_privilege(r.oid, d.oid, 'CONNECT') as connect_perm,
                           pg_catalog.has_database_privilege(r.oid, d.oid, 'TEMPORARY') as temp_perm
                    FROM pg_catalog.pg_database d
                    CROSS JOIN pg_catalog.pg_roles r
                    WHERE d.datname = current_database()
                    AND r.rolname NOT LIKE 'pg_%'
                    ORDER BY r.rolname;
                """)
                
                for db, role, create, connect, temp in cur.fetchall():
                    if create:
                        issue = PermissionIssue(
                            object_type="database",
                            object_name=db,
                            grantee=role,
                            permission="CREATE",
                            risk_level=PermissionRisk.MEDIUM,
                            recommendation=f"Review if {role} needs CREATE permission on database {db}",
                            details={"database": db}
                        )
                        self.audit_result.add_issue(issue)
        except Exception as e:
            self.console.print(f"[yellow]Warning: Error during database permission audit: {e}[/yellow]")
            logger.warning(f"Error during database permission audit: {e}")
            
    def _audit_role_permissions(self):
        """Audit role permissions and inheritance"""
        try:
            # Start a fresh transaction to avoid any previous errors affecting this query
            self.conn.rollback()
            with self.conn.cursor() as cur:
                # Get all roles and their attributes
                cur.execute("""
                    SELECT r.rolname, 
                           r.rolsuper, 
                           r.rolcreatedb, 
                           r.rolcreaterole,
                           r.rolcanlogin,
                           array_agg(m.rolname) FILTER (WHERE m.rolname IS NOT NULL) as member_of
                    FROM pg_catalog.pg_roles r
                    LEFT JOIN pg_catalog.pg_auth_members am ON r.oid = am.member
                    LEFT JOIN pg_catalog.pg_roles m ON am.roleid = m.oid
                    WHERE r.rolname NOT LIKE 'pg_%'
                    GROUP BY r.rolname, r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolcanlogin
                    ORDER BY r.rolname;
                """)
                
                for role_name, is_super, create_db, create_role, can_login, member_of in cur.fetchall():
                    # Store role in audit result
                    role = DatabaseRole(role_name)
                    role.is_superuser = is_super
                    role.can_login = can_login
                    role.can_create_db = create_db
                    role.can_create_role = create_role
                    role.member_of = member_of if member_of else []
                    
                    self.audit_result.roles[role_name] = role
                    
                    # Skip postgres - administrative account
                    if role_name == 'postgres':
                        continue
                        
                    if is_super:
                        issue = PermissionIssue(
                            object_type="role",
                            object_name=role_name,
                            grantee="",  # Not applicable for role permissions
                            permission="SUPERUSER",
                            risk_level=PermissionRisk.HIGH,
                            recommendation=f"Remove SUPERUSER privilege from {role_name} if not required",
                            details={"role": role_name}
                        )
                        self.audit_result.add_issue(issue)
                        
                    if create_role:
                        issue = PermissionIssue(
                            object_type="role",
                            object_name=role_name,
                            grantee="",  # Not applicable for role permissions
                            permission="CREATEROLE",
                            risk_level=PermissionRisk.HIGH,
                            recommendation=f"Remove CREATEROLE privilege from {role_name} if not required",
                            details={"role": role_name}
                        )
                        self.audit_result.add_issue(issue)
                        
                    if create_db:
                        issue = PermissionIssue(
                            object_type="role",
                            object_name=role_name,
                            grantee="",  # Not applicable for role permissions
                            permission="CREATEDB",
                            risk_level=PermissionRisk.MEDIUM,
                            recommendation=f"Remove CREATEDB privilege from {role_name} if not required",
                            details={"role": role_name}
                        )
                        self.audit_result.add_issue(issue)
        except Exception as e:
            self.console.print(f"[yellow]Warning: Error during role permission audit: {e}[/yellow]")
            logger.warning(f"Error during role permission audit: {e}")
    
    def generate_report(self, summary: bool = False) -> str:
        """
        Generate a report of permission issues
        
        Args:
            summary: If True, only generate a summary report
            
        Returns:
            Report as a string
        """
        # Use rich to format the report
        report_console = Console(record=True)
        
        # Print report header
        report_console.print(f"[bold blue]PostgreSQL Permission Audit Report[/bold blue]")
        report_console.print(f"Database: [cyan]{self.database_name}[/cyan]")
        report_console.print(f"Timestamp: [cyan]{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/cyan]")
        report_console.print()
        
        # Organize issues by risk level
        high_risk = [issue for issue in self.audit_result.issues if issue.risk_level == PermissionRisk.HIGH]
        medium_risk = [issue for issue in self.audit_result.issues if issue.risk_level == PermissionRisk.MEDIUM]
        low_risk = [issue for issue in self.audit_result.issues if issue.risk_level == PermissionRisk.LOW]
        
        # Print summary
        report_console.print("[bold]Summary:[/bold]")
        report_console.print(f"High Risk Issues: [bold red]{len(high_risk)}[/bold red]")
        report_console.print(f"Medium Risk Issues: [bold yellow]{len(medium_risk)}[/bold yellow]")
        report_console.print(f"Low Risk Issues: [bold green]{len(low_risk)}[/bold green]")
        report_console.print(f"Total Issues: [bold]{len(self.audit_result.issues)}[/bold]")
        report_console.print()
        
        if summary:
            return report_console.export_text()
        if high_risk:
            self._print_risk_report(report_console, high_risk, "High Risk Issues", "red")
        
        if medium_risk:
            self._print_risk_report(report_console, medium_risk, "Medium Risk Issues", "yellow")
        
        if low_risk and not summary:
            self._print_risk_report(report_console, low_risk, "Low Risk Issues", "green")
        
        # Return the report as a string
        return report_console.export_text()
    def _print_risk_report(self, console: Console, issues: List[PermissionIssue], title: str, color: str):
        """Print a section of the report for a specific risk level"""
        console.print(f"[bold {color}]{title}[/bold {color}]")
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Object Type")
        table.add_column("Object Name")
        table.add_column("Grantee")
        table.add_column("Permission")
        table.add_column("Recommendation")
        
        for issue in issues:
            table.add_row(
                issue.object_type.upper(),
                issue.object_name,
                issue.grantee,
                issue.permission,
                issue.recommendation
            )
        
        console.print(table)
        console.print()
    
    def _display_roles(self) -> None:
        """Display information about database roles"""
        self.console.print("[bold]Database Roles[/bold]")
        
        table = Table(title="Roles and Privileges")
        table.add_column("Role", style="cyan")
        table.add_column("Login?", style="bold")
        table.add_column("Superuser?", style="red")
        table.add_column("Create DB?", style="yellow")
        table.add_column("Create Role?", style="yellow")
        table.add_column("Member Of", style="green")
        
        for role_name, role in sorted(self.audit_result.roles.items()):
            table.add_row(
                role.name,
                "✓" if role.can_login else "✗",
                "✓" if role.is_superuser else "✗",
                "✓" if role.can_create_db else "✗",
                "✓" if role.can_create_role else "✗",
                ", ".join(role.member_of) if role.member_of else "None"
            )
        
        # Note: We're not implementing the _display_risk_tables method here
        # as it would duplicate functionality
        
        self.console.print(table)
        self.console.print()
    
    def _display_schema_permissions(self) -> None:
        """Display schema permissions"""
        self.console.print("[bold]Schema Permissions[/bold]")
        
        table = Table(title="Schema Access")
        table.add_column("Schema", style="cyan")
        table.add_column("Owner", style="yellow")
        table.add_column("Grantee", style="bold")
        table.add_column("Privileges", style="green")
        
        for schema_name, schema in sorted(self.audit_result.schemas.items()):
            # First row with owner info
            shown = False
            
            for grantee, privileges in sorted(schema.permissions.items()):
                if not shown:
                    table.add_row(
                        schema_name, 
                        schema.owner,
                        grantee,
                        ", ".join(privileges)
                    )
                    shown = True
                else:
                    table.add_row(
                        "", 
                        "",
                        grantee,
                        ", ".join(privileges)
                    )
            
            if not shown:
                table.add_row(schema_name, schema.owner, "None", "")
        
        self.console.print(table)
        self.console.print()
    
    def _display_table_permissions(self) -> None:
        """Display table permissions, focusing on those with potentially dangerous permissions"""
        self.console.print("[bold]Table Permissions (Dangerous Only)[/bold]")
        
        # Identify tables with dangerous permissions
        dangerous_tables = set()
        for perm in self.audit_result.dangerous_permissions:
            if perm["type"] == "table":
                dangerous_tables.add(perm["name"])
        
        if not dangerous_tables:
            self.console.print("[green]No dangerous table permissions found.[/green]\n")
            return
        
        table = Table(title="Table Permission Issues")
        table.add_column("Table", style="cyan")
        table.add_column("Owner", style="yellow")
        table.add_column("Grantee", style="bold")
        table.add_column("Privileges", style="red")
        
        for table_key in sorted(dangerous_tables):
            table_info = self.audit_result.tables[table_key]
            shown = False
            
            for grantee, privileges in sorted(table_info.permissions.items()):
                # Format privileges by risk level
                formatted_privs = []
                for priv in privileges:
                    risk = PERMISSION_RISK_MAP.get(priv, PermissionRisk.SAFE)
                    if risk == PermissionRisk.HIGH:
                        formatted_privs.append(f"[bold red]{priv}[/bold red]")
                    elif risk == PermissionRisk.MEDIUM:
                        formatted_privs.append(f"[yellow]{priv}[/yellow]")
                    elif risk == PermissionRisk.LOW:
                        formatted_privs.append(f"[blue]{priv}[/blue]")
                    else:
                        formatted_privs.append(priv)
                
                if not shown:
                    table.add_row(
                        table_key, 
                        table_info.owner,
                        grantee,
                        ", ".join(formatted_privs)
                    )
                    shown = True
                else:
                    table.add_row(
                        "", 
                        "",
                        grantee,
                        ", ".join(formatted_privs)
                    )
        
        self.console.print(table)
        self.console.print()
    
    def _display_default_acls(self) -> None:
        """Display default ACLs"""
        self.console.print("[bold]Default Access Control Lists[/bold]")
        
        table = Table(title="Default Permissions for New Objects")
        table.add_column("Schema", style="cyan")
        table.add_column("Object Type", style="bold")
        table.add_column("Role", style="yellow")
        table.add_column("Grantee", style="yellow")
        table.add_column("Privilege", style="green")
        
        for acl in sorted(self.audit_result.default_acls, key=lambda x: (x["schema"], x["object_type"])):
            privilege = acl.get("privilege", "")
            risk = PERMISSION_RISK_MAP.get(privilege, PermissionRisk.SAFE)
            
            if risk == PermissionRisk.HIGH:
                privilege = f"[bold red]{privilege}[/bold red]"
            elif risk == PermissionRisk.MEDIUM:
                privilege = f"[yellow]{privilege}[/yellow]"
            
            table.add_row(
                acl["schema"],
                acl["object_type"],
                acl["role"],
                acl["grantee"],
                privilege
            )
        
        self.console.print(table)
        self.console.print()
    
    def export_report(self, export_path: str) -> None:
        """
        Export the audit results to a file
        
        Args:
            export_path: Path to export the results to
        """
        try:
            dirname = os.path.dirname(export_path)
            if dirname and not os.path.exists(dirname):
                os.makedirs(dirname)
                
            timestamp = self.audit_result.timestamp.strftime("%Y-%m-%d_%H-%M-%S")
            
            # Default to a timestamped file if none specified
            if not export_path:
                export_path = f"audit_report_{self.audit_result.database}_{timestamp}.txt"
            
            # Create a console for file output without color codes
            file_console = Console(file=open(export_path, "w"), highlight=False)
            
            # Write header info
            file_console.print(f"PostgreSQL Permissions Audit Report")
            file_console.print(f"Database: {self.audit_result.database}")
            file_console.print(f"Timestamp: {timestamp}")
            file_console.print(f"Found: {len(self.audit_result.roles)} roles, {len(self.audit_result.schemas)} schemas, {len(self.audit_result.tables)} tables\n")
            
            # Write dangerous permissions section
            if self.audit_result.dangerous_permissions:
                file_console.print("DANGEROUS PERMISSIONS")
                file_console.print("=" * 50)
                
                # Group by risk level
                high_risk = [p for p in self.audit_result.dangerous_permissions if p["risk_level"] == "high"]
                medium_risk = [p for p in self.audit_result.dangerous_permissions if p["risk_level"] == "medium"]
                
                file_console.print("HIGH RISK PERMISSIONS:")
                if high_risk:
                    for perm in high_risk:
                        file_console.print(f"- {perm['type'].title()}: {perm['name']} - {perm.get('privilege', perm.get('issue', 'N/A'))} ({perm['details']})")
                else:
                    file_console.print("  None found")
                
                file_console.print("\nMEDIUM RISK PERMISSIONS:")
                if medium_risk:
                    for perm in medium_risk:
                        file_console.print(f"- {perm['type'].title()}: {perm['name']} - {perm.get('privilege', perm.get('issue', 'N/A'))} ({perm['details']})")
                else:
                    file_console.print("  None found")
                
                file_console.print("\n")
            
            # Write roles section
            file_console.print("DATABASE ROLES")
            file_console.print("=" * 50)
            for role_name, role in sorted(self.audit_result.roles.items()):
                file_console.print(f"Role: {role_name}")
                file_console.print(f"  Superuser: {'Yes' if role.is_superuser else 'No'}")
                file_console.print(f"  Can Login: {'Yes' if role.can_login else 'No'}")
                file_console.print(f"  Can Create DB: {'Yes' if role.can_create_db else 'No'}")
                file_console.print(f"  Can Create Role: {'Yes' if role.can_create_role else 'No'}")
                file_console.print(f"  Member Of: {', '.join(role.member_of) if role.member_of else 'None'}")
                file_console.print("")
            
            # Write schemas section (summarized)
            file_console.print("\nSCHEMA PERMISSIONS")
            file_console.print("=" * 50)
            for schema_name, schema in sorted(self.audit_result.schemas.items()):
                file_console.print(f"Schema: {schema_name}")
                file_console.print(f"  Owner: {schema.owner}")
                if schema.permissions:
                    file_console.print("  Permissions:")
                    for grantee, privileges in sorted(schema.permissions.items()):
                        file_console.print(f"    - {grantee}: {', '.join(privileges)}")
                else:
                    file_console.print("  No additional permissions")
                file_console.print("")
            
            # Write tables section (only dangerous tables to keep the file manageable)
            dangerous_tables = set()
            for perm in self.audit_result.dangerous_permissions:
                if perm["type"] == "table":
                    dangerous_tables.add(perm["name"])
            
            if dangerous_tables:
                file_console.print("\nTABLES WITH DANGEROUS PERMISSIONS")
                file_console.print("=" * 50)
                for table_key in sorted(dangerous_tables):
                    table_info = self.audit_result.tables[table_key]
                    file_console.print(f"Table: {table_key}")
                    file_console.print(f"  Owner: {table_info.owner}")
                    file_console.print("  Permissions:")
                    for grantee, privileges in sorted(table_info.permissions.items()):
                        file_console.print(f"    - {grantee}: {', '.join(privileges)}")
                    file_console.print("")
            
            # Write default ACLs
            if self.audit_result.default_acls:
                file_console.print("\nDEFAULT ACCESS CONTROL LISTS")
                file_console.print("=" * 50)
                for acl in sorted(self.audit_result.default_acls, key=lambda x: (x["schema"], x["object_type"])):
                    file_console.print(f"Schema: {acl['schema']}, Object Type: {acl['object_type']}")
                    file_console.print(f"  Role: {acl['role']}, Grantee: {acl['grantee']}, Privilege: {acl['privilege']}")
                file_console.print("")
            
            # Write remediation recommendations
            file_console.print("\nRECOMMENDED ACTIONS")
            file_console.print("=" * 50)
            if self.audit_result.dangerous_permissions:
                file_console.print("Consider the following actions to improve database security:")
                
                # Role recommendations
                superusers = [p for p in self.audit_result.dangerous_permissions 
                             if p["type"] == "role" and p.get("issue") == "Superuser"]
                if superusers:
                    file_console.print("\n1. Review superuser privileges:")
                    for perm in superusers:
                        file_console.print(f"   - Consider creating a dedicated role with reduced privileges for {perm['name']}")
                
                # Table permission recommendations
                if dangerous_tables:
                    file_console.print("\n2. Consider revoking the following dangerous table privileges:")
                    for perm in self.audit_result.dangerous_permissions:
                        if perm["type"] == "table" and perm["risk_level"] == "high":
                            file_console.print(f"   - Revoke {perm['privilege']} on {perm['name']} from {perm['grantee']}")
                
                # Schema permission recommendations
                dangerous_schemas = [p for p in self.audit_result.dangerous_permissions if p["type"] == "schema"]
                if dangerous_schemas:
                    file_console.print("\n3. Review schema-level permissions:")
                    for perm in dangerous_schemas:
                        file_console.print(f"   - Consider restricting {perm['privilege']} on schema {perm['name']} for {perm['grantee']}")
            else:
                file_console.print("No high-risk permissions were found.")
            
            file_console.print("\nEND OF REPORT")
            
            logger.info(f"Audit report exported to {export_path}")
            file_console.file.close()
        except Exception as e:
            logger.error(f"Error exporting audit report: {e}")
            raise
