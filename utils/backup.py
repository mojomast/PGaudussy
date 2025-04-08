"""
PostgreSQL backup and restore utilities

Provides functionality to backup and restore PostgreSQL databases
using pg_dump and pg_restore.
"""

import os
import sys
import logging
import subprocess
import datetime
import json
import shutil
import pathlib
import platform
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass, field

from pg_service import ServiceConfig
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

logger = logging.getLogger("dbaudit")

@dataclass
class BackupInfo:
    """Information about a database backup"""
    id: str
    timestamp: str
    database: str
    service: str
    backup_type: str
    file_path: str
    size_bytes: int
    metadata: Dict[str, Any] = field(default_factory=dict)


class BackupManager:
    """Manages database backups and restores"""
    
    def __init__(self, service_config: ServiceConfig, backup_dir: Optional[str] = None, 
                 console: Optional[Console] = None):
        """
        Initialize the backup manager
        
        Args:
            service_config: PostgreSQL service configuration
            backup_dir: Directory to store backups (default: ./backups)
            console: Console for output
        """
        self.service_config = service_config
        self.console = console or Console()
        
        # Set up backup directory
        if backup_dir:
            self.backup_dir = pathlib.Path(backup_dir)
        else:
            self.backup_dir = pathlib.Path("./backups")
        
        # Ensure backup directory exists
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up backup history file
        self.history_file = self.backup_dir / "backup_history.json"
        self.backup_history = self._load_backup_history()
        
        # Set up PostgreSQL binary paths
        self.pg_bin_paths = self._get_pg_bin_paths()
    
    def _load_backup_history(self) -> Dict[str, BackupInfo]:
        """Load backup history from disk"""
        if not self.history_file.exists():
            return {}
        
        try:
            with open(self.history_file, 'r') as f:
                history_data = json.load(f)
                
            # Convert to BackupInfo objects
            history = {}
            for backup_id, data in history_data.items():
                history[backup_id] = BackupInfo(
                    id=backup_id,
                    timestamp=data.get("timestamp", ""),
                    database=data.get("database", ""),
                    service=data.get("service", ""),
                    backup_type=data.get("backup_type", ""),
                    file_path=data.get("file_path", ""),
                    size_bytes=data.get("size_bytes", 0),
                    metadata=data.get("metadata", {})
                )
            
            return history
        except Exception as e:
            logger.warning(f"Error loading backup history: {e}")
            return {}
    
    def _save_backup_history(self):
        """Save backup history to disk"""
        try:
            # Convert to serializable dict
            history_data = {}
            for backup_id, info in self.backup_history.items():
                history_data[backup_id] = {
                    "timestamp": info.timestamp,
                    "database": info.database,
                    "service": info.service,
                    "backup_type": info.backup_type,
                    "file_path": info.file_path,
                    "size_bytes": info.size_bytes,
                    "metadata": info.metadata
                }
            
            with open(self.history_file, 'w') as f:
                json.dump(history_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving backup history: {e}")
    
    def _get_pg_bin_paths(self) -> Dict[str, str]:
        """
        Get paths to PostgreSQL binaries based on operating system
        
        Returns:
            Dictionary of binary names to their full paths
        """
        pg_binaries = {
            "pg_dump": "pg_dump",
            "pg_restore": "pg_restore",
            "psql": "psql"
        }
        
        # On Windows, try to find PostgreSQL installation
        if platform.system() == "Windows":
            # Common installation paths for PostgreSQL on Windows
            postgres_paths = [
                pathlib.Path("C:/Program Files/PostgreSQL")
            ]
            
            for base_path in postgres_paths:
                if base_path.exists():
                    # Find latest version
                    versions = [d for d in base_path.iterdir() if d.is_dir()]
                    if versions:
                        # Sort versions and get the latest one
                        versions.sort(reverse=True)
                        latest_version = versions[0]
                        bin_path = latest_version / "bin"
                        
                        if bin_path.exists():
                            # Update paths with full paths to executables
                            for binary, _ in pg_binaries.items():
                                exe_path = bin_path / f"{binary}.exe"
                                if exe_path.exists():
                                    pg_binaries[binary] = str(exe_path)
                            
                            logger.debug(f"Using PostgreSQL binaries from: {bin_path}")
                            break
        
        return pg_binaries
    
    def list_backups(self) -> List[BackupInfo]:
        """List all available backups"""
        return list(self.backup_history.values())
    
    def get_backup_info(self, backup_id: str) -> Optional[BackupInfo]:
        """Get information about a specific backup"""
        return self.backup_history.get(backup_id)
    
    def create_backup(self, backup_type: str = "full", custom_name: Optional[str] = None,
                      dry_run: bool = False) -> Optional[BackupInfo]:
        """
        Create a database backup
        
        Args:
            backup_type: Type of backup ('full', 'schema', 'permissions')
            custom_name: Custom name for the backup file
            dry_run: If True, only show what would be done
            
        Returns:
            BackupInfo if successful, None otherwise
        """
        # Validate backup type
        if backup_type not in ["full", "schema", "permissions"]:
            raise ValueError(f"Invalid backup type: {backup_type}")
        
        # Generate backup ID and filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        database_name = self.service_config.dbname
        service_name = self.service_config.host.replace('.', '_')
        
        if custom_name:
            backup_id = f"{custom_name}_{timestamp}"
        else:
            backup_id = f"{database_name}_{backup_type}_{timestamp}"
        
        # Set file extension based on backup type
        if backup_type == "full":
            file_ext = "dump"
        else:
            file_ext = "sql"
        
        backup_file = self.backup_dir / f"{backup_id}.{file_ext}"
        
        # Build pg_dump command
        cmd = [self.pg_bin_paths["pg_dump"]]
        
        # Add connection parameters
        cmd.extend([
            f"--host={self.service_config.host}",
            f"--port={self.service_config.port}",
            f"--username={self.service_config.user}",
            f"--dbname={self.service_config.dbname}"
        ])
        # Add backup type specific options
        # Add backup type specific options
        if backup_type == "schema":
            cmd.extend(["--schema-only"])
        elif backup_type == "permissions":
            cmd.extend(["--schema-only", "--no-tablespaces"])
        
        # Add output file
        cmd.extend(["-f", str(backup_file)])
        
        # For a custom format that can be used with pg_restore
        if backup_type == "full":
            cmd.append("--format=c")
        
        # Set environment variables for password
        # Set environment variables for password and SSL
        env = os.environ.copy()
        env["PGPASSWORD"] = self.service_config.password
        
        # Set SSL mode in environment if specified
        if self.service_config.sslmode:
            env["PGSSLMODE"] = self.service_config.sslmode
        logger.debug(f"Backup command: {' '.join(cmd)}")
        
        if dry_run:
            self.console.print(f"[yellow]DRY RUN: Would execute: {' '.join(cmd)}[/yellow]")
            return None
        
        try:
            # Show progress spinner during backup
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=self.console
            ) as progress:
                task = progress.add_task(f"Backing up {database_name} ({backup_type})...", total=None)
                
                # Execute pg_dump
                result = subprocess.run(
                    cmd,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )
                
                progress.update(task, completed=True)
                
                # Log more details if the command failed
                if result.returncode != 0:
                    logger.error(f"pg_dump command failed: {' '.join(cmd)}")
                    logger.error(f"Error output: {result.stderr}")
            
            if result.returncode != 0:
                self.console.print(f"[bold red]Backup failed:[/bold red] {result.stderr}")
                return None
            
            # Get file size
            file_size = os.path.getsize(backup_file)
            
            # Create backup info
            backup_info = BackupInfo(
                id=backup_id,
                timestamp=timestamp,
                database=database_name,
                service=service_name,
                backup_type=backup_type,
                file_path=str(backup_file),
                size_bytes=file_size,
                metadata={
                    "host": self.service_config.host,
                    "port": self.service_config.port,
                    "user": self.service_config.user,
                    "command": " ".join(cmd)
                }
            )
            
            # Add to history
            self.backup_history[backup_id] = backup_info
            self._save_backup_history()
            
            size_mb = file_size / (1024 * 1024)
            self.console.print(f"[green]Backup completed successfully:[/green] {backup_file} ({size_mb:.2f} MB)")
            
            return backup_info
            
        except Exception as e:
            self.console.print(f"[bold red]Error creating backup:[/bold red] {str(e)}")
            if backup_file.exists():
                backup_file.unlink()
            logger.error(f"Backup error: {e}")
            return None
    
    def restore_backup(self, backup_id: str = None, backup_file: str = None, 
                       dry_run: bool = False) -> bool:
        """
        Restore a database from backup
        
        Args:
            backup_id: ID of the backup to restore
            backup_file: Direct path to a backup file (alternative to backup_id)
            dry_run: If True, only show what would be done
            
        Returns:
            True if successful, False otherwise
        """
        file_to_restore = None
        
        if backup_id:
            # Get backup info from history
            backup_info = self.get_backup_info(backup_id)
            if not backup_info:
                self.console.print(f"[bold red]Error:[/bold red] Backup ID '{backup_id}' not found in history")
                return False
            
            file_to_restore = pathlib.Path(backup_info.file_path)
            backup_type = backup_info.backup_type
        elif backup_file:
            file_to_restore = pathlib.Path(backup_file)
            # Guess backup type from extension
            if file_to_restore.suffix == '.dump':
                backup_type = "full"
            else:
                backup_type = "schema"  # assume schema or permissions
        else:
            self.console.print("[bold red]Error:[/bold red] Must specify either backup_id or backup_file")
            return False
        
        if not file_to_restore.exists():
            self.console.print(f"[bold red]Error:[/bold red] Backup file does not exist: {file_to_restore}")
            return False
        
        # Build restore command
        database_name = self.service_config.dbname
        
        if backup_type == "full" and file_to_restore.suffix == '.dump':
            # Use pg_restore for custom format dumps
            cmd = [self.pg_bin_paths["pg_restore"]]
            cmd.extend([
                f"--host={self.service_config.host}",
                f"--port={self.service_config.port}",
                f"--username={self.service_config.user}",
                f"--dbname={self.service_config.dbname}",
                "--clean",  # Clean (drop) database objects before recreating
                "--if-exists",  # Don't error if objects don't exist
            ])
            
            cmd.append(str(file_to_restore))
        else:
            # Use psql for SQL format dumps
            cmd = [self.pg_bin_paths["psql"]]
            cmd.extend([
                f"--host={self.service_config.host}",
                f"--port={self.service_config.port}",
                f"--username={self.service_config.user}",
                f"--dbname={self.service_config.dbname}",
            ])
            
            cmd.extend(["-f", str(file_to_restore)])
        
        # Set environment variables for password
        # Set environment variables for password and SSL
        env = os.environ.copy()
        env["PGPASSWORD"] = self.service_config.password
        
        # Set SSL mode in environment if specified  
        if self.service_config.sslmode:
            env["PGSSLMODE"] = self.service_config.sslmode
        logger.debug(f"Restore command: {' '.join(cmd)}")
        
        if dry_run:
            self.console.print(f"[yellow]DRY RUN: Would execute: {' '.join(cmd)}[/yellow]")
            return True
        
        try:
            # Show progress spinner during restore
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=self.console
            ) as progress:
                task = progress.add_task(f"Restoring {database_name} from backup...", total=None)
                
                # Execute restore command
                result = subprocess.run(
                    cmd,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )
                
                progress.update(task, completed=True)
            
            if result.returncode != 0:
                self.console.print(f"[bold red]Restore failed:[/bold red] {result.stderr}")
                return False
            
            self.console.print(f"[green]Restore completed successfully[/green]")
            return True
            
        except Exception as e:
            self.console.print(f"[bold red]Error restoring backup:[/bold red] {str(e)}")
            logger.error(f"Restore error: {e}")
            return False
    
    def delete_backup(self, backup_id: str, dry_run: bool = False) -> bool:
        """
        Delete a backup file and remove from history
        
        Args:
            backup_id: ID of the backup to delete
            dry_run: If True, only show what would be done
            
        Returns:
            True if successful, False otherwise
        """
        backup_info = self.get_backup_info(backup_id)
        if not backup_info:
            self.console.print(f"[bold red]Error:[/bold red] Backup ID '{backup_id}' not found in history")
            return False
        
        backup_file = pathlib.Path(backup_info.file_path)
        
        if dry_run:
            self.console.print(f"[yellow]DRY RUN: Would delete backup: {backup_file}[/yellow]")
            return True
        
        try:
            if backup_file.exists():
                backup_file.unlink()
            
            # Remove from history
            del self.backup_history[backup_id]
            self._save_backup_history()
            
            self.console.print(f"[green]Backup deleted:[/green] {backup_id}")
            return True
            
        except Exception as e:
            self.console.print(f"[bold red]Error deleting backup:[/bold red] {str(e)}")
            logger.error(f"Delete backup error: {e}")
