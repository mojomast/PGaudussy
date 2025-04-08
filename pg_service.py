"""
PostgreSQL service configuration parser

Parses pg_service.conf files to extract connection information for PostgreSQL databases.
"""

import os
import re
import pathlib
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger("dbaudit")

@dataclass
class ServiceConfig:
    """PostgreSQL service configuration data"""
    host: str
    port: str
    dbname: str
    user: str
    password: str
    sslmode: Optional[str] = None
    
    def get_connection_string(self) -> str:
        """Return connection string for this service"""
        conn_parts = [
            f"host={self.host}",
            f"port={self.port}",
            f"dbname={self.dbname}",
            f"user={self.user}",
            f"password={self.password}"
        ]
        
        if self.sslmode:
            conn_parts.append(f"sslmode={self.sslmode}")
            
        return " ".join(conn_parts)

class PgServiceConfigParser:
    """Parser for PostgreSQL service configuration files"""
    
    def __init__(self, config_path=None):
        """Initialize with path to pg_service.conf"""
        if config_path:
            self.config_path = pathlib.Path(config_path)
        else:
            # Always use the pg_service.conf in the project directory
            self.config_path = pathlib.Path(os.path.join(os.getcwd(), 'pg_service.conf'))
            
            # Create the file if it doesn't exist
            if not self.config_path.exists():
                # Ensure parent directory exists
                self.config_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Create empty pg_service.conf with comments
                with open(self.config_path, 'w') as f:
                    f.write("""# PostgreSQL Service Configuration File
# Format: [service_name]
#         host=hostname
#         port=port
#         dbname=database_name
#         user=username
#         password=password (optional)
""")
                logger.info(f"Created new pg_service.conf at {self.config_path}")
        
        self.services: Dict[str, ServiceConfig] = {}
        self._parse_config()
    
    def _parse_config(self):
        """Parse the pg_service.conf file"""
        if not self.config_path.exists():
            logger.warning(f"pg_service.conf not found at {self.config_path}, using empty configuration")
            return
        
        current_service = None
        service_params = {}
        line_number = 0
        
        try:
            with open(self.config_path, 'r') as f:
                for line_number, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Service section header
                    service_match = re.match(r'\[(.*)\]', line)
                    if service_match:
                        # If we were parsing a service, save it
                        if current_service and service_params:
                            try:
                                self._add_service(current_service, service_params)
                            except Exception as e:
                                logger.warning(f"Invalid service config for {current_service} at line {line_number-1}: {e}")
                        
                        # Start new service
                        current_service = service_match.group(1)
                        if not current_service:
                            logger.warning(f"Empty service name at line {line_number}, skipping")
                            current_service = None
                        service_params = {}
                        continue
                    
                    # Service parameters - handle spaces around equals sign
                    if current_service:
                        # More flexible regex to handle spaces around equals sign
                        param_match = re.match(r'(\w+)\s*=\s*(.*)', line)
                        if param_match:
                            key, value = param_match.groups()
                            # Strip spaces from both key and value
                            service_params[key.strip()] = value.strip()
                        else:
                            logger.warning(f"Invalid parameter format at line {line_number}: '{line}'")
                
                # Save the last service if any
                if current_service and service_params:
                    try:
                        self._add_service(current_service, service_params)
                    except Exception as e:
                        logger.warning(f"Invalid service config for {current_service} at end of file: {e}")
        
        except Exception as e:
            logger.error(f"Error parsing pg_service.conf at line {line_number}: {e}")
            # Don't raise an exception, just log the error and continue with an empty configuration
    
    def _add_service(self, service_name: str, params: dict):
        """Add a service to the services dictionary after validating parameters"""
        # Check for required parameters
        required_params = ['host', 'dbname', 'user']
        missing = [param for param in required_params if param not in params]
        
        if missing:
            logger.warning(f"Service '{service_name}' is missing required parameters: {', '.join(missing)}")
            # Still create the service, but with default values
            for param in missing:
                if param == 'host':
                    params['host'] = 'localhost'
                elif param == 'port':
                    params['port'] = '5432'
                else:
                    params[param] = ''
        
        # Ensure port is a string
        if 'port' in params and not isinstance(params['port'], str):
            params['port'] = str(params['port'])
        elif 'port' not in params:
            params['port'] = '5432'
            
        try:
            self.services[service_name] = ServiceConfig(**params)
        except TypeError as e:
            logger.warning(f"Could not create service '{service_name}': {e}")
            raise
    
    def get_available_services(self) -> List[str]:
        """Return list of available service names"""
        return list(self.services.keys())
    
    def get_service_config(self, service_name: str) -> ServiceConfig:
        """Return configuration for specified service"""
        if service_name not in self.services:
            raise KeyError(f"Service '{service_name}' not found in configuration")
        
        return self.services[service_name]
