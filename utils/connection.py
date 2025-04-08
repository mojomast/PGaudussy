"""
PostgreSQL connection utilities
"""

import logging
from typing import Optional
import psycopg
from pg_service import ServiceConfig

logger = logging.getLogger("dbaudit")

class PostgresConnection:
    """Manages PostgreSQL database connections using service configurations"""
    
    def __init__(self, service_config: ServiceConfig):
        """Initialize with a service configuration"""
        self.service_config = service_config
        self.connection: Optional[psycopg.Connection] = None
        self._autocommit = False
    
    @property
    def closed(self) -> bool:
        """Return True if connection is closed or not established yet"""
        return self.connection is None or self.connection.closed
    
    def connect(self) -> psycopg.Connection:
        """Establish connection to the PostgreSQL database"""
        if self.connection and not self.closed:
            return self.connection
        
        try:
            logger.debug(f"Connecting to {self.service_config.dbname} on {self.service_config.host}...")
            conn_string = self.service_config.get_connection_string()
            
            # Attempt to connect with a timeout
            self.connection = psycopg.connect(
                conninfo=conn_string,
                connect_timeout=10  # 10 seconds timeout
            )
            
            # Set autocommit mode if needed
            if self._autocommit:
                self.connection.autocommit = True
                
            logger.debug("Connection established successfully")
            return self.connection
        except psycopg.OperationalError as e:
            # Provide more helpful error message for common connection issues
            if "could not connect to server" in str(e):
                logger.error(f"Could not connect to PostgreSQL server at {self.service_config.host}:{self.service_config.port}")
                logger.error("Please check that the server is running and that network connectivity is available")
            elif "password authentication failed" in str(e):
                logger.error(f"Authentication failed for user '{self.service_config.user}'")
                logger.error("Please check your username and password")
            elif "database" in str(e) and "does not exist" in str(e):
                logger.error(f"Database '{self.service_config.dbname}' does not exist")
            else:
                logger.error(f"Connection error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected connection error: {e}")
            raise
    
    def set_autocommit(self, autocommit: bool):
        """Set autocommit mode for the connection"""
        self._autocommit = autocommit
        if self.connection and not self.closed:
            self.connection.autocommit = autocommit
    
    def close(self):
        """Close the database connection if open"""
        if self.connection and not self.closed:
            try:
                self.connection.close()
                logger.debug("Connection closed")
            except Exception as e:
                logger.warning(f"Error while closing connection: {e}")
            finally:
                self.connection = None
    
    def __enter__(self) -> psycopg.Connection:
        """Context manager entry point"""
        return self.connect()
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit point"""
        # Don't close the connection here to allow for reuse
        # The connection will be closed when the object is garbage collected
        # or when close() is explicitly called
        pass
