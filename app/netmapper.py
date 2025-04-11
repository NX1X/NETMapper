#!/usr/bin/env python3
"""
NETMapper SSH

This is the main script for the SSH-based network device tracking system.
It provides command-line interface for polling network switches,
managing the database, and other operations.
"""

import os
import sys
import json
import time
import logging
import argparse
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

from ssh_switch_manager import SwitchManager
from credential_manager import CredentialManager
from encrypted_db_manager import DatabaseManager

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("netmapper.log")
    ]
)
logger = logging.getLogger("netmapper")

class NETMapper:
    """Main class for the NETMapper application."""
    
    def __init__(self, 
                config_path: str = None,
                db_path: str = None, 
                credential_path: str = None,
                use_encryption: bool = False,
                encryption_key: str = None):
        """
        Initialize the NETMapper.
        
        Args:
            config_path: Path to configuration file
            db_path: Path to database file
            credential_path: Path to credential file
            use_encryption: Whether to use encryption
            encryption_key: Encryption key if encryption is enabled
        """
        # Load configuration from file if provided
        self.config = {}
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    self.config = json.load(f)
                logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                logger.error(f"Error loading configuration: {str(e)}")
        
        # Use provided parameters or get from config or environment
        self.db_path = db_path or self.config.get('database_path') or os.environ.get('DATABASE_PATH', 'data/device_mappings.db')
        self.credential_path = credential_path or self.config.get('credentials_path') or os.environ.get('CREDENTIALS_PATH', 'data/credentials.json')
        self.use_encryption = use_encryption or self.config.get('use_encryption', False) or os.environ.get('USE_ENCRYPTION', 'false').lower() == 'true'
        self.encryption_key = encryption_key or self.config.get('encryption_key') or os.environ.get('ENCRYPTION_KEY')
        
        # Create directories if they don't exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.credential_path), exist_ok=True)
        
        # Initialize components
        self.db_manager = DatabaseManager(
            db_path=self.db_path,
            encryption_key=self.encryption_key,
            use_encryption=self.use_encryption
        )
        
        self.credential_manager = CredentialManager(
            credential_file=self.credential_path,
            encryption_key=self.encryption_key,
            use_encryption=True  # Always encrypt credentials
        )
        
        self.switch_manager = SwitchManager(
            db_manager=self.db_manager
        )
        
        logger.info("NETMapper initialized")
        logger.info(f"Database: {self.db_path}")
        logger.info(f"Credentials: {self.credential_path}")
        logger.info(f"Encryption: {self.use_encryption}")
    
    def poll_switch(self, hostname: str, username: str, password: str, 
                   port: int = 22, switch_name: Optional[str] = None) -> int:
        """
        Poll a single switch and update the database.
        
        Args:
            hostname: Hostname or IP of the switch
            username: SSH username
            password: SSH password
            port: SSH port
            switch_name: Friendly name for the switch
            
        Returns:
            Number of device entries processed
        """
        logger.info(f"Polling switch {hostname}")
        
        try:
            entries, count = self.switch_manager.fetch_and_process_switch_data(
                hostname=hostname,
                username=username,
                password=password,
                port=port,
                switch_name=switch_name
            )
            
            logger.info(f"Processed {count} entries from {hostname}")
            return count
        except Exception as e:
            logger.error(f"Error polling switch {hostname}: {str(e)}")
            return 0
    
    def poll_all_switches(self) -> int:
        """
        Poll all switches with stored credentials.
        
        Returns:
            Total number of device entries processed
        """
        logger.info("Polling all switches with stored credentials")
        
        credentials = self.credential_manager.load_credentials()
        if not credentials:
            logger.warning("No credentials found")
            return 0
        
        total_count = 0
        for cred in credentials:
            try:
                count = self.poll_switch(
                    hostname=cred['hostname'],
                    username=cred['username'],
                    password=cred['password'],
                    port=cred.get('port', 22),
                    switch_name=cred.get('name')
                )
                total_count += count
            except Exception as e:
                logger.error(f"Error polling switch {cred['hostname']}: {str(e)}")
        
        logger.info(f"Finished polling all switches, processed {total_count} entries")
        return total_count
    
    def export_data(self, output_file: str, format: str = 'json', 
                  filters: Optional[Dict[str, Any]] = None) -> int:
        """
        Export data from the database.
        
        Args:
            output_file: Path to save the export
            format: Export format ('json' or 'csv')
            filters: Optional filters to apply
            
        Returns:
            Number of exported entries
        """
        logger.info(f"Exporting data to {format} format")
        
        if format.lower() == 'csv':
            return self.db_manager.export_to_csv(output_file, filters)
        else:
            return self.db_manager.export_to_json(output_file, filters)
    
    def cleanup_database(self, days: int = 30) -> int:
        """
        Clean up stale entries from the database.
        
        Args:
            days: Number of days to consider entries stale
            
        Returns:
            Number of entries removed
        """
        logger.info(f"Cleaning up entries older than {days} days")
        return self.db_manager.cleanup_stale_mappings(days)
    
    def run_daemon(self, interval: int = 3600) -> None:
        """
        Run in daemon mode, polling switches at regular intervals.
        
        Args:
            interval: Polling interval in seconds
        """
        logger.info(f"Starting daemon mode with interval of {interval} seconds")
        
        try:
            while True:
                start_time = time.time()
                
                # Poll all switches
                count = self.poll_all_switches()
                
                # Clean up old entries if configured
                cleanup_days = self.config.get('cleanup_days')
                if cleanup_days:
                    try:
                        days = int(cleanup_days)
                        deleted = self.cleanup_database(days)
                        logger.info(f"Cleaned up {deleted} stale entries")
                    except ValueError:
                        logger.error(f"Invalid cleanup_days value: {cleanup_days}")
                
                # Export data if configured
                export_path = self.config.get('export_path')
                if export_path:
                    # Generate timestamped filename
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    export_file = f"{export_path}/device_mappings_{timestamp}.json"
                    
                    # Create directory if it doesn't exist
                    os.makedirs(os.path.dirname(export_file), exist_ok=True)
                    
                    # Export data
                    exported = self.export_data(export_file)
                    logger.info(f"Exported {exported} entries to {export_file}")
                
                # Calculate time spent and sleep for the remaining interval
                elapsed = time.time() - start_time
                sleep_time = max(0, interval - elapsed)
                
                logger.info(f"Cycle completed in {elapsed:.1f} seconds, "
                          f"sleeping for {sleep_time:.1f} seconds")
                
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    
        except KeyboardInterrupt:
            logger.info("Daemon stopped by user")
        except Exception as e:
            logger.error(f"Error in daemon mode: {str(e)}")
            raise
    
    def close(self) -> None:
        """Clean up resources."""
        self.db_manager.close()
        logger.info("NETMapper resources closed")


def main():
    """Main entry point for the CLI application."""
    parser = argparse.ArgumentParser(description='NETMapper SSH - Network Device Location Tracker')
    
    # Configuration options
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-d', '--db', help='Database file path')
    parser.add_argument('--credentials', help='Credentials file path')
    parser.add_argument('--encrypt', action='store_true', help='Enable database encryption')
    parser.add_argument('--key', help='Encryption key (required if encryption is enabled)')
    
    # Operation modes
    parser.add_argument('--daemon', action='store_true', help='Run in daemon mode')
    parser.add_argument('--interval', type=int, default=3600, 
                         help='Polling interval in seconds (for daemon mode)')
    
    # Switch polling options
    parser.add_argument('-s', '--switch', help='IP address or hostname of switch to poll')
    parser.add_argument('-u', '--username', help='SSH username')
    parser.add_argument('-p', '--password', help='SSH password')
    parser.add_argument('--port', type=int, default=22, help='SSH port')
    parser.add_argument('--poll-all', action='store_true', help='Poll all switches with stored credentials')
    
    # Credential management
    parser.add_argument('--add-credential', action='store_true', 
                       help='Add a new credential (requires --switch, --username, --password)')
    parser.add_argument('--import-credentials', help='Import credentials from CSV file')
    parser.add_argument('--export-credentials', help='Export credentials to CSV file')
    parser.add_argument('--list-credentials', action='store_true', help='List all stored credentials')
    
    # Database operations
    parser.add_argument('--cleanup', type=int, help='Clean up entries older than specified days')
    parser.add_argument('-o', '--output', help='Output JSON/CSV file')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Export format')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    
    args = parser.parse_args()
    
    # Initialize NETMapper
    mapper = NETMapper(
        config_path=args.config,
        db_path=args.db,
        credential_path=args.credentials,
        use_encryption=args.encrypt,
        encryption_key=args.key
    )
    
    try:
        # Handle credential management
        if args.add_credential:
            if not args.switch or not args.username or not args.password:
                logger.error("Missing required parameters for adding credential")
                parser.print_help()
                return 1
            
            success = mapper.credential_manager.add_credential(
                hostname=args.switch,
                username=args.username,
                password=args.password,
                port=args.port
            )
            
            if success:
                print(f"Successfully added credential for {args.switch}")
            else:
                print(f"Failed to add credential for {args.switch}")
                return 1
        
        elif args.import_credentials:
            if not os.path.exists(args.import_credentials):
                logger.error(f"Import file not found: {args.import_credentials}")
                return 1
            
            success, failure = mapper.credential_manager.import_from_csv(args.import_credentials)
            print(f"Imported {success} credentials, {failure} failures")
        
        elif args.export_credentials:
            count = mapper.credential_manager.export_to_csv(
                args.export_credentials, 
                include_passwords=False
            )
            print(f"Exported {count} credentials to {args.export_credentials}")
        
        elif args.list_credentials:
            credentials = mapper.credential_manager.load_credentials()
            print(f"Found {len(credentials)} credentials:")
            for cred in credentials:
                print(f"  {cred.get('name', cred['hostname'])} ({cred['hostname']}): "
                     f"{cred['username']}, Port: {cred.get('port', 22)}")
        
        # Handle switch polling
        elif args.switch and args.username and args.password:
            # Poll a single switch
            count = mapper.poll_switch(
                hostname=args.switch,
                username=args.username,
                password=args.password,
                port=args.port
            )
            print(f"Processed {count} entries from {args.switch}")
        
        elif args.poll_all:
            # Poll all switches with stored credentials
            count = mapper.poll_all_switches()
            print(f"Processed {count} entries from all switches")
        
        # Handle database operations
        elif args.cleanup:
            # Clean up stale entries
            deleted = mapper.cleanup_database(args.cleanup)
            print(f"Cleaned up {deleted} stale entries older than {args.cleanup} days")
        
        elif args.output:
            # Export data
            count = mapper.export_data(args.output, args.format)
            print(f"Exported {count} entries to {args.output}")
        
        elif args.stats:
            # Show database statistics
            stats = mapper.db_manager.get_stats()
            print("Database Statistics:")
            print(f"  Total Devices: {stats['total_devices']}")
            print(f"  Total Switches: {stats['total_switches']}")
            print(f"  Newest Record: {stats['newest_record']}")
            print(f"  Oldest Record: {stats['oldest_record']}")
            print(f"  Updates in last 24h: {stats['updates_last_24h']}")
            print(f"  Encryption Enabled: {stats['encryption_enabled']}")
            print("  VLAN Distribution:")
            for vlan, count in stats['vlan_distribution'].items():
                print(f"    VLAN {vlan}: {count} devices")
        
        # Run in daemon mode if requested
        elif args.daemon:
            mapper.run_daemon(args.interval)
        
        else:
            # No operation specified
            parser.print_help()
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return 1
    finally:
        mapper.close()


if __name__ == "__main__":
    sys.exit(main())
