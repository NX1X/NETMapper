#!/usr/bin/env python3
"""
Encrypted Database Manager

This module provides database operations for storing network device data
with support for both encrypted and plain storage.
"""

import os
import sqlite3
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
from cryptography.fernet import Fernet

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("encrypted_db_manager")

class DatabaseManager:
    """
    Database manager for storing network device data with encryption support.
    """
    
    def __init__(self, 
                db_path: str = 'data/device_mappings.db', 
                encryption_key: Optional[str] = None,
                use_encryption: bool = False):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to the database file
            encryption_key: Encryption key for database
            use_encryption: Whether to encrypt sensitive data
        """
        self.db_path = db_path
        self.use_encryption = use_encryption
        self.encryption_key = encryption_key
        self.fernet = None
        self.conn = None
        
        # Set up encryption if requested
        if use_encryption and encryption_key:
            self.fernet = Fernet(encryption_key.encode())
        
        # Initialize database
        self.setup_database()
    
    def encrypt(self, data: str) -> str:
        """Encrypt a string if encryption is enabled."""
        if not self.use_encryption or not self.fernet:
            return data
        
        return self.fernet.encrypt(data.encode()).decode()
    
    def decrypt(self, data: str) -> str:
        """Decrypt a string if it's encrypted."""
        if not self.use_encryption or not self.fernet:
            return data
        
        try:
            return self.fernet.decrypt(data.encode()).decode()
        except Exception as e:
            logger.error(f"Error decrypting data: {str(e)}")
            return data  # Return original data if decryption fails
    
    def setup_database(self) -> None:
        """Create the necessary database structure if it doesn't exist."""
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        
        # Enable foreign keys
        cursor.execute('PRAGMA foreign_keys = ON')
        
        # Create switches table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS switches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            name TEXT
        )
        ''')
        
        # Create device_mappings table (enhanced from the original mac_mappings)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT,
            ip_address TEXT,
            vlan TEXT,
            switch_id INTEGER,
            switch_port TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            encrypted INTEGER DEFAULT 0,
            FOREIGN KEY (switch_id) REFERENCES switches (id),
            UNIQUE (mac_address, switch_id, switch_port)
        )
        ''')
        
        # Create an index for faster lookups
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_mac_address ON device_mappings(mac_address)
        ''')
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_ip_address ON device_mappings(ip_address)
        ''')
        
        self.conn.commit()
        logger.info("Database setup complete")
    
    def get_or_create_switch(self, ip: str, name: Optional[str] = None) -> int:
        """
        Get the switch ID from the database or create a new entry.
        
        Args:
            ip: IP address of the switch
            name: Optional friendly name for the switch
            
        Returns:
            Switch ID in the database
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT id FROM switches WHERE ip = ?', (ip,))
        result = cursor.fetchone()
        
        if result:
            switch_id = result[0]
            # Update name if provided and different
            if name:
                cursor.execute('UPDATE switches SET name = ? WHERE id = ?', (name, switch_id))
                self.conn.commit()
        else:
            cursor.execute(
                'INSERT INTO switches (ip, name) VALUES (?, ?)',
                (ip, name or ip)
            )
            switch_id = cursor.lastrowid
            self.conn.commit()
            
        return switch_id
    
    def update_device_mapping(self, mac_address: str, switch_id: int, 
                             switch_port: str, vlan: str = "", 
                             ip_address: str = "") -> None:
        """
        Update or insert a device mapping with current timestamp.
        
        Args:
            mac_address: MAC address of the device
            switch_id: ID of the switch in the database
            switch_port: Port on the switch
            vlan: VLAN ID (optional)
            ip_address: IP address of the device (optional)
        """
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.cursor()
        
        # Encrypt data if needed
        encrypted = False
        if self.use_encryption and self.fernet:
            mac_address = self.encrypt(mac_address)
            if ip_address:
                ip_address = self.encrypt(ip_address)
            encrypted = True
        
        # Try to update an existing entry first
        cursor.execute('''
        UPDATE device_mappings
        SET last_seen = ?, ip_address = ?, vlan = ?, encrypted = ?
        WHERE mac_address = ? AND switch_id = ? AND switch_port = ?
        ''', (now, ip_address, vlan, int(encrypted), mac_address, switch_id, switch_port))
        
        # If no rows were updated, insert a new entry
        if cursor.rowcount == 0:
            cursor.execute('''
            INSERT INTO device_mappings 
            (mac_address, ip_address, vlan, switch_id, switch_port, first_seen, last_seen, encrypted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (mac_address, ip_address, vlan, switch_id, switch_port, now, now, int(encrypted)))
            
        self.conn.commit()
    
    def get_all_mappings(self, days: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Retrieve all device mappings from the database.
        
        Args:
            days: Optional filter for entries updated in the last N days
            
        Returns:
            List of device mapping dictionaries
        """
        cursor = self.conn.cursor()
        
        query = '''
        SELECT d.mac_address, d.ip_address, d.vlan, s.ip, s.name, 
               d.switch_port, d.first_seen, d.last_seen, d.encrypted
        FROM device_mappings d
        JOIN switches s ON d.switch_id = s.id
        '''
        
        params = []
        if days is not None:
            query += ' WHERE datetime(d.last_seen) > datetime("now", ?)'
            params.append(f'-{days} days')
        
        query += ' ORDER BY d.last_seen DESC'
        
        cursor.execute(query, params)
        
        results = []
        for row in cursor.fetchall():
            mac_address, ip_address, vlan, switch_ip, switch_name, \
            switch_port, first_seen, last_seen, encrypted = row
            
            # Decrypt if necessary
            if encrypted:
                try:
                    mac_address = self.decrypt(mac_address)
                    if ip_address:
                        ip_address = self.decrypt(ip_address)
                except Exception as e:
                    logger.error(f"Decryption error: {str(e)}")
                    # Keep the encrypted version if decryption fails
            
            results.append({
                "mac_address": mac_address,
                "ip_address": ip_address,
                "vlan": vlan,
                "switch_ip": switch_ip,
                "switch_name": switch_name,
                "switch_port": switch_port,
                "first_seen": first_seen,
                "last_present": last_seen  # Using 'last_present' as specified in requirements
            })
            
        return results
    
    def search_mappings(self, 
                       mac_filter: Optional[str] = None,
                       ip_filter: Optional[str] = None,
                       vlan_filter: Optional[str] = None,
                       switch_filter: Optional[str] = None,
                       port_filter: Optional[str] = None,
                       days_filter: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Search for device mappings with various filters.
        
        Args:
            mac_filter: Filter by MAC address (partial match)
            ip_filter: Filter by IP address (partial match)
            vlan_filter: Filter by VLAN
            switch_filter: Filter by switch IP or name (partial match)
            port_filter: Filter by port name (partial match)
            days_filter: Only include entries updated in the last N days
            
        Returns:
            List of matching device mapping dictionaries
        """
        cursor = self.conn.cursor()
        
        query = '''
        SELECT d.mac_address, d.ip_address, d.vlan, s.ip, s.name, 
               d.switch_port, d.first_seen, d.last_seen, d.encrypted
        FROM device_mappings d
        JOIN switches s ON d.switch_id = s.id
        WHERE 1=1
        '''
        
        params = []
        
        # Apply filters - note that encrypted data complicates filtering
        if self.use_encryption and self.fernet:
            # For encrypted databases, we need to retrieve all records and filter in memory
            query_with_days = query
            if days_filter is not None:
                query_with_days += ' AND datetime(d.last_seen) > datetime("now", ?)'
                params.append(f'-{days_filter} days')
                
            if switch_filter:
                query_with_days += ' AND (s.ip LIKE ? OR s.name LIKE ?)'
                params.append(f'%{switch_filter}%')
                params.append(f'%{switch_filter}%')
                
            if port_filter:
                query_with_days += ' AND d.switch_port LIKE ?'
                params.append(f'%{port_filter}%')
                
            query_with_days += ' ORDER BY d.last_seen DESC'
            cursor.execute(query_with_days, params)
            
            # Fetch all and filter in memory for encrypted fields
            results = []
            for row in cursor.fetchall():
                mac_address, ip_address, vlan, switch_ip, switch_name, \
                switch_port, first_seen, last_seen, encrypted = row
                
                # Decrypt
                if encrypted:
                    try:
                        mac_address_decrypted = self.decrypt(mac_address)
                        ip_address_decrypted = self.decrypt(ip_address) if ip_address else ""
                    except Exception as e:
                        logger.error(f"Decryption error: {str(e)}")
                        continue  # Skip this record if decryption fails
                else:
                    mac_address_decrypted = mac_address
                    ip_address_decrypted = ip_address
                
                # Apply filters manually on decrypted data
                if mac_filter and mac_filter.lower() not in mac_address_decrypted.lower():
                    continue
                    
                if ip_filter and ip_filter.lower() not in ip_address_decrypted.lower():
                    continue
                    
                if vlan_filter and vlan_filter != vlan:
                    continue
                
                results.append({
                    "mac_address": mac_address_decrypted,
                    "ip_address": ip_address_decrypted,
                    "vlan": vlan,
                    "switch_ip": switch_ip,
                    "switch_name": switch_name,
                    "switch_port": switch_port,
                    "first_seen": first_seen,
                    "last_present": last_seen
                })
                
            return results
        else:
            # For unencrypted databases, we can filter directly in the query
            if mac_filter:
                query += ' AND d.mac_address LIKE ?'
                params.append(f'%{mac_filter}%')
                
            if ip_filter:
                query += ' AND d.ip_address LIKE ?'
                params.append(f'%{ip_filter}%')
                
            if vlan_filter:
                query += ' AND d.vlan = ?'
                params.append(vlan_filter)
                
            if switch_filter:
                query += ' AND (s.ip LIKE ? OR s.name LIKE ?)'
                params.append(f'%{switch_filter}%')
                params.append(f'%{switch_filter}%')
                
            if port_filter:
                query += ' AND d.switch_port LIKE ?'
                params.append(f'%{port_filter}%')
                
            if days_filter is not None:
                query += ' AND datetime(d.last_seen) > datetime("now", ?)'
                params.append(f'-{days_filter} days')
                
            query += ' ORDER BY d.last_seen DESC'
            
            cursor.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                mac_address, ip_address, vlan, switch_ip, switch_name, \
                switch_port, first_seen, last_seen, encrypted = row
                
                # Decrypt if needed
                if encrypted:
                    try:
                        mac_address = self.decrypt(mac_address)
                        if ip_address:
                            ip_address = self.decrypt(ip_address)
                    except Exception as e:
                        logger.error(f"Decryption error: {str(e)}")
                
                results.append({
                    "mac_address": mac_address,
                    "ip_address": ip_address,
                    "vlan": vlan,
                    "switch_ip": switch_ip,
                    "switch_name": switch_name,
                    "switch_port": switch_port,
                    "first_seen": first_seen,
                    "last_present": last_seen
                })
                
            return results
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the database.
        
        Returns:
            Dictionary with database statistics
        """
        cursor = self.conn.cursor()
        
        # Get total device count
        cursor.execute('SELECT COUNT(*) as count FROM device_mappings')
        device_count = cursor.fetchone()[0]
        
        # Get switch count
        cursor.execute('SELECT COUNT(*) as count FROM switches')
        switch_count = cursor.fetchone()[0]
        
        # Get newest record
        cursor.execute('SELECT MAX(last_seen) as newest FROM device_mappings')
        newest = cursor.fetchone()[0]
        
        # Get oldest record
        cursor.execute('SELECT MIN(first_seen) as oldest FROM device_mappings')
        oldest = cursor.fetchone()[0]
        
        # Get count of updates in the last 24 hours
        cursor.execute('''
        SELECT COUNT(*) as count 
        FROM device_mappings 
        WHERE datetime(last_seen) > datetime("now", "-1 day")
        ''')
        recent_count = cursor.fetchone()[0]
        
        # Get VLAN distribution
        cursor.execute('''
        SELECT vlan, COUNT(*) as count
        FROM device_mappings
        GROUP BY vlan
        ORDER BY count DESC
        ''')
        vlan_distribution = {row[0] or "None": row[1] for row in cursor.fetchall()}
        
        return {
            "total_devices": device_count,
            "total_switches": switch_count,
            "newest_record": newest,
            "oldest_record": oldest,
            "updates_last_24h": recent_count,
            "vlan_distribution": vlan_distribution,
            "encryption_enabled": self.use_encryption and self.fernet is not None
        }
    
    def cleanup_stale_mappings(self, days: int = 30) -> int:
        """
        Remove mappings that haven't been updated in the specified number of days.
        
        Args:
            days: Number of days to consider entries stale
            
        Returns:
            Number of deleted entries
        """
        cursor = self.conn.cursor()
        cursor.execute('''
        DELETE FROM device_mappings
        WHERE datetime(last_seen) < datetime("now", ?)
        ''', (f'-{days} days',))
        
        deleted_count = cursor.rowcount
        self.conn.commit()
        logger.info(f"Cleaned up {deleted_count} stale entries older than {days} days")
        return deleted_count
    
    def export_to_json(self, output_file: str, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        Export device mappings to a JSON file with optional filtering.
        
        Args:
            output_file: Path to save the JSON file
            filters: Optional dictionary of filters
            
        Returns:
            Number of exported entries
        """
        # Get mappings with filters
        if filters:
            mappings = self.search_mappings(
                mac_filter=filters.get('mac'),
                ip_filter=filters.get('ip'),
                vlan_filter=filters.get('vlan'),
                switch_filter=filters.get('switch'),
                port_filter=filters.get('port'),
                days_filter=filters.get('days')
            )
        else:
            mappings = self.get_all_mappings()
        
        # Format the output according to the specified structure
        formatted_mappings = []
        for mapping in mappings:
            formatted_mappings.append({
                "mac_address": mapping["mac_address"],
                "ip_address": mapping.get("ip_address", ""),
                "vlan": mapping.get("vlan", ""),
                "switch_port": mapping["switch_port"],
                "last_present": mapping["last_present"]
            })
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(formatted_mappings, f, indent=2)
            
        logger.info(f"Exported {len(formatted_mappings)} mappings to {output_file}")
        return len(formatted_mappings)
    
    def export_to_csv(self, output_file: str, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        Export device mappings to a CSV file with optional filtering.
        
        Args:
            output_file: Path to save the CSV file
            filters: Optional dictionary of filters
            
        Returns:
            Number of exported entries
        """
        import csv
        
        # Get mappings with filters
        if filters:
            mappings = self.search_mappings(
                mac_filter=filters.get('mac'),
                ip_filter=filters.get('ip'),
                vlan_filter=filters.get('vlan'),
                switch_filter=filters.get('switch'),
                port_filter=filters.get('port'),
                days_filter=filters.get('days')
            )
        else:
            mappings = self.get_all_mappings()
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow([
                'MAC Address', 'IP Address', 'VLAN', 'Switch Name', 
                'Switch IP', 'Port', 'First Seen', 'Last Seen'
            ])
            
            # Write data
            for mapping in mappings:
                writer.writerow([
                    mapping["mac_address"],
                    mapping.get("ip_address", ""),
                    mapping.get("vlan", ""),
                    mapping["switch_name"],
                    mapping["switch_ip"],
                    mapping["switch_port"],
                    mapping.get("first_seen", ""),
                    mapping["last_present"]
                ])
        
        logger.info(f"Exported {len(mappings)} entries to CSV file {output_file}")
        return len(mappings)
    
    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            logger.info("Database connection closed")


# Test the module directly
if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='Encrypted Database Manager')
    
    parser.add_argument('--db', default='data/device_mappings.db', help='Database file path')
    parser.add_argument('--encrypt', action='store_true', help='Enable encryption')
    parser.add_argument('--key', help='Encryption key (if not provided, will be generated)')
    parser.add_argument('--export-json', help='Export to JSON file')
    parser.add_argument('--export-csv', help='Export to CSV file')
    parser.add_argument('--cleanup', type=int, help='Clean up entries older than specified days')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    
    args = parser.parse_args()
    
    # Initialize the database manager
    db_manager = DatabaseManager(
        db_path=args.db,
        encryption_key=args.key,
        use_encryption=args.encrypt
    )
    
    try:
        if args.cleanup:
            deleted = db_manager.cleanup_stale_mappings(args.cleanup)
            print(f"Cleaned up {deleted} stale entries")
            
        if args.export_json:
            count = db_manager.export_to_json(args.export_json)
            print(f"Exported {count} entries to {args.export_json}")
            
        if args.export_csv:
            count = db_manager.export_to_csv(args.export_csv)
            print(f"Exported {count} entries to {args.export_csv}")
            
        if args.stats:
            stats = db_manager.get_stats()
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
                
    finally:
        db_manager.close()
