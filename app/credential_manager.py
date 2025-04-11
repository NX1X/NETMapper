#!/usr/bin/env python3
"""
Credential Manager

This module handles secure storage and management of switch credentials
with support for both encrypted and decrypted storage.
"""

import os
import json
import csv
import logging
import base64
from typing import Dict, List, Any, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("credential_manager")

class CredentialManager:
    """Manages secure storage and retrieval of switch credentials."""
    
    def __init__(self, 
                credential_file: str = 'credentials.json', 
                encryption_key: Optional[str] = None,
                use_encryption: bool = True):
        """
        Initialize the credential manager.
        
        Args:
            credential_file: Path to the credential storage file
            encryption_key: Optional encryption key for securing credentials
            use_encryption: Whether to encrypt credentials in storage
        """
        self.credential_file = credential_file
        self.use_encryption = use_encryption
        self.encryption_key = encryption_key
        self.fernet = None
        
        # Initialize encryption if requested
        if use_encryption:
            self._setup_encryption(encryption_key)
    
    def _setup_encryption(self, key: Optional[str] = None):
        """Set up encryption with the provided key or generate a new one."""
        if key:
            # Use provided key (must be base64-encoded 32-byte key)
            try:
                # Check if it's a valid Fernet key
                if not key.startswith("key_"):
                    self.fernet = Fernet(key.encode())
                    self.encryption_key = key
                else:
                    # It's a passphrase, derive a key from it
                    self._derive_key_from_passphrase(key[4:])  # Remove "key_" prefix
            except Exception as e:
                logger.error(f"Invalid encryption key provided: {str(e)}")
                self._generate_new_key()
        else:
            # Check if a key file exists
            key_file = 'encryption_key.txt'
            if os.path.exists(key_file):
                with open(key_file, 'r') as f:
                    key = f.read().strip()
                    self.fernet = Fernet(key.encode())
                    self.encryption_key = key
            else:
                self._generate_new_key(key_file)
    
    def _derive_key_from_passphrase(self, passphrase: str):
        """Derive a Fernet key from a user passphrase."""
        salt = b'netmapper_salt'  # In a production system, this should be stored securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        self.fernet = Fernet(key)
        self.encryption_key = key.decode()
    
    def _generate_new_key(self, key_file: Optional[str] = None):
        """Generate a new encryption key and optionally save it to a file."""
        key = Fernet.generate_key().decode()
        self.fernet = Fernet(key.encode())
        self.encryption_key = key
        
        if key_file:
            with open(key_file, 'w') as f:
                f.write(key)
            logger.info(f"Generated new encryption key and saved to {key_file}")
        else:
            logger.info("Generated new encryption key (not saved to disk)")
    
    def encrypt(self, data: str) -> str:
        """Encrypt the provided data."""
        if not self.use_encryption or not self.fernet:
            return data
        
        return self.fernet.encrypt(data.encode()).decode()
    
    def decrypt(self, data: str) -> str:
        """Decrypt the provided data."""
        if not self.use_encryption or not self.fernet:
            return data
        
        return self.fernet.decrypt(data.encode()).decode()
    
    def save_credentials(self, credentials: List[Dict[str, Any]]):
        """
        Save credentials to the storage file.
        
        Args:
            credentials: List of credential dictionaries with hostname, username, password
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.credential_file), exist_ok=True)
            
            # Encrypt passwords if encryption is enabled
            processed_credentials = []
            for cred in credentials:
                processed_cred = cred.copy()
                if self.use_encryption and self.fernet:
                    processed_cred['password'] = self.encrypt(cred['password'])
                    processed_cred['encrypted'] = True
                else:
                    processed_cred['encrypted'] = False
                processed_credentials.append(processed_cred)
            
            # Save to file
            with open(self.credential_file, 'w') as f:
                json.dump(processed_credentials, f, indent=2)
            
            logger.info(f"Saved {len(credentials)} credentials to {self.credential_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving credentials: {str(e)}")
            return False
    
    def load_credentials(self) -> List[Dict[str, Any]]:
        """
        Load credentials from the storage file.
        
        Returns:
            List of credential dictionaries with decrypted passwords
        """
        if not os.path.exists(self.credential_file):
            logger.warning(f"Credential file {self.credential_file} does not exist")
            return []
        
        try:
            with open(self.credential_file, 'r') as f:
                credentials = json.load(f)
            
            # Decrypt passwords if needed
            decrypted_credentials = []
            for cred in credentials:
                decrypted_cred = cred.copy()
                if cred.get('encrypted', False) and self.fernet:
                    try:
                        decrypted_cred['password'] = self.decrypt(cred['password'])
                    except Exception as e:
                        logger.error(f"Error decrypting password for {cred['hostname']}: {str(e)}")
                        # Keep the encrypted password in this case
                decrypted_credentials.append(decrypted_cred)
            
            logger.info(f"Loaded {len(decrypted_credentials)} credentials from {self.credential_file}")
            return decrypted_credentials
        except Exception as e:
            logger.error(f"Error loading credentials: {str(e)}")
            return []
    
    def add_credential(self, hostname: str, username: str, password: str, 
                    name: Optional[str] = None, port: int = 22) -> bool:
        """
        Add a single credential to the storage.
        
        Args:
            hostname: IP address or hostname of the switch
            username: SSH username
            password: SSH password
            name: Optional friendly name for the switch
            port: SSH port (default: 22)
            
        Returns:
            Success status as boolean
        """
        credentials = self.load_credentials()
        
        # Check if the credential already exists
        for i, cred in enumerate(credentials):
            if cred['hostname'] == hostname:
                # Update existing credential
                credentials[i] = {
                    'hostname': hostname,
                    'username': username,
                    'password': password,
                    'name': name or hostname,
                    'port': port
                }
                return self.save_credentials(credentials)
        
        # Add new credential
        credentials.append({
            'hostname': hostname,
            'username': username,
            'password': password,
            'name': name or hostname,
            'port': port
        })
        return self.save_credentials(credentials)
    
    def remove_credential(self, hostname: str) -> bool:
        """
        Remove a credential from storage by hostname.
        
        Args:
            hostname: Hostname to remove
            
        Returns:
            Success status as boolean
        """
        credentials = self.load_credentials()
        initial_count = len(credentials)
        
        credentials = [c for c in credentials if c['hostname'] != hostname]
        
        if len(credentials) < initial_count:
            return self.save_credentials(credentials)
        else:
            logger.warning(f"No credential found for hostname {hostname}")
            return False
    
    def import_from_csv(self, csv_file_path: str) -> Tuple[int, int]:
        """
        Import credentials from a CSV file.
        
        Expected CSV format:
        hostname,username,password,name(optional),port(optional)
        
        Args:
            csv_file_path: Path to the CSV file
            
        Returns:
            Tuple of (success_count, failure_count)
        """
        if not os.path.exists(csv_file_path):
            logger.error(f"CSV file {csv_file_path} does not exist")
            return 0, 0
        
        success_count = 0
        failure_count = 0
        
        try:
            current_credentials = self.load_credentials()
            current_hostnames = {cred['hostname'] for cred in current_credentials}
            
            with open(csv_file_path, 'r', newline='') as csvfile:
                reader = csv.reader(csvfile)
                
                # Skip header if it exists
                first_row = next(reader, None)
                if first_row and first_row[0].lower() == 'hostname':
                    # This was a header, continue to next row
                    pass
                else:
                    # This was data, process it
                    csvfile.seek(0)
                    reader = csv.reader(csvfile)
                
                for row in reader:
                    try:
                        if len(row) < 3:
                            logger.warning(f"Skipping row with insufficient data: {row}")
                            failure_count += 1
                            continue
                        
                        hostname = row[0].strip()
                        username = row[1].strip()
                        password = row[2].strip()
                        name = row[3].strip() if len(row) > 3 and row[3].strip() else hostname
                        
                        try:
                            port = int(row[4]) if len(row) > 4 and row[4].strip() else 22
                        except ValueError:
                            logger.warning(f"Invalid port for {hostname}, using default 22")
                            port = 22
                        
                        # Add or update credential
                        cred = {
                            'hostname': hostname,
                            'username': username,
                            'password': password,
                            'name': name,
                            'port': port
                        }
                        
                        if hostname in current_hostnames:
                            # Update existing credential
                            for i, existing_cred in enumerate(current_credentials):
                                if existing_cred['hostname'] == hostname:
                                    current_credentials[i] = cred
                                    break
                        else:
                            # Add new credential
                            current_credentials.append(cred)
                            current_hostnames.add(hostname)
                        
                        success_count += 1
                    except Exception as e:
                        logger.error(f"Error processing row {row}: {str(e)}")
                        failure_count += 1
            
            # Save all credentials at once
            if success_count > 0:
                self.save_credentials(current_credentials)
            
            logger.info(f"Imported {success_count} credentials from CSV, {failure_count} failures")
            return success_count, failure_count
        except Exception as e:
            logger.error(f"Error importing from CSV: {str(e)}")
            return success_count, failure_count

    def export_to_csv(self, csv_file_path: str, include_passwords: bool = False) -> int:
        """
        Export credentials to a CSV file.
        
        Args:
            csv_file_path: Path to save the CSV file
            include_passwords: Whether to include passwords in the export
            
        Returns:
            Number of credentials exported
        """
        credentials = self.load_credentials()
        
        try:
            with open(csv_file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write header
                writer.writerow(['hostname', 'username', 'password', 'name', 'port'])
                
                # Write data
                for cred in credentials:
                    writer.writerow([
                        cred['hostname'],
                        cred['username'],
                        cred['password'] if include_passwords else '********',
                        cred.get('name', cred['hostname']),
                        cred.get('port', 22)
                    ])
            
            logger.info(f"Exported {len(credentials)} credentials to {csv_file_path}")
            return len(credentials)
        except Exception as e:
            logger.error(f"Error exporting to CSV: {str(e)}")
            return 0


# Test the module directly
if __name__ == "__main__":
    import sys
    
    # Example usage
    credential_mgr = CredentialManager(
        credential_file='data/credentials.json',
        use_encryption=True
    )
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "add" and len(sys.argv) >= 5:
            # Add a credential
            hostname = sys.argv[2]
            username = sys.argv[3]
            password = sys.argv[4]
            name = sys.argv[5] if len(sys.argv) > 5 else hostname
            port = int(sys.argv[6]) if len(sys.argv) > 6 else 22
            
            if credential_mgr.add_credential(hostname, username, password, name, port):
                print(f"Successfully added credential for {hostname}")
            else:
                print(f"Failed to add credential for {hostname}")
                
        elif command == "list":
            # List all credentials
            credentials = credential_mgr.load_credentials()
            print(f"Found {len(credentials)} credentials:")
            for cred in credentials:
                print(f"  {cred['name']} ({cred['hostname']}): {cred['username']}")
                
        elif command == "import" and len(sys.argv) > 2:
            # Import from CSV
            csv_file = sys.argv[2]
            success, failure = credential_mgr.import_from_csv(csv_file)
            print(f"Imported {success} credentials, {failure} failures")
            
        elif command == "export" and len(sys.argv) > 2:
            # Export to CSV
            csv_file = sys.argv[2]
            include_passwords = True if len(sys.argv) > 3 and sys.argv[3].lower() == "true" else False
            count = credential_mgr.export_to_csv(csv_file, include_passwords)
            print(f"Exported {count} credentials to {csv_file}")
            
        else:
            print("Unknown command or insufficient parameters")
    else:
        print("Usage:")
        print("  python credential_manager.py add <hostname> <username> <password> [name] [port]")
        print("  python credential_manager.py list")
        print("  python credential_manager.py import <csv_file>")
        print("  python credential_manager.py export <csv_file> [include_passwords]")
