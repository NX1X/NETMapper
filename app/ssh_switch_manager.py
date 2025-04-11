#!/usr/bin/env python3
"""
SSH Switch Manager

This module handles SSH connections to network switches and extracts
information from command outputs.
"""

import re
import logging
import paramiko
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("ssh_mapper.log")
    ]
)
logger = logging.getLogger("ssh_switch_manager")

class SSHClient:
    """Handles SSH connections to network devices."""
    
    def __init__(self, hostname: str, username: str, password: str, port: int = 22):
        """Initialize with connection parameters."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.client = None
    
    def connect(self) -> bool:
        """Establish SSH connection to the device."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10
            )
            logger.info(f"Successfully connected to {self.hostname}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to {self.hostname}: {str(e)}")
            return False
    
    def execute_command(self, command: str) -> str:
        """Execute a command on the device and return the output."""
        if not self.client:
            if not self.connect():
                return ""
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if error:
                logger.warning(f"Command {command} returned error: {error}")
            
            return output
        except Exception as e:
            logger.error(f"Error executing command {command}: {str(e)}")
            return ""
    
    def close(self):
        """Close the SSH connection."""
        if self.client:
            self.client.close()
            self.client = None
            logger.info(f"Closed connection to {self.hostname}")


class MacAddressParser:
    """Parser for MAC address table outputs from different switch vendors."""
    
    @staticmethod
    def parse_cisco_mac_table(output: str) -> List[Dict[str, str]]:
        """Parse MAC address table output from Cisco switches."""
        results = []
        
        # Regular expression pattern for Cisco MAC table entries
        # Format: VLAN MAC Address Type Ports
        pattern = r'(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\w+\s+(\S+)'
        
        for line in output.splitlines():
            match = re.search(pattern, line)
            if match:
                vlan, mac, port = match.groups()
                
                # Convert MAC from Cisco format to standard format
                mac_parts = mac.split('.')
                standard_mac = ':'.join([f"{int(mac_parts[0][0:2], 16):02x}",
                                         f"{int(mac_parts[0][2:4], 16):02x}",
                                         f"{int(mac_parts[1][0:2], 16):02x}",
                                         f"{int(mac_parts[1][2:4], 16):02x}",
                                         f"{int(mac_parts[2][0:2], 16):02x}",
                                         f"{int(mac_parts[2][2:4], 16):02x}"])
                
                results.append({
                    "mac_address": standard_mac,
                    "vlan": vlan,
                    "switch_port": port
                })
        
        return results
    
    @staticmethod
    def parse_juniper_mac_table(output: str) -> List[Dict[str, str]]:
        """Parse MAC address table output from Juniper switches."""
        results = []
        
        # Regular expression pattern for Juniper MAC table entries
        # Format: MAC address       VLAN     Interface    
        pattern = r'([0-9a-f:]{17})\s+(\d+)\s+(\S+)'
        
        for line in output.splitlines():
            match = re.search(pattern, line)
            if match:
                mac, vlan, port = match.groups()
                results.append({
                    "mac_address": mac,
                    "vlan": vlan,
                    "switch_port": port
                })
        
        return results
    
    @staticmethod
    def parse_hp_mac_table(output: str) -> List[Dict[str, str]]:
        """Parse MAC address table output from HP/Aruba switches."""
        results = []
        
        # Regular expression pattern for HP MAC table entries
        # Format: MAC Address   Port  VLAN
        pattern = r'([0-9a-f]{6}-[0-9a-f]{6})\s+(\S+)\s+(\d+)'
        
        for line in output.splitlines():
            match = re.search(pattern, line)
            if match:
                mac, port, vlan = match.groups()
                
                # Convert HP format to standard format
                standard_mac = ':'.join([mac[0:2], mac[2:4], mac[4:6],
                                         mac[7:9], mac[9:11], mac[11:13]])
                
                results.append({
                    "mac_address": standard_mac,
                    "vlan": vlan,
                    "switch_port": port
                })
        
        return results
    
    @staticmethod
    def auto_detect_and_parse(output: str) -> List[Dict[str, str]]:
        """Automatically detect switch vendor and parse output accordingly."""
        # Try to detect the format from the output header or content
        if "VLAN" in output and "Type" in output and "Ports" in output:
            # Likely Cisco format
            return MacAddressParser.parse_cisco_mac_table(output)
        elif "MAC address" in output and "VLAN" in output and "Interface" in output:
            # Likely Juniper format
            return MacAddressParser.parse_juniper_mac_table(output)
        elif "MAC Address" in output and "Port" in output:
            # Likely HP/Aruba format
            return MacAddressParser.parse_hp_mac_table(output)
        else:
            # Try all parsers in sequence
            results = MacAddressParser.parse_cisco_mac_table(output)
            if results:
                return results
            
            results = MacAddressParser.parse_juniper_mac_table(output)
            if results:
                return results
            
            results = MacAddressParser.parse_hp_mac_table(output)
            return results  # Return results even if empty


class ArpParser:
    """Parser for ARP table outputs to extract IP address information."""
    
    @staticmethod
    def parse_cisco_arp_table(output: str) -> Dict[str, str]:
        """Parse ARP table output from Cisco switches/routers."""
        results = {}
        
        # Regular expression pattern for Cisco ARP entries
        # Format: Protocol  Address          Age (min)  Hardware Addr   Type   Interface
        pattern = r'Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})'
        
        for line in output.splitlines():
            match = re.search(pattern, line)
            if match:
                ip, mac = match.groups()
                
                # Convert MAC from Cisco format to standard format
                mac_parts = mac.split('.')
                standard_mac = ':'.join([f"{int(mac_parts[0][0:2], 16):02x}",
                                         f"{int(mac_parts[0][2:4], 16):02x}",
                                         f"{int(mac_parts[1][0:2], 16):02x}",
                                         f"{int(mac_parts[1][2:4], 16):02x}",
                                         f"{int(mac_parts[2][0:2], 16):02x}",
                                         f"{int(mac_parts[2][2:4], 16):02x}"])
                
                results[standard_mac] = ip
        
        return results
    
    @staticmethod
    def parse_juniper_arp_table(output: str) -> Dict[str, str]:
        """Parse ARP table output from Juniper devices."""
        results = {}
        
        # Regular expression pattern for Juniper ARP entries
        # Format: MAC Address       Address         Name                      Interface
        pattern = r'([0-9a-f:]{17})\s+(\d+\.\d+\.\d+\.\d+)'
        
        for line in output.splitlines():
            match = re.search(pattern, line)
            if match:
                mac, ip = match.groups()
                results[mac] = ip
        
        return results
    
    @staticmethod
    def auto_detect_and_parse(output: str) -> Dict[str, str]:
        """Automatically detect device type and parse ARP table accordingly."""
        # Try to detect the format from the output
        if "Protocol" in output and "Address" in output and "Hardware Addr" in output:
            # Likely Cisco format
            return ArpParser.parse_cisco_arp_table(output)
        elif "MAC Address" in output and "Address" in output and "Interface" in output:
            # Likely Juniper format
            return ArpParser.parse_juniper_arp_table(output)
        else:
            # Try all parsers in sequence
            results = ArpParser.parse_cisco_arp_table(output)
            if results:
                return results
            
            results = ArpParser.parse_juniper_arp_table(output)
            return results


class SwitchManager:
    """Main class for managing switch connections and data extraction."""
    
    def __init__(self, db_manager=None):
        """Initialize with optional database manager."""
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
    
    def fetch_and_process_switch_data(self, 
                                     hostname: str, 
                                     username: str, 
                                     password: str, 
                                     port: int = 22,
                                     switch_name: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
        """
        Connect to a switch, fetch MAC and ARP tables, and process the data.
        
        Returns:
            Tuple containing a list of processed entries and the count of entries
        """
        ssh_client = SSHClient(hostname, username, password, port)
        
        if not ssh_client.connect():
            self.logger.error(f"Failed to connect to switch {hostname}")
            return [], 0
        
        try:
            # Get switch information for identification
            system_info = ssh_client.execute_command("show version")
            
            # Get the MAC address table
            mac_table_output = ssh_client.execute_command("show mac address-table")
            if not mac_table_output:
                # Try alternative command for some vendors
                mac_table_output = ssh_client.execute_command("show mac-address-table")
            
            # Get the ARP table for IP address mapping
            arp_table_output = ssh_client.execute_command("show ip arp")
            
            # Parse the outputs
            mac_entries = MacAddressParser.auto_detect_and_parse(mac_table_output)
            self.logger.info(f"Parsed {len(mac_entries)} MAC entries from {hostname}")
            
            ip_mapping = ArpParser.auto_detect_and_parse(arp_table_output)
            self.logger.info(f"Parsed {len(ip_mapping)} ARP entries from {hostname}")
            
            # Create a switch record in the database if we have a database manager
            switch_id = None
            if self.db_manager and switch_name:
                switch_id = self.db_manager.get_or_create_switch(hostname, switch_name)
            
            # Combine the data and store in database
            now = datetime.now(timezone.utc).isoformat()
            processed_entries = []
            
            for entry in mac_entries:
                mac_address = entry["mac_address"]
                entry["ip_address"] = ip_mapping.get(mac_address, "")
                entry["last_seen"] = now
                
                # Add to database if we have a database manager
                if self.db_manager and switch_id:
                    self.db_manager.update_device_mapping(
                        mac_address=mac_address,
                        ip_address=entry["ip_address"],
                        vlan=entry["vlan"],
                        switch_id=switch_id,
                        switch_port=entry["switch_port"]
                    )
                
                processed_entries.append(entry)
            
            return processed_entries, len(processed_entries)
            
        except Exception as e:
            self.logger.error(f"Error processing switch data from {hostname}: {str(e)}")
            return [], 0
        finally:
            ssh_client.close()
    
    def bulk_process_switches(self, switch_configs: List[Dict[str, Any]]) -> int:
        """Process multiple switches in bulk."""
        total_entries = 0
        
        for config in switch_configs:
            entries, count = self.fetch_and_process_switch_data(
                hostname=config["hostname"],
                username=config["username"],
                password=config["password"],
                port=config.get("port", 22),
                switch_name=config.get("name")
            )
            total_entries += count
            
        return total_entries


# Test the module directly
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python ssh_switch_manager.py hostname username password [port]")
        sys.exit(1)
    
    hostname = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 22
    
    manager = SwitchManager()
    entries, count = manager.fetch_and_process_switch_data(hostname, username, password, port)
    
    print(f"Processed {count} entries from {hostname}")
    for entry in entries:
        print(f"MAC: {entry['mac_address']}, IP: {entry.get('ip_address', 'N/A')}, "
              f"VLAN: {entry['vlan']}, Port: {entry['switch_port']}")
