#!/usr/bin/env python3
"""
NETMapper SSH API

This script provides a REST API for the SSH-based network device tracking system.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from flask import Flask, jsonify, request, g, abort, send_file
from flask_cors import CORS

from encrypted_db_manager import DatabaseManager
from credential_manager import CredentialManager
from ssh_switch_manager import SwitchManager

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("api.log")
    ]
)
logger = logging.getLogger("api")

# Create Flask application
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Get configuration from environment variables or use defaults
DATABASE_PATH = os.environ.get('DATABASE_PATH', 'data/device_mappings.db')
CREDENTIALS_PATH = os.environ.get('CREDENTIALS_PATH', 'data/credentials.json')
USE_ENCRYPTION = os.environ.get('USE_ENCRYPTION', 'false').lower() == 'true'
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', None)
CONFIG_PATH = os.environ.get('CONFIG_PATH', 'config/netmapper.json')

# Load configuration file if it exists
config = {}
if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")

# Create directories if they don't exist
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
os.makedirs(os.path.dirname(CREDENTIALS_PATH), exist_ok=True)
os.makedirs('data/exports', exist_ok=True)

def get_db():
    """Get database manager."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = DatabaseManager(
            db_path=DATABASE_PATH,
            encryption_key=ENCRYPTION_KEY,
            use_encryption=USE_ENCRYPTION
        )
    return db

def get_credential_manager():
    """Get credential manager."""
    cred_mgr = getattr(g, '_credential_manager', None)
    if cred_mgr is None:
        cred_mgr = g._credential_manager = CredentialManager(
            credential_file=CREDENTIALS_PATH,
            encryption_key=ENCRYPTION_KEY,
            use_encryption=True  # Always encrypt credentials
        )
    return cred_mgr

def get_switch_manager():
    """Get switch manager."""
    switch_mgr = getattr(g, '_switch_manager', None)
    if switch_mgr is None:
        db = get_db()
        switch_mgr = g._switch_manager = SwitchManager(db)
    return switch_mgr

@app.teardown_appcontext
def close_connections(exception):
    """Close connections when application context ends."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# API Routes

@app.route('/api/mappings', methods=['GET'])
def get_mappings():
    """Get all device mappings or filter by parameters."""
    db = get_db()
    
    # Get query parameters for filtering
    mac_filter = request.args.get('mac')
    ip_filter = request.args.get('ip')
    vlan_filter = request.args.get('vlan')
    switch_filter = request.args.get('switch')
    port_filter = request.args.get('port')
    days_filter = request.args.get('days')
    
    try:
        days = int(days_filter) if days_filter else None
    except ValueError:
        days = None
    
    # Use the search function
    results = db.search_mappings(
        mac_filter=mac_filter,
        ip_filter=ip_filter,
        vlan_filter=vlan_filter,
        switch_filter=switch_filter,
        port_filter=port_filter,
        days_filter=days
    )
    
    return jsonify(results)

@app.route('/api/mapping/<mac_address>', methods=['GET'])
def get_mapping_by_mac(mac_address):
    """Get mapping for a specific MAC address."""
    db = get_db()
    
    results = db.search_mappings(mac_filter=mac_address)
    
    if not results:
        abort(404, description=f"MAC address {mac_address} not found")
        
    return jsonify(results)

@app.route('/api/switches', methods=['GET'])
def get_switches():
    """Get all switches in the database."""
    db = get_db()
    cursor = db.conn.cursor()
    
    cursor.execute('''
    SELECT id, ip, name
    FROM switches
    ORDER BY name
    ''')
    
    results = []
    for row in cursor.fetchall():
        results.append({
            "id": row[0],
            "ip": row[1],
            "name": row[2]
        })
        
    return jsonify(results)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get statistics about the database."""
    db = get_db()
    stats = db.get_stats()
    return jsonify(stats)

@app.route('/api/export', methods=['GET'])
def export_json():
    """Export mappings to JSON with optional filters."""
    db = get_db()
    
    # Get query parameters for filtering
    filters = {}
    for param in ['mac', 'ip', 'vlan', 'switch', 'port', 'days']:
        value = request.args.get(param)
        if value:
            filters[param] = value
    
    # Generate an export filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    export_file = f"data/exports/device_mappings_{timestamp}.json"
    
    count = db.export_to_json(export_file, filters)
    
    return jsonify({
        "success": True,
        "file": export_file,
        "count": count,
        "timestamp": timestamp
    })

@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    """Export mappings to CSV with optional filters."""
    db = get_db()
    
    # Get query parameters for filtering
    filters = {}
    for param in ['mac', 'ip', 'vlan', 'switch', 'port', 'days']:
        value = request.args.get(param)
        if value:
            filters[param] = value
    
    # Generate an export filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    export_file = f"data/exports/device_mappings_{timestamp}.csv"
    
    count = db.export_to_csv(export_file, filters)
    
    return jsonify({
        "success": True,
        "file": export_file,
        "count": count,
        "timestamp": timestamp
    })

@app.route('/api/download/<path:filename>', methods=['GET'])
def download_file(filename):
    """Download a generated export file."""
    if '..' in filename or filename.startswith('/'):
        abort(404)  # Prevent directory traversal
    
    base_dir = os.path.abspath('data/exports')
    file_path = os.path.join(base_dir, os.path.basename(filename))
    
    if not os.path.exists(file_path):
        abort(404, description=f"File not found: {os.path.basename(filename)}")
    
    return send_file(file_path, as_attachment=True)

@app.route('/api/credentials', methods=['GET'])
def get_credentials():
    """Get all stored credentials (without passwords)."""
    cred_mgr = get_credential_manager()
    credentials = cred_mgr.load_credentials()
    
    # Remove passwords for security
    for cred in credentials:
        cred['password'] = '********'
    
    return jsonify(credentials)

@app.route('/api/credentials', methods=['POST'])
def add_credential():
    """Add a new credential."""
    cred_mgr = get_credential_manager()
    data = request.json
    
    if not data or not all(k in data for k in ['hostname', 'username', 'password']):
        abort(400, description="Missing required fields")
    
    success = cred_mgr.add_credential(
        hostname=data['hostname'],
        username=data['username'],
        password=data['password'],
        name=data.get('name'),
        port=data.get('port', 22)
    )
    
    if success:
        return jsonify({"success": True, "message": "Credential added successfully"})
    else:
        abort(500, description="Failed to add credential")

@app.route('/api/credentials/<hostname>', methods=['DELETE'])
def remove_credential(hostname):
    """Remove a credential by hostname."""
    cred_mgr = get_credential_manager()
    success = cred_mgr.remove_credential(hostname)
    
    if success:
        return jsonify({"success": True, "message": f"Removed credential for {hostname}"})
    else:
        abort(404, description=f"No credential found for {hostname}")

@app.route('/api/credentials/import', methods=['POST'])
def import_credentials():
    """Import credentials from a CSV file."""
    # Check if file was uploaded
    if 'file' not in request.files:
        abort(400, description="No file part")
    
    file = request.files['file']
    if file.filename == '':
        abort(400, description="No selected file")
    
    if not file.filename.endswith('.csv'):
        abort(400, description="File must be a CSV")
    
    # Save the file temporarily
    temp_path = 'data/temp_import.csv'
    file.save(temp_path)
    
    # Import the credentials
    cred_mgr = get_credential_manager()
    success_count, failure_count = cred_mgr.import_from_csv(temp_path)
    
    # Clean up
    try:
        os.remove(temp_path)
    except:
        pass
    
    return jsonify({
        "success": True,
        "imported": success_count,
        "failed": failure_count,
        "message": f"Imported {success_count} credentials, {failure_count} failures"
    })

@app.route('/api/poll', methods=['POST'])
def poll_switch():
    """Poll a single switch for device data."""
    data = request.json
    
    if not data or not all(k in data for k in ['hostname', 'username', 'password']):
        abort(400, description="Missing required fields")
    
    switch_mgr = get_switch_manager()
    
    try:
        entries, count = switch_mgr.fetch_and_process_switch_data(
            hostname=data['hostname'],
            username=data['username'],
            password=data['password'],
            port=data.get('port', 22),
            switch_name=data.get('name')
        )
        
        return jsonify({
            "success": True,
            "count": count,
            "message": f"Successfully polled {data['hostname']}, processed {count} entries"
        })
    except Exception as e:
        logger.error(f"Error polling switch: {str(e)}")
        abort(500, description=f"Error polling switch: {str(e)}")

@app.route('/api/poll/all', methods=['GET'])
def poll_all_switches():
    """Poll all switches with stored credentials."""
    cred_mgr = get_credential_manager()
    switch_mgr = get_switch_manager()
    
    credentials = cred_mgr.load_credentials()
    
    if not credentials:
        abort(400, description="No credentials found")
    
    results = {}
    total_count = 0
    
    for cred in credentials:
        try:
            entries, count = switch_mgr.fetch_and_process_switch_data(
                hostname=cred['hostname'],
                username=cred['username'],
                password=cred['password'],
                port=cred.get('port', 22),
                switch_name=cred.get('name')
            )
            
            results[cred['hostname']] = {
                "success": True,
                "count": count
            }
            total_count += count
        except Exception as e:
            logger.error(f"Error polling switch {cred['hostname']}: {str(e)}")
            results[cred['hostname']] = {
                "success": False,
                "error": str(e)
            }
    
    return jsonify({
        "success": True,
        "total_count": total_count,
        "results": results
    })

@app.route('/api/cleanup', methods=['POST'])
def cleanup_stale():
    """Clean up stale device entries."""
    data = request.json
    days = data.get('days', 30) if data else 30
    
    try:
        days = int(days)
    except ValueError:
        abort(400, description="Days must be a number")
    
    db = get_db()
    count = db.cleanup_stale_mappings(days)
    
    return jsonify({
        "success": True,
        "count": count,
        "message": f"Removed {count} stale entries older than {days} days"
    })

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get the current configuration."""
    # Return only non-sensitive configuration
    safe_config = {
        "use_encryption": USE_ENCRYPTION,
        "database_path": DATABASE_PATH,
        "credentials_path": CREDENTIALS_PATH
    }
    
    # Add any other config from the config file
    if config:
        for key, value in config.items():
            if key not in ['encryption_key']:  # Skip sensitive fields
                safe_config[key] = value
    
    return jsonify(safe_config)

@app.route('/api/config', methods=['POST'])
def update_config():
    """Update the configuration."""
    data = request.json
    
    if not data:
        abort(400, description="No configuration provided")
    
    # Don't allow updating sensitive fields via API
    sensitive_fields = ['encryption_key']
    for field in sensitive_fields:
        if field in data:
            del data[field]
    
    # Update the config
    global config
    config.update(data)
    
    # Save to file
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
        
        return jsonify({
            "success": True,
            "message": "Configuration updated"
        })
    except Exception as e:
        logger.error(f"Error saving configuration: {str(e)}")
        abort(500, description=f"Error saving configuration: {str(e)}")

# Error Handlers

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": 400,
        "message": str(error.description)
    }), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": str(error.description)
    }), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({
        "success": False,
        "error": 500,
        "message": str(error.description)
    }), 500

if __name__ == '__main__':
    # Run the Flask application
    app.run(host='0.0.0.0', port=5000, debug=False)
