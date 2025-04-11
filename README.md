# NETMapper: Network Device Location Tracker

[![GitHub](https://img.shields.io/badge/GitHub-NX1X%2FNETMapper-blue?logo=github)](https://github.com/NX1X/NETMapper)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Eden%20Porat-blue?logo=linkedin)](https://www.linkedin.com/in/edenporat/)
[![Support](https://img.shields.io/badge/Support-support%40nx1xlab.dev-green?logo=mail.ru)](mailto:support@nx1xlab.dev)
[![Beta Partner](https://img.shields.io/badge/Beta%20Partner-Ben%20Gurion%20University-orange)](https://bgu.ac.il)
[![Donate](https://img.shields.io/badge/Donate-Buy%20Me%20A%20Coffee-yellow.svg?logo=buy-me-a-coffee)](https://buymeacoffee.com/nx1x)

**Securely map devices across your network using SSH connections instead of SNMP**

## Project Overview

NETMapper is a powerful network administration tool designed to track device locations by connecting to switches via SSH. It builds a comprehensive database that maps MAC addresses to specific switch ports, IP addresses, and VLANs, allowing you to quickly locate any device on your network.

## Key Features

- **SSH-Based Polling**: Securely connect to network switches using SSH instead of SNMP
- **Database Encryption**: Option to encrypt sensitive data in the database
- **CSV Import/Export**: Easily import switch credentials and export device mappings
- **Comprehensive Database**: Track MAC addresses, IP addresses, VLANs, and when devices were first and last seen
- **Multi-Switch Support**: Poll multiple network switches simultaneously
- **Customizable Polling Interval**: Adjust polling frequency to balance accuracy and network load
- **Clean Web Interface**: Search, filter, and export device location data through an intuitive dashboard
- **REST API**: Integrate with your existing network management tools
- **Docker Ready**: Deploy quickly with containerized installation
- **Stale Entry Management**: Automatically clean up outdated device records

## Architecture

NETMapper consists of three main components:

1. **Core Service (netmapper)**: Polls switches and maintains the database
2. **API Service**: Provides a RESTful interface for querying and managing the system
3. **Web Interface**: User-friendly dashboard for interaction

## Installation

### Prerequisites

- Docker and Docker Compose
- Network switches accessible via SSH
- SSH credentials for the switches

### Quick Start

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/netmapper.git
   cd netmapper
   ```

2. Create a basic configuration:
   ```bash
   mkdir -p config data
   cp config/netmapper.json.example config/netmapper.json
   ```

3. Build and start the containers:
   ```bash
   docker-compose up -d
   ```

4. Access the web interface at `http://localhost:8080`

## Usage

### Web Interface

The web interface provides an intuitive way to interact with NETMapper:

1. **Dashboard**: View system statistics and recent device updates
2. **Devices**: Search and filter device mappings
3. **Credentials**: Manage switch SSH credentials
4. **Settings**: Configure system behavior

### Manual Credential Entry

1. Navigate to the "Credentials" tab
2. Click "Add Switch"
3. Enter the switch details:
   - Name (optional)
   - Hostname/IP
   - Username
   - Password
   - SSH Port (default: 22)
4. Click "Save"

### CSV Credential Import

1. Navigate to the "Credentials" tab
2. Click "Import CSV"
3. Select a CSV file with the format:
   ```
   hostname,username,password,name(optional),port(optional)
   192.168.1.1,admin,password123,Core Switch,22
   ```
4. Click "Import"

### Polling Switches

- To poll a single switch: Go to "Credentials", find the switch, and click "Poll"
- To poll all switches: Click "Poll All Switches" in the navigation bar

### Searching Devices

1. Navigate to the "Devices" tab
2. Use the filters to search by:
   - MAC Address
   - IP Address
   - VLAN
   - Switch Name/IP
   - Port
   - Time Period (days)
3. Click "Search"

### Exporting Data

1. Click "Export" in the navigation bar
2. Choose the export format (CSV or JSON)
3. Decide whether to apply current search filters
4. Click "Export"

## API Endpoints

NETMapper provides a comprehensive REST API:

- `GET /api/mappings`: Get all device mappings (with optional filters)
- `GET /api/mapping/<mac_address>`: Get mapping for a specific MAC address
- `GET /api/switches`: Get all switches in the database
- `GET /api/stats`: Get system statistics
- `GET /api/export`: Export mappings in JSON format
- `GET /api/export/csv`: Export mappings in CSV format
- `GET /api/credentials`: Get all stored credentials (passwords hidden)
- `POST /api/credentials`: Add a new credential
- `DELETE /api/credentials/<hostname>`: Remove a credential
- `POST /api/credentials/import`: Import credentials from a CSV file
- `POST /api/poll`: Poll a single switch
- `GET /api/poll/all`: Poll all switches with stored credentials
- `POST /api/cleanup`: Clean up stale device entries

## Security Considerations

- SSH is used instead of SNMP for enhanced security
- Credentials are always stored encrypted
- Database encryption is optional but recommended
- Use dedicated SSH accounts with read-only access
- Restrict access to the API and web interface using a firewall or reverse proxy
- Use HTTPS in production environments

## Configuration

The main configuration file is `config/netmapper.json`:

```json
{
  "database_path": "/app/data/device_mappings.db",
  "credentials_path": "/app/data/credentials.json",
  "use_encryption": false,
  "cleanup_days": 30,
  "polling_interval": 3600,
  "export_path": "/app/data/exports"
}
```

## License

NETMapper is proprietary software. All rights reserved.

### Usage Rights:
- **Free to Use**: The software is free to use for any purpose, including personal and commercial use
- **No Modifications**: The software may not be modified or altered without explicit permission
- **No Code Copying**: The source code may not be copied, reproduced, or distributed

See the [LICENSE.md](LICENSE.md) file for complete terms and conditions.

For licensing inquiries or to request permission for modifications, please contact: [support@nx1xlab.dev](mailto:support@nx1xlab.dev)

## Acknowledgements

![Ben Gurion University Logo](web/img/bgu-logo.png)

Special thanks to [Ben Gurion University of the Negev](https://bgu.ac.il) for supporting and participating in the beta testing of NETMapper. Their IT department's valuable feedback and collaboration have been instrumental in refining this tool for enterprise use.

## Beta Program

NETMapper is currently in beta testing with Ben Gurion University and select organizations. We're looking for additional partners to join our beta program:

- 🚀 **Get early access** to new features
- 🔍 **Influence the roadmap** with your feedback
- 🛠️ **Receive dedicated support** during implementation
- 💰 **No cost** for beta participants

**Want to participate?** Organizations interested in joining the beta program are welcome to [contact me](mailto:support@nx1xlab.dev?subject=NETMapper%20Beta%20Participation%20Request) for more information.

## Support the Project

NETMapper is provided free of charge for everyone to use. If you find this tool valuable, please consider supporting its continued development:

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/guidelines/download-assets-sm-1.svg)](https://buymeacoffee.com/nx1x)

Your donations help fund new features, improvements, and ongoing maintenance.

## Contact & Feature Requests

Have a feature request or need support? Feel free to reach out:

- GitHub: [github.com/NX1X/NETMapper](https://github.com/NX1X/NETMapper)
- LinkedIn: [linkedin.com/in/edenporat](https://www.linkedin.com/in/edenporat/)
- Support Email: [support@nx1xlab.dev](mailto:support@nx1xlab.dev)

I welcome contributions, feature requests, and feedback to improve NETMapper. Contact me directly via email or LinkedIn to discuss enhancements or report issues.