# pfSense Configuration Management CLI Tool

A professional automation CLI tool that directly manages pfSense configurations through the REST API v2.6.0, providing real-time configuration changes for client management, network operations, and VPN setup.

## Features

### 🔧 Core Functionality
- **Client Management**: Add, remove, list, and manage client configurations directly in pfSense
- **Network Operations**: Create and configure VLANs, DHCP servers, NAT rules, and firewall rules in real-time
- **VPN Management**: Setup OpenVPN servers and manage client certificates on your pfSense instance
- **Live API Integration**: All changes are immediately applied to your pfSense system via REST API v2.6.0
- **Configuration Templates**: YAML-based templates for different client types
- **Backup & Restore**: Automatic configuration backups with retention policies

### 🏗️ Architecture
- **Professional API Client**: Authentication, retry logic, rate limiting, and error handling
- **Pydantic Data Models**: Type-safe configuration validation
- **YAML Configuration**: Human-readable configuration files with Jinja2 templating
- **Structured Logging**: JSON and colored console logging with performance tracking
- **Click CLI Framework**: Comprehensive command-line interface with help documentation

### 🔐 Security Features
- SSL certificate validation
- Secure credential management
- API authentication with token refresh
- Input validation and sanitization

## Prerequisites

### pfSense Requirements
- **pfSense Version**: 2.5.0 or later (tested with 2.8.1)
- **REST API Package**: pfSense REST API v2.6.0 must be installed
  - Install via: System > Package Manager > Available Packages > "pfSense-pkg-API"
  - Enable via: System > API > Enable API
- **Admin Access**: User account with administrative privileges

### Python Requirements
- Python 3.8 or later
- pip package manager

## Quick Start

### Installation

```powershell
# Clone the repository
git clone <repository-url>
cd pfsense-config-tool

# Install dependencies
python -m pip install -r requirements.txt

# Install the package
python -m pip install -e .

# Or install from wheel
python -m pip install dist/pfsense_cli-1.0.0-py3-none-any.whl
```

### Initial Setup

```powershell
# Configure your pfSense connection (PowerShell)
$env:PFSENSE_URL = "https://192.168.1.1"  # Your pfSense IP
$env:PFSENSE_USERNAME = "admin"
$env:PFSENSE_PASSWORD = "your-password"

# Test connection to pfSense
pfsense-cli status

# Or configure via config file
pfsense-cli set-config pfsense.base_url https://192.168.1.1
pfsense-cli set-config pfsense.username admin
pfsense-cli set-config pfsense.password your-password
```

**Note:** Ensure pfSense REST API v2.6.0 is installed and enabled on your pfSense system.

### Basic Usage

```powershell
# Add a new client (creates VLAN, interface, DHCP, and firewall rules in pfSense)
pfsense-cli client add --name "AcmeCorp" --network "192.168.50.0/24" --vlan 150 --dhcp-start "192.168.50.100" --dhcp-end "192.168.50.200"

# List all clients configured in pfSense
pfsense-cli client list

# Show client status from pfSense
pfsense-cli client status AcmeCorp

# Configure network settings (updates live pfSense configuration)
pfsense-cli network configure --client "AcmeCorp" --gateway "192.168.50.1"

# Setup VPN (creates OpenVPN server in pfSense)
pfsense-cli vpn setup --client "AcmeCorp" --port 1194

# Remove client (removes all associated pfSense configurations)
pfsense-cli client remove AcmeCorp
```

**Important:** All commands make immediate changes to your pfSense system. Changes are visible in the pfSense WebUI instantly.

## Configuration

The CLI tool uses a hierarchical configuration system:

- **Global Settings**: `~/.pfsense-cli/settings.yaml`
- **Client Configurations**: `~/.pfsense-cli/clients/`
- **Templates**: `~/.pfsense-cli/templates/`
- **Backups**: `~/.pfsense-cli/backups/`

### Example Client Configuration

```yaml
name: "AcmeCorp"
client_type: "corporate"
status: "active"

network:
  network: "192.168.50.0/24"
  gateway: "192.168.50.1"
  dns_servers:
    - "8.8.8.8"
    - "8.8.4.4"
  domain_name: "acme.local"

vlan:
  vlan_id: 150
  description: "AcmeCorp Corporate Network"
  interface: "em0"

dhcp:
  enabled: true
  start_ip: "192.168.50.100"
  end_ip: "192.168.50.200"
  lease_time: 7200

firewall_rules:
  - action: "pass"
    protocol: "any"
    source: "192.168.50.0/24"
    destination: "any"
    description: "Allow AcmeCorp internet access"

vpn_enabled: true
vpn_port: 1194
```

## Command Reference

### Client Management

```powershell
# Add client with template
pfsense-cli client add --name "BranchOffice" --template "branch_office" --network "192.168.60.0/24" --vlan 160

# Remove client
pfsense-cli client remove AcmeCorp

# List clients with filters
pfsense-cli client list --status active --client-type corporate

# Update client configuration
pfsense-cli client update AcmeCorp --status active --vpn
```

### Network Operations

```powershell
# Manage VLANs
pfsense-cli network vlan create --client "AcmeCorp" --vlan-id 150
pfsense-cli network vlan list

# Configure DHCP
pfsense-cli network dhcp enable --client "AcmeCorp" --start-ip "192.168.50.100" --end-ip "192.168.50.200"
pfsense-cli network dhcp status

# Manage NAT rules
pfsense-cli network nat add --client "AcmeCorp" --external-port 8080 --internal-ip "192.168.50.10" --internal-port 80
pfsense-cli network nat list

# Configure firewall rules
pfsense-cli network firewall add --client "AcmeCorp" --rule-action pass --protocol tcp --port "80,443"
pfsense-cli network firewall list
```

### VPN Management

```powershell
# Setup VPN server
pfsense-cli vpn setup --client "AcmeCorp" --port 1194 --network "10.8.0.0/24"

# Manage VPN clients
pfsense-cli vpn client create --server "AcmeCorp_vpn" --client-name "john_doe" --email "john@acme.com"
pfsense-cli vpn client list
pfsense-cli vpn client export --client-name "john_doe" --output-dir "./vpn_configs"

# Check VPN status
pfsense-cli vpn status
pfsense-cli vpn logs --lines 100

# Manage certificates
pfsense-cli vpn certificates create-ca --name "AcmeCorp_CA" --common-name "AcmeCorp Certificate Authority"
pfsense-cli vpn certificates list
```

### Configuration Management

```powershell
# View current configuration
pfsense-cli config --format yaml

# Set configuration values
pfsense-cli set-config pfsense.base_url https://192.168.1.1
pfsense-cli set-config network.default_dns_servers '["8.8.8.8", "1.1.1.1"]'

# Export/import configurations
pfsense-cli client export AcmeCorp --format yaml > acmecorp.yaml
```

## Templates

The tool supports Jinja2-powered configuration templates:

### Corporate Client Template
```yaml
name: "{{ client_name }}"
client_type: "corporate"
network:
  network: "{{ network_cidr }}"
  gateway: "{{ gateway_ip }}"
vlan:
  vlan_id: {{ vlan_id }}
vpn_enabled: {{ vpn_enabled | default(false) }}
```

### Usage
```bash
pfsense-cli client add --name "NewCorp" --template "corporate_client" --network "192.168.70.0/24" --vlan 170
```

## API Integration

The tool provides direct integration with pfSense REST API v2.6.0:

### Live Operations
- **Real-time Changes**: All operations immediately affect your pfSense system
- **WebUI Visibility**: Changes appear instantly in the pfSense web interface
- **Configuration Apply**: Automatic configuration reload after changes
- **Rollback Support**: Error handling with partial configuration cleanup

### Features
- JWT authentication with pfSense REST API v2.6.0
- Automatic retry with exponential backoff
- Rate limiting and connection pooling
- Comprehensive error handling
- Response validation and parsing

### Supported pfSense Operations
- ✅ Interface creation and management
- ✅ VLAN configuration
- ✅ DHCP server setup
- ✅ Firewall rule creation
- ✅ NAT/Port forwarding rules
- ✅ OpenVPN server configuration
- ✅ System configuration reload

### Error Handling
- Network connectivity issues
- Authentication failures (JWT token management)
- API rate limiting
- Invalid configurations with validation
- Resource conflicts (VLAN/network overlap detection)

## Development

### Project Structure
```
pfsense_cli/
├── api/                 # API client and endpoints
├── cli/                 # Click CLI commands
├── config/              # Configuration management
├── models/              # Pydantic data models
└── utils/               # Utilities and logging
```

### Running Tests
```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=pfsense_cli --cov-report=html

# Lint code
flake8 pfsense_cli/
black pfsense_cli/
mypy pfsense_cli/
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Logging

The tool provides structured logging with multiple output formats:

### Console Logging
```bash
# Enable verbose logging
pfsense-cli --verbose client list

# Log to file
pfsense-cli --log-file pfsense.log client add --name "TestClient"
```

### Log Formats
- **Console**: Colored output for terminals
- **File**: Structured JSON or plain text
- **Performance**: Execution time tracking

## Security Considerations

- Store credentials securely (consider using environment variables)
- Use SSL/TLS for all API communications
- Regularly rotate API credentials
- Monitor access logs
- Keep the tool and dependencies updated

## Support

For issues, feature requests, or questions:
- GitHub Issues: [Create an issue](https://github.com/your-org/pfsense-cli/issues)
- Documentation: [Read the docs](https://pfsense-cli.readthedocs.io/)

## License

This project is licensed under the MIT License - see the LICENSE file for details.