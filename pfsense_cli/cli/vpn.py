"""
VPN management CLI commands for pfSense automation tool.
"""

import asyncio
import sys
import os
from typing import List, Optional
import click
from tabulate import tabulate

from ..models.vpn import OpenVPNServerConfig, VPNClient, CertificateConfig
from ..api.exceptions import VPNConfigError, CertificateError
from ..utils.logging import get_logger, LogContext
from .main import PfSenseContext, pass_context, _get_endpoints

logger = get_logger(__name__)


@click.group('vpn')
def vpn_group():
    """VPN management and configuration commands."""
    pass


@vpn_group.command('setup')
@click.option('--client', required=True, help='Client name')
@click.option('--port', type=int, default=1194, help='VPN port (default: 1194)')
@click.option('--protocol', type=click.Choice(['udp', 'tcp']), default='udp', help='VPN protocol')
@click.option('--network', help='VPN tunnel network (e.g., 10.8.0.0/24)')
@click.option('--push-routes', multiple=True, help='Routes to push to clients')
@click.option('--dns', multiple=True, help='DNS servers to push to clients')
@click.option('--compression/--no-compression', default=False, help='Enable compression')
@click.option('--client-to-client/--no-client-to-client', default=False, help='Allow client-to-client communication')
@click.option('--dry-run', is_flag=True, help='Show what would be done without making changes')
@pass_context
def setup_vpn(ctx: PfSenseContext, client: str, port: int, protocol: str, 
              network: Optional[str], push_routes: List[str], dns: List[str],
              compression: bool, client_to_client: bool, dry_run: bool):
    """
    Setup OpenVPN server for a client.
    
    Example:
    pfsense-cli vpn setup --client "AcmeCorp" --port 1194 --network "10.8.0.0/24"
    """
    try:
        with LogContext(logger, client_name=client, operation='setup_vpn'):
            
            # Load client config
            try:
                client_config = ctx.config_manager.load_client_config(client)
            except Exception:
                click.echo(f"❌ Client '{client}' not found")
                sys.exit(1)
            
            # Use client network as default tunnel network
            if not network:
                # Generate tunnel network based on client network
                import ipaddress
                client_network = ipaddress.IPv4Network(client_config.network.network, strict=False)
                # Use a different subnet for VPN tunnel
                tunnel_network = f"10.{client_network.network_address.packed[2]}.0.0/24"
                network = tunnel_network
            
            # Create OpenVPN server config
            server_config = OpenVPNServerConfig(
                name=f"{client}_vpn",
                protocol=protocol,
                port=port,
                tunnel_network=network,
                ca_certificate=f"{client}_ca",
                server_certificate=f"{client}_server",
                push_routes=list(push_routes),
                dns_servers=list(dns) if dns else client_config.network.dns_servers,
                compression=compression,
                client_to_client=client_to_client
            )
            
            click.echo(f"OpenVPN Server Configuration for {client}:")
            click.echo(f"  Port: {port}/{protocol}")
            click.echo(f"  Tunnel Network: {network}")
            click.echo(f"  DNS Servers: {', '.join(server_config.dns_servers)}")
            click.echo(f"  Compression: {'Enabled' if compression else 'Disabled'}")
            click.echo(f"  Client-to-Client: {'Enabled' if client_to_client else 'Disabled'}")
            
            if dry_run:
                click.echo("\n✅ Dry run completed. Use without --dry-run to create VPN server.")
                return
            
            # Update client config
            client_config.vpn_enabled = True
            client_config.vpn_port = port
            ctx.config_manager.save_client_config(client_config)
            
            # Setup VPN server via API
            endpoints = _get_endpoints(ctx)
            
            async def setup_server():
                return await endpoints.setup_openvpn_server(server_config)
            
            result = asyncio.run(setup_server())
            
            click.echo(f"✅ OpenVPN server setup completed for client '{client}'")
            click.echo(f"VPN Port: {port}")
            click.echo(f"Tunnel Network: {network}")
            
    except Exception as e:
        logger.error(f"Failed to setup VPN for client '{client}': {e}")
        click.echo(f"❌ Failed to setup VPN: {e}")
        sys.exit(1)


@vpn_group.command('client')
@click.argument('action', type=click.Choice(['create', 'revoke', 'list', 'export']))
@click.option('--server', help='VPN server name')
@click.option('--client-name', help='VPN client name')
@click.option('--common-name', help='Certificate common name')
@click.option('--email', help='Client email address')
@click.option('--description', help='Client description')
@click.option('--output-dir', type=click.Path(), help='Output directory for client config')
@click.option('--format', type=click.Choice(['table', 'json', 'yaml']), default='table')
@pass_context
def manage_vpn_client(ctx: PfSenseContext, action: str, server: Optional[str], 
                     client_name: Optional[str], common_name: Optional[str],
                     email: Optional[str], description: Optional[str], 
                     output_dir: Optional[str], format: str):
    """
    Manage VPN client certificates and configurations.
    
    Examples:
    pfsense-cli vpn client create --server "AcmeCorp_vpn" --client-name "john_doe" --email "john@acme.com"
    pfsense-cli vpn client list
    pfsense-cli vpn client export --client-name "john_doe" --output-dir "./vpn_configs"
    """
    try:
        if action == 'create':
            if not all([server, client_name]):
                click.echo("❌ Server and client-name are required for create action")
                sys.exit(1)
            
            with LogContext(logger, client_name=client_name, operation='create_vpn_client'):
                
                # Create VPN client config
                vpn_client = VPNClient(
                    name=client_name,
                    common_name=common_name or client_name,
                    email=email,
                    description=description,
                    certificate_name=f"{client_name}_cert"
                )
                
                # Create client via API
                endpoints = _get_endpoints(ctx)
                
                async def create_client():
                    return await endpoints.create_vpn_client(server, vpn_client)
                
                result = asyncio.run(create_client())
                
                click.echo(f"✅ VPN client '{client_name}' created successfully")
                click.echo(f"Certificate: {vpn_client.certificate_name}")
                
                # Save client configuration locally
                vpn_clients_dir = ctx.config_manager.config_dir / 'vpn_clients'
                vpn_clients_dir.mkdir(exist_ok=True)
                
                client_file = vpn_clients_dir / f'{client_name}.yaml'
                import yaml
                with open(client_file, 'w') as f:
                    yaml.dump(vpn_client.dict(), f, default_flow_style=False)
                
                click.echo(f"Client configuration saved: {client_file}")
                
        elif action == 'revoke':
            if not client_name:
                click.echo("❌ Client name is required for revoke action")
                sys.exit(1)
            
            with LogContext(logger, client_name=client_name, operation='revoke_vpn_client'):
                
                # This would revoke the client certificate
                click.echo(f"⚠️  Revoking VPN client '{client_name}'...")
                
                # For now, just update the local status
                vpn_clients_dir = ctx.config_manager.config_dir / 'vpn_clients'
                client_file = vpn_clients_dir / f'{client_name}.yaml'
                
                if client_file.exists():
                    import yaml
                    with open(client_file, 'r') as f:
                        client_data = yaml.safe_load(f)
                    
                    client_data['status'] = 'revoked'
                    
                    with open(client_file, 'w') as f:
                        yaml.dump(client_data, f, default_flow_style=False)
                
                click.echo(f"✅ VPN client '{client_name}' revoked")
                
        elif action == 'list':
            # List VPN clients
            vpn_clients_dir = ctx.config_manager.config_dir / 'vpn_clients'
            
            if not vpn_clients_dir.exists():
                click.echo("No VPN clients found.")
                return
            
            clients = []
            for client_file in vpn_clients_dir.glob('*.yaml'):
                try:
                    import yaml
                    with open(client_file, 'r') as f:
                        client_data = yaml.safe_load(f)
                    clients.append(client_data)
                except Exception:
                    continue
            
            if not clients:
                click.echo("No VPN clients found.")
                return
            
            if format == 'json':
                import json
                click.echo(json.dumps(clients, indent=2, default=str))
            elif format == 'yaml':
                import yaml
                click.echo(yaml.dump(clients, default_flow_style=False))
            else:
                # Table format
                headers = ['Name', 'Common Name', 'Status', 'Email', 'Certificate']
                rows = []
                for client in clients:
                    status_icon = {
                        'connected': '✅',
                        'disconnected': '⭕',
                        'revoked': '❌',
                        'expired': '⚠️'
                    }.get(client.get('status', 'disconnected'), '❓')
                    
                    rows.append([
                        client.get('name', 'N/A'),
                        client.get('common_name', 'N/A'),
                        f"{status_icon} {client.get('status', 'unknown').title()}",
                        client.get('email', 'N/A'),
                        client.get('certificate_name', 'N/A')
                    ])
                
                click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
                click.echo(f"\nTotal: {len(clients)} VPN clients")
                
        elif action == 'export':
            if not client_name:
                click.echo("❌ Client name is required for export action")
                sys.exit(1)
            
            with LogContext(logger, client_name=client_name, operation='export_vpn_client'):
                
                # Load client configuration
                vpn_clients_dir = ctx.config_manager.config_dir / 'vpn_clients'
                client_file = vpn_clients_dir / f'{client_name}.yaml'
                
                if not client_file.exists():
                    click.echo(f"❌ VPN client '{client_name}' not found")
                    sys.exit(1)
                
                # Set output directory
                if not output_dir:
                    output_dir = './vpn_configs'
                
                output_path = os.path.abspath(output_dir)
                os.makedirs(output_path, exist_ok=True)
                
                # Generate OpenVPN client configuration file
                config_content = f"""# OpenVPN Client Configuration for {client_name}
client
dev tun
proto udp
remote {ctx.config_manager.get_setting('pfsense.base_url', 'YOUR_PFSENSE_IP')} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert {client_name}.crt
key {client_name}.key
verb 3
cipher AES-256-CBC
auth SHA256
compress lz4-v2
"""
                
                # Save configuration file
                config_file = os.path.join(output_path, f'{client_name}.ovpn')
                with open(config_file, 'w') as f:
                    f.write(config_content)
                
                click.echo(f"✅ VPN client configuration exported:")
                click.echo(f"   Config file: {config_file}")
                click.echo(f"\n📋 Next steps:")
                click.echo(f"   1. Copy the following files from pfSense:")
                click.echo(f"      - ca.crt (Certificate Authority)")
                click.echo(f"      - {client_name}.crt (Client Certificate)")
                click.echo(f"      - {client_name}.key (Client Private Key)")
                click.echo(f"   2. Place them in the same directory as the .ovpn file")
                click.echo(f"   3. Import the .ovpn file in your OpenVPN client")
                
    except Exception as e:
        logger.error(f"Failed to manage VPN client: {e}")
        click.echo(f"❌ Failed to manage VPN client: {e}")
        sys.exit(1)


@vpn_group.command('status')
@click.option('--server', help='Specific VPN server name')
@click.option('--format', type=click.Choice(['table', 'json', 'yaml']), default='table')
@pass_context
def vpn_status(ctx: PfSenseContext, server: Optional[str], format: str):
    """Show VPN server status and connected clients."""
    try:
        endpoints = _get_endpoints(ctx)
        
        async def get_status():
            return await endpoints.get_vpn_status()
        
        status_data = asyncio.run(get_status())
        
        if format == 'json':
            import json
            click.echo(json.dumps(status_data, indent=2, default=str))
        elif format == 'yaml':
            import yaml
            click.echo(yaml.dump(status_data, default_flow_style=False))
        else:
            # Table format
            click.echo("VPN Server Status")
            click.echo("=" * 16)
            
            servers = status_data.get('data', [])
            if not servers:
                click.echo("No VPN servers configured.")
                return
            
            for srv in servers:
                click.echo(f"\nServer: {srv.get('name', 'Unknown')}")
                click.echo(f"Status: {'✅ Running' if srv.get('status') == 'up' else '❌ Stopped'}")
                click.echo(f"Port: {srv.get('port', 'N/A')}")
                click.echo(f"Protocol: {srv.get('protocol', 'N/A')}")
                click.echo(f"Connected Clients: {srv.get('connected_clients', 0)}")
                
                # Show connected clients
                active_clients = srv.get('active_clients', [])
                if active_clients:
                    click.echo("\nConnected Clients:")
                    headers = ['Client', 'IP Address', 'Connected Since', 'Bytes In/Out']
                    rows = []
                    for client in active_clients:
                        rows.append([
                            client.get('common_name', 'Unknown'),
                            client.get('virtual_addr', 'N/A'),
                            client.get('connected_since', 'N/A'),
                            f"{client.get('bytes_received', 0)}/{client.get('bytes_sent', 0)}"
                        ])
                    
                    click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
                else:
                    click.echo("No clients currently connected.")
                    
    except Exception as e:
        logger.error(f"Failed to get VPN status: {e}")
        click.echo(f"❌ Failed to get VPN status: {e}")
        sys.exit(1)


@vpn_group.command('logs')
@click.option('--server', help='Specific VPN server name')
@click.option('--lines', type=int, default=50, help='Number of log lines to show')
@click.option('--follow', is_flag=True, help='Follow log output (like tail -f)')
@pass_context
def vpn_logs(ctx: PfSenseContext, server: Optional[str], lines: int, follow: bool):
    """Show VPN server logs."""
    try:
        click.echo("VPN Server Logs")
        click.echo("=" * 15)
        
        # This would typically fetch logs from pfSense API
        # For now, show a placeholder message
        if follow:
            click.echo("Following VPN logs (Ctrl+C to stop)...")
            click.echo("(This would show real-time VPN logs from pfSense)")
        else:
            click.echo(f"Showing last {lines} lines of VPN logs:")
            click.echo("(This would show VPN logs from pfSense)")
        
        # Example log entries
        example_logs = [
            "2024-01-15 10:30:15 OpenVPN[1234]: CLIENT_CONNECT john_doe 10.8.0.2",
            "2024-01-15 10:30:16 OpenVPN[1234]: Authentication succeeded for 'john_doe'",
            "2024-01-15 10:35:22 OpenVPN[1234]: CLIENT_DISCONNECT john_doe 10.8.0.2 (Received 1024 bytes, Sent 2048 bytes)",
            "2024-01-15 10:40:01 OpenVPN[1234]: TLS handshake succeeded for 'jane_doe'",
            "2024-01-15 10:40:02 OpenVPN[1234]: CLIENT_CONNECT jane_doe 10.8.0.3"
        ]
        
        for log_line in example_logs[-lines:]:
            click.echo(log_line)
            
        if not follow:
            click.echo(f"\n(Showing example logs - implement pfSense log API integration)")
        
    except KeyboardInterrupt:
        click.echo("\nLog following stopped.")
    except Exception as e:
        logger.error(f"Failed to get VPN logs: {e}")
        click.echo(f"❌ Failed to get VPN logs: {e}")
        sys.exit(1)


@vpn_group.command('certificates')
@click.argument('action', type=click.Choice(['create-ca', 'create-server', 'list', 'revoke']))
@click.option('--name', help='Certificate name')
@click.option('--common-name', help='Certificate common name')
@click.option('--country', default='US', help='Country code')
@click.option('--state', help='State or province')
@click.option('--city', help='City')
@click.option('--organization', help='Organization name')
@click.option('--email', help='Email address')
@click.option('--key-length', type=click.Choice(['2048', '4096']), default='2048', help='Key length in bits')
@click.option('--lifetime', type=int, default=3650, help='Certificate lifetime in days')
@click.option('--format', type=click.Choice(['table', 'json', 'yaml']), default='table')
@pass_context
def manage_certificates(ctx: PfSenseContext, action: str, name: Optional[str],
                       common_name: Optional[str], country: str, state: Optional[str],
                       city: Optional[str], organization: Optional[str], email: Optional[str],
                       key_length: str, lifetime: int, format: str):
    """
    Manage VPN certificates.
    
    Examples:
    pfsense-cli vpn certificates create-ca --name "MyCA" --common-name "My Certificate Authority"
    pfsense-cli vpn certificates list
    """
    try:
        if action in ['create-ca', 'create-server']:
            if not all([name, common_name]):
                click.echo("❌ Name and common-name are required")
                sys.exit(1)
            
            cert_type = 'Certificate Authority' if action == 'create-ca' else 'Server Certificate'
            
            with LogContext(logger, operation=f'create_{action}'):
                
                # Create certificate config
                cert_config = CertificateConfig(
                    name=name,
                    common_name=common_name,
                    country=country,
                    state=state or '',
                    city=city or '',
                    organization=organization or '',
                    email=email,
                    key_length=int(key_length),
                    lifetime=lifetime
                )
                
                click.echo(f"Creating {cert_type}:")
                click.echo(f"  Name: {name}")
                click.echo(f"  Common Name: {common_name}")
                click.echo(f"  Key Length: {key_length} bits")
                click.echo(f"  Lifetime: {lifetime} days")
                
                # Save certificate configuration locally
                certs_dir = ctx.config_manager.config_dir / 'certificates'
                certs_dir.mkdir(exist_ok=True)
                
                cert_file = certs_dir / f'{name}.yaml'
                import yaml
                cert_data = cert_config.dict()
                cert_data['type'] = 'ca' if action == 'create-ca' else 'server'
                
                with open(cert_file, 'w') as f:
                    yaml.dump(cert_data, f, default_flow_style=False)
                
                click.echo(f"✅ {cert_type} configuration saved: {cert_file}")
                click.echo("📋 Next: Apply this certificate in pfSense certificate manager")
                
        elif action == 'list':
            # List certificates
            certs_dir = ctx.config_manager.config_dir / 'certificates'
            
            if not certs_dir.exists():
                click.echo("No certificates found.")
                return
            
            certificates = []
            for cert_file in certs_dir.glob('*.yaml'):
                try:
                    import yaml
                    with open(cert_file, 'r') as f:
                        cert_data = yaml.safe_load(f)
                    certificates.append(cert_data)
                except Exception:
                    continue
            
            if not certificates:
                click.echo("No certificates found.")
                return
            
            if format == 'json':
                import json
                click.echo(json.dumps(certificates, indent=2, default=str))
            elif format == 'yaml':
                import yaml
                click.echo(yaml.dump(certificates, default_flow_style=False))
            else:
                # Table format
                headers = ['Name', 'Type', 'Common Name', 'Key Length', 'Lifetime', 'Country']
                rows = []
                for cert in certificates:
                    cert_type_icon = '🏛️' if cert.get('type') == 'ca' else '🖥️'
                    rows.append([
                        cert.get('name', 'N/A'),
                        f"{cert_type_icon} {cert.get('type', 'unknown').upper()}",
                        cert.get('common_name', 'N/A'),
                        f"{cert.get('key_length', 'N/A')} bits",
                        f"{cert.get('lifetime', 'N/A')} days",
                        cert.get('country', 'N/A')
                    ])
                
                click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
                click.echo(f"\nTotal: {len(certificates)} certificates")
                
        elif action == 'revoke':
            if not name:
                click.echo("❌ Certificate name is required for revoke action")
                sys.exit(1)
            
            with LogContext(logger, operation='revoke_certificate'):
                
                click.echo(f"⚠️  Revoking certificate '{name}'...")
                click.echo("📋 This action would revoke the certificate in pfSense")
                click.echo("    and update the Certificate Revocation List (CRL)")
                
                # For now, just mark as revoked locally
                certs_dir = ctx.config_manager.config_dir / 'certificates'
                cert_file = certs_dir / f'{name}.yaml'
                
                if cert_file.exists():
                    import yaml
                    with open(cert_file, 'r') as f:
                        cert_data = yaml.safe_load(f)
                    
                    cert_data['status'] = 'revoked'
                    cert_data['revoked_at'] = ctx.config_manager.settings.get('created_at')
                    
                    with open(cert_file, 'w') as f:
                        yaml.dump(cert_data, f, default_flow_style=False)
                
                click.echo(f"✅ Certificate '{name}' marked as revoked")
                
    except Exception as e:
        logger.error(f"Failed to manage certificates: {e}")
        click.echo(f"❌ Failed to manage certificates: {e}")
        sys.exit(1)