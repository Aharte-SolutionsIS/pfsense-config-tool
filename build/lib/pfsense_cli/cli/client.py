"""
Client management CLI commands for pfSense automation tool.
"""

import asyncio
import sys
from typing import List, Optional
import click
from tabulate import tabulate

from ..models.client import ClientConfig, ClientType, ClientStatus, NetworkConfig, VLANConfig, DHCPConfig
from ..api.exceptions import ClientNotFoundError, ClientAlreadyExistsError
from ..utils.logging import get_logger, LogContext
import click
from .utils import get_endpoints

# Use Click's built-in context passing
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .main import PfSenseContext

pass_context = click.pass_obj

logger = get_logger(__name__)


@click.group('client')
def client_group():
    """Client management commands."""
    pass


@client_group.command('add')
@click.option('--name', required=True, help='Client name')
@click.option('--network', required=True, help='Network CIDR (e.g., 192.168.50.0/24)')
@click.option('--vlan', type=int, help='VLAN ID')
@click.option('--client-type', type=click.Choice(['corporate', 'branch_office', 'remote_user', 'guest']), 
              default='corporate', help='Client type')
@click.option('--template', help='Template name to use')
@click.option('--gateway', help='Gateway IP address')
@click.option('--dns', multiple=True, help='DNS server addresses (can be used multiple times)')
@click.option('--domain', help='Domain name')
@click.option('--dhcp/--no-dhcp', default=True, help='Enable DHCP')
@click.option('--dhcp-start', help='DHCP range start IP')
@click.option('--dhcp-end', help='DHCP range end IP')
@click.option('--vpn/--no-vpn', default=False, help='Enable VPN for client')
@click.option('--vpn-port', type=int, help='VPN port assignment')
@click.option('--dry-run', is_flag=True, help='Show what would be done without making changes')
@pass_context
def add_client(ctx, name: str, network: str, vlan: Optional[int], 
               client_type: str, template: Optional[str], gateway: Optional[str],
               dns: List[str], domain: Optional[str], dhcp: bool, 
               dhcp_start: Optional[str], dhcp_end: Optional[str],
               vpn: bool, vpn_port: Optional[int], dry_run: bool):
    """
    Add a new client configuration.
    
    Example:
    pfsense-cli client add --name "AcmeCorp" --network "192.168.50.0/24" --vlan 150
    """
    try:
        with LogContext(logger, client_name=name, operation='add_client'):
            
            if template:
                # Use template-based creation
                _create_from_template(ctx, template, name, {
                    'network_cidr': network,
                    'vlan_id': vlan,
                    'gateway_ip': gateway,
                    'dhcp_start': dhcp_start,
                    'dhcp_end': dhcp_end,
                    'vpn_enabled': vpn,
                    'vpn_port': vpn_port,
                    'dns_servers': list(dns) if dns else None
                })
            else:
                # Manual configuration creation
                _create_manual_config(ctx, name, network, vlan, client_type, gateway, 
                                    dns, domain, dhcp, dhcp_start, dhcp_end, vpn, vpn_port)
            
            if dry_run:
                click.echo("[OK] Dry run completed successfully. Use without --dry-run to apply changes.")
                return
            
            # Apply configuration to pfSense
            endpoints = get_endpoints(ctx)
            client_config = ctx.config_manager.load_client_config(name)
            
            async def create_client():
                return await endpoints.create_client(client_config)
            
            result = asyncio.run(create_client())
            
            click.echo(f"[OK] Client '{name}' created successfully!")
            if ctx.verbose:
                click.echo(f"Configuration saved to: {ctx.config_manager.clients_dir / f'{name}.yaml'}")
                
    except ClientAlreadyExistsError as e:
        click.echo(f"[ERROR] {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to add client '{name}': {e}")
        click.echo(f"[ERROR] Failed to add client: {e}")
        sys.exit(1)


@client_group.command('remove')
@click.argument('name')
@click.option('--force', is_flag=True, help='Skip confirmation prompt')
@click.option('--keep-config', is_flag=True, help='Keep local configuration file')
@pass_context
def remove_client(ctx, name: str, force: bool, keep_config: bool):
    """Remove a client configuration."""
    try:
        with LogContext(logger, client_name=name, operation='remove_client'):
            
            # Check if client exists
            try:
                client_config = ctx.config_manager.load_client_config(name)
            except Exception:
                click.echo(f"[ERROR] Client '{name}' not found in local configuration")
                sys.exit(1)
            
            # Confirmation
            if not force:
                click.echo(f"Client: {name}")
                click.echo(f"Network: {client_config.network.network}")
                if client_config.vlan:
                    click.echo(f"VLAN: {client_config.vlan.vlan_id}")
                click.echo(f"Status: {client_config.status}")
                
                if not click.confirm(f"\n⚠️  Really remove client '{name}'?"):
                    click.echo("Operation cancelled.")
                    return
            
            # Remove from pfSense
            endpoints = get_endpoints(ctx)
            
            async def delete_client():
                return await endpoints.delete_client(name)
            
            asyncio.run(delete_client())
            
            # Remove local configuration
            if not keep_config:
                ctx.config_manager.delete_client_config(name, backup=True)
                click.echo(f"[OK] Client '{name}' removed successfully!")
            else:
                click.echo(f"[OK] Client '{name}' removed from pfSense (local config preserved)")
                
    except ClientNotFoundError as e:
        click.echo(f"[ERROR] {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to remove client '{name}': {e}")
        click.echo(f"[ERROR] Failed to remove client: {e}")
        sys.exit(1)


@client_group.command('list')
@click.option('--format', type=click.Choice(['table', 'json', 'yaml']), default='table')
@click.option('--status', type=click.Choice(['active', 'inactive', 'pending', 'error']), 
              help='Filter by status')
@click.option('--client-type', type=click.Choice(['corporate', 'branch_office', 'remote_user', 'guest']), 
              help='Filter by client type')
@click.option('--show-details', is_flag=True, help='Show detailed information')
@pass_context
def list_clients(ctx, format: str, status: Optional[str], 
                client_type: Optional[str], show_details: bool):
    """List all configured clients."""
    try:
        client_names = ctx.config_manager.list_client_configs()
        
        if not client_names:
            click.echo("No clients configured.")
            return
        
        clients = []
        for name in client_names:
            try:
                client_config = ctx.config_manager.load_client_config(name)
                
                # Apply filters
                if status and client_config.status != status:
                    continue
                if client_type and client_config.client_type != client_type:
                    continue
                
                clients.append(client_config)
            except Exception as e:
                logger.warning(f"Failed to load client config '{name}': {e}")
                continue
        
        if not clients:
            click.echo("No clients match the specified filters.")
            return
        
        if format == 'json':
            import json
            client_data = [client.dict() for client in clients]
            click.echo(json.dumps(client_data, indent=2, default=str))
        elif format == 'yaml':
            import yaml
            client_data = [client.dict() for client in clients]
            click.echo(yaml.dump(client_data, default_flow_style=False))
        else:
            # Table format
            if show_details:
                headers = ['Name', 'Type', 'Status', 'Network', 'VLAN', 'DHCP', 'VPN', 'Updated']
                rows = []
                for client in clients:
                    rows.append([
                        client.name,
                        client.client_type,
                        client.status,
                        client.network.network,
                        client.vlan.vlan_id if client.vlan else 'N/A',
                        '[OK]' if client.dhcp and client.dhcp.enabled else '[ERROR]',
                        '[OK]' if client.vpn_enabled else '[ERROR]',
                        client.updated_at or 'Unknown'
                    ])
            else:
                headers = ['Name', 'Type', 'Status', 'Network', 'VLAN']
                rows = []
                for client in clients:
                    rows.append([
                        client.name,
                        client.client_type,
                        client.status,
                        client.network.network,
                        client.vlan.vlan_id if client.vlan else 'N/A'
                    ])
            
            click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
            click.echo(f"\nTotal: {len(clients)} clients")
            
    except Exception as e:
        logger.error(f"Failed to list clients: {e}")
        click.echo(f"[ERROR] Failed to list clients: {e}")
        sys.exit(1)


@client_group.command('status')
@click.argument('name')
@click.option('--format', type=click.Choice(['table', 'json', 'yaml']), default='table')
@pass_context
def client_status(ctx, name: str, format: str):
    """Show detailed status for a specific client."""
    try:
        with LogContext(logger, client_name=name, operation='client_status'):
            
            # Load local config
            try:
                client_config = ctx.config_manager.load_client_config(name)
            except Exception:
                click.echo(f"[ERROR] Client '{name}' not found in local configuration")
                sys.exit(1)
            
            # Get live status from pfSense
            endpoints = get_endpoints(ctx)
            
            async def get_status():
                try:
                    remote_client = await endpoints.get_client(name)
                    return remote_client
                except ClientNotFoundError:
                    return None
            
            remote_client = asyncio.run(get_status())
            
            if format == 'json':
                import json
                status_data = {
                    'local_config': client_config.dict(),
                    'remote_status': remote_client
                }
                click.echo(json.dumps(status_data, indent=2, default=str))
            elif format == 'yaml':
                import yaml
                status_data = {
                    'local_config': client_config.dict(),
                    'remote_status': remote_client
                }
                click.echo(yaml.dump(status_data, default_flow_style=False))
            else:
                # Table format
                click.echo(f"Client Status: {name}")
                click.echo("=" * (15 + len(name)))
                
                click.echo("\nLocal Configuration:")
                click.echo(f"  Type: {client_config.client_type}")
                click.echo(f"  Status: {client_config.status}")
                click.echo(f"  Network: {client_config.network.network}")
                if client_config.network.gateway:
                    click.echo(f"  Gateway: {client_config.network.gateway}")
                if client_config.vlan:
                    click.echo(f"  VLAN ID: {client_config.vlan.vlan_id}")
                    click.echo(f"  VLAN Interface: {client_config.vlan.interface}")
                
                if client_config.dhcp:
                    click.echo(f"\nDHCP Configuration:")
                    click.echo(f"  Enabled: {'Yes' if client_config.dhcp.enabled else 'No'}")
                    if client_config.dhcp.start_ip and client_config.dhcp.end_ip:
                        click.echo(f"  Range: {client_config.dhcp.start_ip} - {client_config.dhcp.end_ip}")
                    click.echo(f"  Lease Time: {client_config.dhcp.lease_time}s")
                
                click.echo(f"\nVPN: {'Enabled' if client_config.vpn_enabled else 'Disabled'}")
                if client_config.vpn_enabled and client_config.vpn_port:
                    click.echo(f"VPN Port: {client_config.vpn_port}")
                
                if client_config.firewall_rules:
                    click.echo(f"\nFirewall Rules: {len(client_config.firewall_rules)}")
                
                if client_config.nat_rules:
                    click.echo(f"NAT Rules: {len(client_config.nat_rules)}")
                
                click.echo(f"\nRemote Status: {'[OK] Found' if remote_client else '[ERROR] Not found'}")
                
                if client_config.created_at:
                    click.echo(f"Created: {client_config.created_at}")
                if client_config.updated_at:
                    click.echo(f"Updated: {client_config.updated_at}")
                
    except Exception as e:
        logger.error(f"Failed to get client status '{name}': {e}")
        click.echo(f"[ERROR] Failed to get client status: {e}")
        sys.exit(1)


@client_group.command('update')
@click.argument('name')
@click.option('--status', type=click.Choice(['active', 'inactive', 'pending', 'error']))
@click.option('--gateway', help='Gateway IP address')
@click.option('--dns', multiple=True, help='DNS server addresses')
@click.option('--dhcp-start', help='DHCP range start IP')
@click.option('--dhcp-end', help='DHCP range end IP')
@click.option('--enable-vpn/--disable-vpn', help='Enable/disable VPN')
@click.option('--vpn-port', type=int, help='VPN port assignment')
@pass_context
def update_client(ctx, name: str, status: Optional[str], 
                 gateway: Optional[str], dns: List[str], 
                 dhcp_start: Optional[str], dhcp_end: Optional[str],
                 enable_vpn: Optional[bool], vpn_port: Optional[int]):
    """Update client configuration."""
    try:
        with LogContext(logger, client_name=name, operation='update_client'):
            
            # Load existing config
            client_config = ctx.config_manager.load_client_config(name)
            
            # Apply updates
            if status:
                client_config.status = ClientStatus(status)
            
            if gateway:
                client_config.network.gateway = gateway
            
            if dns:
                client_config.network.dns_servers = list(dns)
            
            if dhcp_start or dhcp_end:
                if not client_config.dhcp:
                    client_config.dhcp = DHCPConfig()
                if dhcp_start:
                    client_config.dhcp.start_ip = dhcp_start
                if dhcp_end:
                    client_config.dhcp.end_ip = dhcp_end
            
            if enable_vpn is not None:
                client_config.vpn_enabled = enable_vpn
            
            if vpn_port:
                client_config.vpn_port = vpn_port
            
            # Validate updated config
            errors = ctx.config_manager.validate_config(client_config.dict())
            if errors:
                click.echo("[ERROR] Configuration validation failed:")
                for error in errors:
                    click.echo(f"  - {error}")
                sys.exit(1)
            
            # Save updated config
            ctx.config_manager.save_client_config(client_config)
            
            # Update remote configuration
            endpoints = get_endpoints(ctx)
            
            async def update_client():
                return await endpoints.update_client(name, client_config)
            
            asyncio.run(update_client())
            
            click.echo(f"[OK] Client '{name}' updated successfully!")
            
    except Exception as e:
        logger.error(f"Failed to update client '{name}': {e}")
        click.echo(f"[ERROR] Failed to update client: {e}")
        sys.exit(1)


def _create_from_template(ctx, template: str, name: str, template_vars: dict):
    """Create client configuration from template."""
    # Clean up None values
    clean_vars = {k: v for k, v in template_vars.items() if v is not None}
    
    client_config = ctx.config_manager.create_from_template(template, name, clean_vars)
    click.echo(f"[OK] Created client '{name}' from template '{template}'")


def _create_manual_config(ctx, name: str, network: str, vlan: Optional[int], 
                         client_type: str, gateway: Optional[str], dns: List[str], 
                         domain: Optional[str], dhcp: bool, dhcp_start: Optional[str], 
                         dhcp_end: Optional[str], vpn: bool, vpn_port: Optional[int]):
    """Create client configuration manually."""
    
    # Build network config
    network_config = NetworkConfig(
        network=network,
        gateway=gateway,
        dns_servers=list(dns) if dns else [],
        domain_name=domain
    )
    
    # Build VLAN config if specified
    vlan_config = None
    if vlan:
        vlan_config = VLANConfig(
            vlan_id=vlan,
            description=f"{name} VLAN"
        )
    
    # Build DHCP config if enabled
    dhcp_config = None
    if dhcp:
        dhcp_config = DHCPConfig(
            enabled=True,
            start_ip=dhcp_start,
            end_ip=dhcp_end
        )
    
    # Create client config
    client_config = ClientConfig(
        name=name,
        client_type=ClientType(client_type),
        network=network_config,
        vlan=vlan_config,
        dhcp=dhcp_config,
        vpn_enabled=vpn,
        vpn_port=vpn_port
    )
    
    # Validate configuration
    errors = ctx.config_manager.validate_config(client_config.dict())
    if errors:
        click.echo("[ERROR] Configuration validation failed:")
        for error in errors:
            click.echo(f"  - {error}")
        sys.exit(1)
    
    # Save configuration
    ctx.config_manager.save_client_config(client_config)
    click.echo(f"[OK] Created client configuration '{name}'")