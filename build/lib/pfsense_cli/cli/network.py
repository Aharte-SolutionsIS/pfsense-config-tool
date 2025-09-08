"""
Network operations CLI commands for pfSense automation tool.
"""

import asyncio
import sys
from typing import List, Optional
import click
from tabulate import tabulate

from ..models.network import NetworkSettings, NetworkInterface, RouteConfig, DHCPPool
from ..api.exceptions import ClientNotFoundError
from ..utils.logging import get_logger, LogContext
from .utils import get_endpoints

# Use Click's built-in context passing
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .main import PfSenseContext

pass_context = click.pass_obj

logger = get_logger(__name__)


@click.group('network')
def network_group():
    """Network operations and configuration commands."""
    pass


@network_group.command('configure')
@click.option('--client', required=True, help='Client name')
@click.option('--gateway', help='Gateway IP address')
@click.option('--dns', multiple=True, help='DNS server addresses')
@click.option('--domain', help='Domain name')
@click.option('--mtu', type=int, help='MTU size')
@click.option('--dry-run', is_flag=True, help='Show what would be done without making changes')
@pass_context
def configure_network(ctx, client: str, gateway: Optional[str], 
                     dns: List[str], domain: Optional[str], mtu: Optional[int], dry_run: bool):
    """
    Configure network settings for a client.
    
    Example:
    pfsense-cli network configure --client "AcmeCorp" --gateway "192.168.50.1" --dns "8.8.8.8"
    """
    try:
        with LogContext(logger, client_name=client, operation='configure_network'):
            
            # Load client config
            try:
                client_config = ctx.config_manager.load_client_config(client)
            except Exception:
                click.echo(f"[ERROR] Client '{client}' not found")
                sys.exit(1)
            
            # Update network settings
            if gateway:
                client_config.network.gateway = gateway
                click.echo(f"Setting gateway: {gateway}")
            
            if dns:
                client_config.network.dns_servers = list(dns)
                click.echo(f"Setting DNS servers: {', '.join(dns)}")
            
            if domain:
                client_config.network.domain_name = domain
                click.echo(f"Setting domain: {domain}")
            
            # Build network settings object
            network_settings = NetworkSettings(
                hostname=f"pfsense-{client.lower()}",
                domain=client_config.network.domain_name,
                interfaces=[],  # Will be populated by the API
                dns=ctx.config_manager.settings.get('network', {})
            )
            
            if dry_run:
                click.echo("\n[OK] Dry run completed. Use without --dry-run to apply changes.")
                return
            
            # Save updated client config
            ctx.config_manager.save_client_config(client_config)
            
            # Apply to pfSense
            endpoints = get_endpoints(ctx)
            
            async def configure():
                return await endpoints.configure_network(client, network_settings)
            
            result = asyncio.run(configure())
            
            click.echo(f"[OK] Network configured for client '{client}'")
            
    except Exception as e:
        logger.error(f"Failed to configure network for client '{client}': {e}")
        click.echo(f"[ERROR] Failed to configure network: {e}")
        sys.exit(1)


@network_group.command('interfaces')
@click.option('--format', type=click.Choice(['table', 'json', 'yaml']), default='table')
@click.option('--status', type=click.Choice(['up', 'down', 'unknown']), help='Filter by status')
@click.option('--type', type=click.Choice(['physical', 'vlan', 'bridge', 'vpn']), help='Filter by type')
@pass_context
def list_interfaces(ctx, format: str, status: Optional[str], type: Optional[str]):
    """List network interfaces."""
    try:
        endpoints = get_endpoints(ctx)
        
        async def get_interfaces():
            # This would call the pfSense API to get interfaces
            # For now, we'll use a placeholder response
            return [
                {
                    'name': 'em0',
                    'description': 'WAN Interface',
                    'status': 'up',
                    'ip_address': '192.168.1.10',
                    'type': 'physical'
                },
                {
                    'name': 'em1',
                    'description': 'LAN Interface', 
                    'status': 'up',
                    'ip_address': '10.0.0.1',
                    'type': 'physical'
                }
            ]
        
        interfaces = asyncio.run(get_interfaces())
        
        # Apply filters
        if status:
            interfaces = [iface for iface in interfaces if iface.get('status') == status]
        if type:
            interfaces = [iface for iface in interfaces if iface.get('type') == type]
        
        if not interfaces:
            click.echo("No interfaces found matching the criteria.")
            return
        
        if format == 'json':
            import json
            click.echo(json.dumps(interfaces, indent=2))
        elif format == 'yaml':
            import yaml
            click.echo(yaml.dump(interfaces, default_flow_style=False))
        else:
            # Table format
            headers = ['Name', 'Description', 'Status', 'IP Address', 'Type']
            rows = []
            for iface in interfaces:
                status_icon = '[OK]' if iface.get('status') == 'up' else '[ERROR]'
                rows.append([
                    iface.get('name', 'N/A'),
                    iface.get('description', 'N/A'),
                    f"{status_icon} {iface.get('status', 'unknown').title()}",
                    iface.get('ip_address', 'N/A'),
                    iface.get('type', 'unknown').title()
                ])
            
            click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
            click.echo(f"\nTotal: {len(interfaces)} interfaces")
            
    except Exception as e:
        logger.error(f"Failed to list interfaces: {e}")
        click.echo(f"[ERROR] Failed to list interfaces: {e}")
        sys.exit(1)


@network_group.command('vlan')
@click.argument('action', type=click.Choice(['create', 'delete', 'list']))
@click.option('--client', help='Client name (for create/delete)')
@click.option('--vlan-id', type=int, help='VLAN ID (for create)')
@click.option('--interface', default='em0', help='Parent interface (for create)')
@click.option('--description', help='VLAN description (for create)')
@click.option('--format', type=click.Choice(['table', 'json', 'yaml']), default='table')
@pass_context
def manage_vlan(ctx, action: str, client: Optional[str], 
                vlan_id: Optional[int], interface: str, description: Optional[str], format: str):
    """
    Manage VLAN configurations.
    
    Examples:
    pfsense-cli network vlan create --client "AcmeCorp" --vlan-id 150
    pfsense-cli network vlan list
    """
    try:
        if action == 'create':
            if not client or not vlan_id:
                click.echo("[ERROR] Client name and VLAN ID are required for create action")
                sys.exit(1)
            
            with LogContext(logger, client_name=client, operation='create_vlan'):
                
                # Load client config
                try:
                    client_config = ctx.config_manager.load_client_config(client)
                except Exception:
                    click.echo(f"[ERROR] Client '{client}' not found")
                    sys.exit(1)
                
                # Update VLAN configuration
                from ..models.client import VLANConfig
                client_config.vlan = VLANConfig(
                    vlan_id=vlan_id,
                    interface=interface,
                    description=description or f"{client} VLAN"
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
                
                click.echo(f"[OK] VLAN {vlan_id} created for client '{client}'")
                
        elif action == 'delete':
            if not client:
                click.echo("[ERROR] Client name is required for delete action")
                sys.exit(1)
            
            with LogContext(logger, client_name=client, operation='delete_vlan'):
                
                # Load and update client config
                client_config = ctx.config_manager.load_client_config(client)
                old_vlan_id = client_config.vlan.vlan_id if client_config.vlan else None
                client_config.vlan = None
                
                # Save configuration
                ctx.config_manager.save_client_config(client_config)
                
                click.echo(f"[OK] VLAN {old_vlan_id} removed from client '{client}'")
                
        elif action == 'list':
            # List all VLANs from client configurations
            client_names = ctx.config_manager.list_client_configs()
            vlans = []
            
            for name in client_names:
                try:
                    client_config = ctx.config_manager.load_client_config(name)
                    if client_config.vlan:
                        vlans.append({
                            'client': name,
                            'vlan_id': client_config.vlan.vlan_id,
                            'interface': client_config.vlan.interface,
                            'description': client_config.vlan.description,
                            'network': client_config.network.network
                        })
                except Exception:
                    continue
            
            if not vlans:
                click.echo("No VLANs configured.")
                return
            
            if format == 'json':
                import json
                click.echo(json.dumps(vlans, indent=2))
            elif format == 'yaml':
                import yaml
                click.echo(yaml.dump(vlans, default_flow_style=False))
            else:
                # Table format
                headers = ['Client', 'VLAN ID', 'Interface', 'Network', 'Description']
                rows = []
                for vlan in vlans:
                    rows.append([
                        vlan['client'],
                        vlan['vlan_id'],
                        vlan['interface'],
                        vlan['network'],
                        vlan['description'] or 'N/A'
                    ])
                
                click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
                click.echo(f"\nTotal: {len(vlans)} VLANs")
                
    except Exception as e:
        logger.error(f"Failed to manage VLAN: {e}")
        click.echo(f"[ERROR] Failed to manage VLAN: {e}")
        sys.exit(1)


@network_group.command('dhcp')
@click.argument('action', type=click.Choice(['enable', 'disable', 'status']))
@click.option('--client', help='Client name')
@click.option('--start-ip', help='DHCP range start IP')
@click.option('--end-ip', help='DHCP range end IP')
@click.option('--lease-time', type=int, help='Lease time in seconds')
@click.option('--format', type=click.Choice(['table', 'json', 'yaml']), default='table')
@pass_context
def manage_dhcp(ctx, action: str, client: Optional[str], 
                start_ip: Optional[str], end_ip: Optional[str], lease_time: Optional[int], format: str):
    """
    Manage DHCP configurations.
    
    Examples:
    pfsense-cli network dhcp enable --client "AcmeCorp" --start-ip "192.168.50.100" --end-ip "192.168.50.200"
    pfsense-cli network dhcp status
    """
    try:
        if action in ['enable', 'disable']:
            if not client:
                click.echo("[ERROR] Client name is required")
                sys.exit(1)
            
            with LogContext(logger, client_name=client, operation=f'{action}_dhcp'):
                
                # Load client config
                client_config = ctx.config_manager.load_client_config(client)
                
                if action == 'enable':
                    from ..models.client import DHCPConfig
                    client_config.dhcp = DHCPConfig(
                        enabled=True,
                        start_ip=start_ip,
                        end_ip=end_ip,
                        lease_time=lease_time or 7200
                    )
                    click.echo(f"[OK] DHCP enabled for client '{client}'")
                else:
                    if client_config.dhcp:
                        client_config.dhcp.enabled = False
                    click.echo(f"[OK] DHCP disabled for client '{client}'")
                
                # Save configuration
                ctx.config_manager.save_client_config(client_config)
                
        elif action == 'status':
            # Show DHCP status for all clients or specific client
            if client:
                clients_to_check = [client]
            else:
                clients_to_check = ctx.config_manager.list_client_configs()
            
            dhcp_configs = []
            for name in clients_to_check:
                try:
                    client_config = ctx.config_manager.load_client_config(name)
                    if client_config.dhcp:
                        dhcp_configs.append({
                            'client': name,
                            'enabled': client_config.dhcp.enabled,
                            'start_ip': client_config.dhcp.start_ip,
                            'end_ip': client_config.dhcp.end_ip,
                            'lease_time': client_config.dhcp.lease_time,
                            'network': client_config.network.network
                        })
                except Exception:
                    continue
            
            if not dhcp_configs:
                click.echo("No DHCP configurations found.")
                return
            
            if format == 'json':
                import json
                click.echo(json.dumps(dhcp_configs, indent=2))
            elif format == 'yaml':
                import yaml
                click.echo(yaml.dump(dhcp_configs, default_flow_style=False))
            else:
                # Table format
                headers = ['Client', 'Status', 'Network', 'Range', 'Lease Time']
                rows = []
                for dhcp in dhcp_configs:
                    status_icon = '[OK]' if dhcp['enabled'] else '[ERROR]'
                    range_str = f"{dhcp['start_ip']} - {dhcp['end_ip']}" if dhcp['start_ip'] and dhcp['end_ip'] else 'N/A'
                    
                    rows.append([
                        dhcp['client'],
                        f"{status_icon} {'Enabled' if dhcp['enabled'] else 'Disabled'}",
                        dhcp['network'],
                        range_str,
                        f"{dhcp['lease_time']}s"
                    ])
                
                click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
                click.echo(f"\nTotal: {len(dhcp_configs)} DHCP configurations")
                
    except Exception as e:
        logger.error(f"Failed to manage DHCP: {e}")
        click.echo(f"[ERROR] Failed to manage DHCP: {e}")
        sys.exit(1)


@network_group.command('nat')
@click.argument('action', type=click.Choice(['add', 'remove', 'list']))
@click.option('--client', help='Client name')
@click.option('--external-port', type=int, help='External port')
@click.option('--internal-ip', help='Internal IP address')
@click.option('--internal-port', type=int, help='Internal port')
@click.option('--protocol', type=click.Choice(['tcp', 'udp']), default='tcp', help='Protocol')
@click.option('--description', help='NAT rule description')
@click.option('--format', type=click.Choice(['table', 'json', 'yaml']), default='table')
@pass_context
def manage_nat(ctx, action: str, client: Optional[str], 
               external_port: Optional[int], internal_ip: Optional[str], 
               internal_port: Optional[int], protocol: str, description: Optional[str], format: str):
    """
    Manage NAT (port forwarding) rules.
    
    Examples:
    pfsense-cli network nat add --client "AcmeCorp" --external-port 8080 --internal-ip "192.168.50.10" --internal-port 80
    pfsense-cli network nat list
    """
    try:
        if action == 'add':
            if not all([client, external_port, internal_ip, internal_port]):
                click.echo("[ERROR] Client, external-port, internal-ip, and internal-port are required")
                sys.exit(1)
            
            with LogContext(logger, client_name=client, operation='add_nat_rule'):
                
                # Load client config
                client_config = ctx.config_manager.load_client_config(client)
                
                # Create NAT rule
                from ..models.client import NATRule
                nat_rule = NATRule(
                    interface='wan',  # Typically WAN interface
                    protocol=protocol,
                    external_port=external_port,
                    internal_ip=internal_ip,
                    internal_port=internal_port,
                    description=description or f"{client} NAT rule"
                )
                
                # Add to client config
                client_config.nat_rules.append(nat_rule)
                
                # Save configuration
                ctx.config_manager.save_client_config(client_config)
                
                click.echo(f"[OK] NAT rule added for client '{client}': {external_port} -> {internal_ip}:{internal_port}")
                
        elif action == 'remove':
            if not client:
                click.echo("[ERROR] Client name is required")
                sys.exit(1)
            
            with LogContext(logger, client_name=client, operation='remove_nat_rule'):
                
                # Load client config
                client_config = ctx.config_manager.load_client_config(client)
                
                # Find and remove NAT rule
                original_count = len(client_config.nat_rules)
                if external_port:
                    client_config.nat_rules = [
                        rule for rule in client_config.nat_rules 
                        if rule.external_port != external_port
                    ]
                else:
                    # Remove all NAT rules for client
                    client_config.nat_rules = []
                
                removed_count = original_count - len(client_config.nat_rules)
                
                if removed_count == 0:
                    click.echo(f"[ERROR] No NAT rules found to remove for client '{client}'")
                    return
                
                # Save configuration
                ctx.config_manager.save_client_config(client_config)
                
                click.echo(f"[OK] Removed {removed_count} NAT rule(s) for client '{client}'")
                
        elif action == 'list':
            # List NAT rules for all clients or specific client
            if client:
                clients_to_check = [client]
            else:
                clients_to_check = ctx.config_manager.list_client_configs()
            
            nat_rules = []
            for name in clients_to_check:
                try:
                    client_config = ctx.config_manager.load_client_config(name)
                    for rule in client_config.nat_rules:
                        nat_rules.append({
                            'client': name,
                            'interface': rule.interface,
                            'protocol': rule.protocol,
                            'external_port': rule.external_port,
                            'internal_ip': rule.internal_ip,
                            'internal_port': rule.internal_port,
                            'description': rule.description
                        })
                except Exception:
                    continue
            
            if not nat_rules:
                click.echo("No NAT rules found.")
                return
            
            if format == 'json':
                import json
                click.echo(json.dumps(nat_rules, indent=2))
            elif format == 'yaml':
                import yaml
                click.echo(yaml.dump(nat_rules, default_flow_style=False))
            else:
                # Table format
                headers = ['Client', 'Interface', 'Protocol', 'External Port', 'Internal', 'Description']
                rows = []
                for rule in nat_rules:
                    internal_str = f"{rule['internal_ip']}:{rule['internal_port']}"
                    rows.append([
                        rule['client'],
                        rule['interface'],
                        rule['protocol'].upper(),
                        rule['external_port'],
                        internal_str,
                        rule['description'] or 'N/A'
                    ])
                
                click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
                click.echo(f"\nTotal: {len(nat_rules)} NAT rules")
                
    except Exception as e:
        logger.error(f"Failed to manage NAT: {e}")
        click.echo(f"[ERROR] Failed to manage NAT: {e}")
        sys.exit(1)


@network_group.command('firewall')
@click.argument('action', type=click.Choice(['add', 'remove', 'list']))
@click.option('--client', help='Client name')
@click.option('--rule-action', type=click.Choice(['pass', 'block']), default='pass', help='Firewall action')
@click.option('--protocol', type=click.Choice(['tcp', 'udp', 'any']), default='any', help='Protocol')
@click.option('--source', default='any', help='Source address or network')
@click.option('--destination', default='any', help='Destination address or network')
@click.option('--port', help='Destination port or range')
@click.option('--description', help='Rule description')
@click.option('--format', type=click.Choice(['table', 'json', 'yaml']), default='table')
@pass_context
def manage_firewall(ctx, action: str, client: Optional[str], 
                   rule_action: str, protocol: str, source: str, destination: str,
                   port: Optional[str], description: Optional[str], format: str):
    """
    Manage firewall rules.
    
    Examples:
    pfsense-cli network firewall add --client "AcmeCorp" --rule-action pass --protocol tcp --port 80,443
    pfsense-cli network firewall list
    """
    try:
        if action == 'add':
            if not client:
                click.echo("[ERROR] Client name is required")
                sys.exit(1)
            
            with LogContext(logger, client_name=client, operation='add_firewall_rule'):
                
                # Load client config
                client_config = ctx.config_manager.load_client_config(client)
                
                # Create firewall rule
                from ..models.client import FirewallRule
                firewall_rule = FirewallRule(
                    action=rule_action,
                    protocol=protocol,
                    source=source,
                    destination=destination,
                    port=port,
                    description=description or f"{client} firewall rule"
                )
                
                # Add to client config
                client_config.firewall_rules.append(firewall_rule)
                
                # Save configuration
                ctx.config_manager.save_client_config(client_config)
                
                click.echo(f"[OK] Firewall rule added for client '{client}': {rule_action} {protocol} {source} -> {destination}")
                
        elif action == 'remove':
            if not client:
                click.echo("[ERROR] Client name is required")
                sys.exit(1)
            
            with LogContext(logger, client_name=client, operation='remove_firewall_rule'):
                
                # Load client config
                client_config = ctx.config_manager.load_client_config(client)
                
                # Remove all firewall rules for now (could be made more specific)
                original_count = len(client_config.firewall_rules)
                client_config.firewall_rules = []
                
                # Save configuration
                ctx.config_manager.save_client_config(client_config)
                
                click.echo(f"[OK] Removed {original_count} firewall rule(s) for client '{client}'")
                
        elif action == 'list':
            # List firewall rules for all clients or specific client
            if client:
                clients_to_check = [client]
            else:
                clients_to_check = ctx.config_manager.list_client_configs()
            
            firewall_rules = []
            for name in clients_to_check:
                try:
                    client_config = ctx.config_manager.load_client_config(name)
                    for rule in client_config.firewall_rules:
                        firewall_rules.append({
                            'client': name,
                            'action': rule.action,
                            'protocol': rule.protocol,
                            'source': rule.source,
                            'destination': rule.destination,
                            'port': rule.port,
                            'description': rule.description
                        })
                except Exception:
                    continue
            
            if not firewall_rules:
                click.echo("No firewall rules found.")
                return
            
            if format == 'json':
                import json
                click.echo(json.dumps(firewall_rules, indent=2))
            elif format == 'yaml':
                import yaml
                click.echo(yaml.dump(firewall_rules, default_flow_style=False))
            else:
                # Table format
                headers = ['Client', 'Action', 'Protocol', 'Source', 'Destination', 'Port', 'Description']
                rows = []
                for rule in firewall_rules:
                    action_icon = '[OK]' if rule['action'] == 'pass' else '[ERROR]'
                    rows.append([
                        rule['client'],
                        f"{action_icon} {rule['action'].title()}",
                        rule['protocol'].upper(),
                        rule['source'],
                        rule['destination'],
                        rule['port'] or 'any',
                        rule['description'] or 'N/A'
                    ])
                
                click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
                click.echo(f"\nTotal: {len(firewall_rules)} firewall rules")
                
    except Exception as e:
        logger.error(f"Failed to manage firewall: {e}")
        click.echo(f"[ERROR] Failed to manage firewall: {e}")
        sys.exit(1)