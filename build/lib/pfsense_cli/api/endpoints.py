"""
pfSense API endpoint implementations for specific operations.
"""

import logging
from typing import Dict, Any, List, Optional

from .client import PfSenseAPIClient
from .exceptions import (
    ClientNotFoundError, ClientAlreadyExistsError, NetworkConflictError,
    VLANConflictError, ValidationError, CertificateError, VPNConfigError
)
from ..models.client import ClientConfig
from ..models.network import NetworkSettings, NetworkInterface
from ..models.vpn import VPNConfig, OpenVPNServerConfig, VPNClient

logger = logging.getLogger(__name__)


class PfSenseEndpoints:
    """
    High-level API endpoints for pfSense operations.
    Provides abstraction over raw API calls with business logic.
    """
    
    def __init__(self, api_client: PfSenseAPIClient):
        self.client = api_client
    
    # Client Management
    async def get_clients(self) -> List[Dict[str, Any]]:
        """Get list of all configured clients from pfSense interfaces."""
        try:
            # Get all interfaces from pfSense
            interfaces_response = await self.client.get('/interface')
            interfaces = interfaces_response.get('data', [])
            
            # Filter interfaces that appear to be client interfaces (contain CLIENT_ prefix)
            client_interfaces = []
            for interface in interfaces:
                descr = interface.get('descr', '')
                if descr.startswith('CLIENT_'):
                    client_name = descr.replace('CLIENT_', '')
                    client_interfaces.append({
                        'name': client_name,
                        'interface_id': interface.get('if'),
                        'description': descr,
                        'enabled': interface.get('enable', False),
                        'type': interface.get('type'),
                        'ipaddr': interface.get('ipaddr'),
                        'subnet': interface.get('subnet'),
                        'gateway': interface.get('gateway')
                    })
            
            logger.info(f"Found {len(client_interfaces)} client interfaces")
            return client_interfaces
            
        except Exception as e:
            logger.error(f"Failed to get clients from pfSense: {e}")
            # Return empty list instead of raising to allow graceful degradation
            return []
    
    async def get_client(self, client_name: str) -> Dict[str, Any]:
        """Get specific client configuration."""
        clients = await self.get_clients()
        
        for client in clients:
            if client.get('descr', '').replace('CLIENT_', '') == client_name:
                return client
        
        raise ClientNotFoundError(f"Client '{client_name}' not found")
    
    async def create_client(self, client_config: ClientConfig) -> Dict[str, Any]:
        """Create a new client configuration with actual pfSense API calls."""
        try:
            logger.info(f"Creating client '{client_config.name}' on pfSense...")
            
            # Step 1: Check for conflicts
            if client_config.vlan:
                await self._check_vlan_conflict(client_config.vlan.vlan_id)
            if client_config.network:
                await self._check_network_conflict(client_config.network.network)
            
            # Step 2: Create VLAN interface if specified
            vlan_result = None
            if client_config.vlan:
                logger.info(f"Creating VLAN {client_config.vlan.vlan_id} for client '{client_config.name}'")
                vlan_result = await self._create_vlan_interface(client_config)
            
            # Step 3: Create DHCP configuration if specified
            dhcp_result = None
            if client_config.dhcp and client_config.dhcp.enabled:
                logger.info(f"Creating DHCP configuration for client '{client_config.name}'")
                dhcp_result = await self._create_dhcp_config(client_config)
            
            # Step 4: Create firewall rules if specified
            if client_config.firewall_rules:
                logger.info(f"Creating {len(client_config.firewall_rules)} firewall rules for client '{client_config.name}'")
                await self._create_firewall_rules(client_config)
            
            # Step 5: Create NAT rules if specified
            if client_config.nat_rules:
                logger.info(f"Creating {len(client_config.nat_rules)} NAT rules for client '{client_config.name}'")
                await self._create_nat_rules(client_config)
            
            # Step 6: Apply configuration changes
            logger.info("Applying configuration changes to pfSense...")
            await self.client.post('/system/halt/reload_config')
            
            logger.info(f"Successfully created client '{client_config.name}' on pfSense")
            return {
                'name': client_config.name,
                'status': 'active',
                'network': client_config.network.network if client_config.network else None,
                'vlan': client_config.vlan.vlan_id if client_config.vlan else None,
                'vlan_interface': vlan_result.get('if') if vlan_result else None,
                'dhcp_enabled': bool(dhcp_result) if dhcp_result else False,
                'firewall_rules_count': len(client_config.firewall_rules),
                'nat_rules_count': len(client_config.nat_rules),
                'message': f'Client {client_config.name} successfully created on pfSense'
            }
            
        except Exception as e:
            logger.error(f"Failed to create client '{client_config.name}': {e}")
            # Try to cleanup any partial configuration
            try:
                await self._cleanup_partial_client_config(client_config.name)
            except:
                pass  # Cleanup failed, but don't mask the original error
            raise
    
    async def update_client(self, client_name: str, client_config: ClientConfig) -> Dict[str, Any]:
        """Update existing client configuration."""
        try:
            # Verify client exists
            existing_client = await self.get_client(client_name)
            
            # Update interface configuration
            await self._update_interface_config(client_name, client_config)
            
            # Update DHCP if needed
            if client_config.dhcp:
                await self._update_dhcp_config(client_name, client_config)
            
            logger.info(f"Successfully updated client '{client_name}'")
            return await self.get_client(client_name)
            
        except Exception as e:
            logger.error(f"Failed to update client '{client_name}': {e}")
            raise
    
    async def delete_client(self, client_name: str) -> bool:
        """Delete client configuration."""
        try:
            client = await self.get_client(client_name)
            
            # Delete associated configurations
            await self._delete_client_dhcp(client_name)
            await self._delete_client_firewall_rules(client_name)
            await self._delete_client_nat_rules(client_name)
            await self._delete_client_interface(client_name)
            
            logger.info(f"Successfully deleted client '{client_name}'")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete client '{client_name}': {e}")
            raise
    
    # Network Operations
    async def configure_network(self, client_name: str, network_config: NetworkSettings) -> Dict[str, Any]:
        """Configure network settings for a client."""
        try:
            # Find the client interface
            client = await self.get_client(client_name)
            interface_id = client.get('interface_id')
            
            if not interface_id:
                raise ValueError(f"No interface found for client '{client_name}'")
            
            # Update interface configuration
            update_data = {
                'enable': True,
                'descr': f'CLIENT_{client_name}',
                'ipaddr': network_config.gateway if network_config.gateway else 'dhcp',
                'subnet': '24'  # Default subnet mask
            }
            
            result = await self.client.put(f'/interface/{interface_id}', data=update_data)
            
            # Apply configuration
            await self.client.post('/system/halt/reload_config')
            
            logger.info(f"Successfully configured network for client '{client_name}'")
            return result
            
        except Exception as e:
            logger.error(f"Failed to configure network for client '{client_name}': {e}")
            raise
    
    # VPN Management
    async def setup_openvpn_server(self, config: OpenVPNServerConfig) -> Dict[str, Any]:
        """Setup OpenVPN server configuration."""
        try:
            # Create server configuration
            server_data = {
                'mode': 'server_user',
                'protocol': config.protocol,
                'interface': config.interface,
                'local_port': config.port,
                'tunnel_network': config.tunnel_network,
                'tunnel_netmask': config.tunnel_netmask,
                'auth_mode': 'local_user',
                'description': f'OpenVPN Server - {config.name}'
            }
            
            result = await self.client.post('/services/openvpn/server', data=server_data)
            
            logger.info(f"Successfully created OpenVPN server '{config.name}'")
            return result
            
        except Exception as e:
            logger.error(f"Failed to create OpenVPN server '{config.name}': {e}")
            raise VPNConfigError(f"Failed to create OpenVPN server: {e}")
    
    async def create_vpn_client(self, server_name: str, client_config: VPNClient) -> Dict[str, Any]:
        """Create VPN client certificate and configuration."""
        try:
            # Create client certificate
            cert_data = {
                'method': 'existing',
                'common_name': client_config.common_name,
                'description': f'VPN Client - {client_config.name}'
            }
            
            cert_result = await self.client.post('/services/openvpn/client_cert', data=cert_data)
            
            # Generate client configuration file
            config_data = {
                'server': server_name,
                'client_cn': client_config.common_name
            }
            
            config_result = await self.client.post('/services/openvpn/client_export', data=config_data)
            
            logger.info(f"Successfully created VPN client '{client_config.name}'")
            return {
                'certificate': cert_result,
                'configuration': config_result
            }
            
        except Exception as e:
            logger.error(f"Failed to create VPN client '{client_config.name}': {e}")
            raise VPNConfigError(f"Failed to create VPN client: {e}")
    
    async def get_vpn_status(self) -> Dict[str, Any]:
        """Get VPN server status and connected clients."""
        try:
            result = await self.client.get('/services/openvpn/server/status')
            return result
        except Exception as e:
            logger.error(f"Failed to get VPN status: {e}")
            raise
    
    # Helper methods
    async def _check_vlan_conflict(self, vlan_id: int):
        """Check for VLAN ID conflicts."""
        try:
            vlans = await self.client.get('/interface/vlan')
            existing_vlans = vlans.get('data', [])
            
            for vlan in existing_vlans:
                if vlan.get('tag') == vlan_id:
                    raise VLANConflictError(f"VLAN ID {vlan_id} is already in use")
        except Exception as e:
            # If we can't check for conflicts, log but don't fail
            logger.warning(f"Could not check VLAN conflicts: {e}")
            pass
    
    async def _check_network_conflict(self, network_cidr: str):
        """Check for network IP conflicts."""
        try:
            interfaces = await self.client.get('/interface')
            existing_interfaces = interfaces.get('data', [])
            
            from ipaddress import IPv4Network
            new_network = IPv4Network(network_cidr, strict=False)
            
            for iface in existing_interfaces:
                if iface.get('ipaddr') and iface.get('subnet'):
                    existing_cidr = f"{iface['ipaddr']}/{iface['subnet']}"
                    try:
                        existing_network = IPv4Network(existing_cidr, strict=False)
                        if new_network.overlaps(existing_network):
                            raise NetworkConflictError(
                                f"Network {network_cidr} conflicts with existing network {existing_cidr}"
                            )
                    except ValueError:
                        continue
        except Exception as e:
            # If we can't check for conflicts, log but don't fail
            logger.warning(f"Could not check network conflicts: {e}")
            pass
    
    async def _create_vlan_interface(self, client_config: ClientConfig) -> Dict[str, Any]:
        """Create VLAN interface for client."""
        vlan_data = {
            'if': client_config.vlan.interface,
            'tag': client_config.vlan.vlan_id,
            'descr': f"CLIENT_{client_config.name}",
            'enable': True
        }
        
        return await self.client.post('/interface/vlan', data=vlan_data)
    
    async def _create_dhcp_config(self, client_config: ClientConfig) -> Dict[str, Any]:
        """Create DHCP configuration for client."""
        dhcp_data = {
            'interface': f"opt{client_config.vlan.vlan_id}",
            'enable': True,
            'range': {
                'from': client_config.dhcp.start_ip,
                'to': client_config.dhcp.end_ip
            },
            'defaultleasetime': client_config.dhcp.lease_time,
            'maxleasetime': client_config.dhcp.lease_time * 2
        }
        
        if client_config.network.dns_servers:
            dhcp_data['dnsserver'] = client_config.network.dns_servers
        
        return await self.client.post('/services/dhcp', data=dhcp_data)
    
    async def _create_firewall_rules(self, client_config: ClientConfig):
        """Create firewall rules for client."""
        for rule in client_config.firewall_rules:
            rule_data = {
                'type': rule.action,
                'interface': f"opt{client_config.vlan.vlan_id}",
                'protocol': rule.protocol,
                'source': rule.source,
                'destination': rule.destination,
                'descr': rule.description or f"Rule for {client_config.name}"
            }
            
            if rule.port:
                rule_data['destination_port'] = rule.port
            
            await self.client.post('/firewall/rule', data=rule_data)
    
    async def _create_nat_rules(self, client_config: ClientConfig):
        """Create NAT rules for client."""
        for nat_rule in client_config.nat_rules:
            nat_data = {
                'interface': nat_rule.interface,
                'protocol': nat_rule.protocol,
                'source_port': nat_rule.external_port,
                'target': nat_rule.internal_ip,
                'local_port': nat_rule.internal_port,
                'descr': nat_rule.description or f"NAT for {client_config.name}"
            }
            
            await self.client.post('/firewall/nat/port_forward', data=nat_data)
    
    async def _delete_client_interface(self, client_name: str):
        """Delete client interface."""
        client = await self.get_client(client_name)
        if_name = client.get('if')
        if if_name:
            await self.client.delete(f'/interface/{if_name}')
    
    async def _delete_client_dhcp(self, client_name: str):
        """Delete client DHCP configuration."""
        try:
            await self.client.delete(f'/services/dhcp/{client_name}')
        except Exception:
            pass  # DHCP might not exist
    
    async def _delete_client_firewall_rules(self, client_name: str):
        """Delete client firewall rules."""
        rules = await self.client.get('/firewall/rule')
        client_rules = [
            rule for rule in rules.get('data', [])
            if client_name in rule.get('descr', '')
        ]
        
        for rule in client_rules:
            await self.client.delete(f"/firewall/rule/{rule.get('id')}")
    
    async def _delete_client_nat_rules(self, client_name: str):
        """Delete client NAT rules."""
        nat_rules = await self.client.get('/firewall/nat')
        client_nat_rules = [
            rule for rule in nat_rules.get('data', [])
            if client_name in rule.get('descr', '')
        ]
        
        for rule in client_nat_rules:
            await self.client.delete(f"/firewall/nat/port_forward/{rule.get('id')}")
    
    async def _update_interface_config(self, client_name: str, client_config: ClientConfig):
        """Update interface configuration."""
        client = await self.get_client(client_name)
        interface_id = client.get('if')
        
        if interface_id:
            update_data = {
                'descr': f"CLIENT_{client_config.name}",
                'enable': client_config.status == 'active'
            }
            
            await self.client.put(f'/interface/{interface_id}', data=update_data)
    
    async def _update_dhcp_config(self, client_name: str, client_config: ClientConfig):
        """Update DHCP configuration."""
        if client_config.dhcp and client_config.dhcp.enabled:
            dhcp_data = {
                'enable': True,
                'range': {
                    'from': client_config.dhcp.start_ip,
                    'to': client_config.dhcp.end_ip
                },
                'defaultleasetime': client_config.dhcp.lease_time
            }
            
            await self.client.put(f'/services/dhcp/{client_name}', data=dhcp_data)
    
    async def _cleanup_partial_client_config(self, client_name: str):
        """Cleanup partial client configuration in case of errors."""
        try:
            logger.info(f"Cleaning up partial configuration for client '{client_name}'")
            
            # Try to delete any created components
            await self._delete_client_dhcp(client_name)
            await self._delete_client_firewall_rules(client_name) 
            await self._delete_client_nat_rules(client_name)
            await self._delete_client_interface(client_name)
            
            # Apply cleanup changes
            await self.client.post('/system/halt/reload_config')
            
        except Exception as cleanup_error:
            logger.error(f"Failed to cleanup partial config for '{client_name}': {cleanup_error}")