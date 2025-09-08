"""
Network-related data models for pfSense automation.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator, IPvAnyAddress
from ipaddress import IPv4Network, IPv4Address, AddressValueError
from enum import Enum


class InterfaceType(str, Enum):
    """Network interface types."""
    PHYSICAL = "physical"
    VLAN = "vlan"
    BRIDGE = "bridge"
    VPN = "vpn"


class InterfaceStatus(str, Enum):
    """Interface operational status."""
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class NetworkInterface(BaseModel):
    """Network interface configuration."""
    
    name: str = Field(..., description="Interface name")
    description: Optional[str] = Field(None, description="Interface description")
    interface_type: InterfaceType = Field(..., description="Interface type")
    status: InterfaceStatus = Field(default=InterfaceStatus.UNKNOWN, description="Interface status")
    
    # IP configuration
    ip_address: Optional[str] = Field(None, description="Interface IP address")
    subnet_mask: Optional[str] = Field(None, description="Subnet mask")
    gateway: Optional[str] = Field(None, description="Gateway IP address")
    
    # Physical interface settings
    mac_address: Optional[str] = Field(None, description="MAC address")
    mtu: int = Field(default=1500, description="Maximum transmission unit")
    
    # VLAN settings (if applicable)
    vlan_id: Optional[int] = Field(None, description="VLAN ID for VLAN interfaces")
    parent_interface: Optional[str] = Field(None, description="Parent interface for VLANs")
    
    @field_validator('ip_address', 'gateway')
    @classmethod
    def validate_ip_addresses(cls, v):
        if v is None:
            return v
        try:
            IPvAnyAddress(v)
            return v
        except Exception:
            raise ValueError(f"Invalid IP address: {v}")
    
    @field_validator('vlan_id')
    @classmethod
    def validate_vlan_id(cls, v):
        if v is None:
            return v
        if not 1 <= v <= 4094:
            raise ValueError("VLAN ID must be between 1 and 4094")
        return v
    
    @field_validator('mtu')
    @classmethod
    def validate_mtu(cls, v):
        if not 68 <= v <= 9000:
            raise ValueError("MTU must be between 68 and 9000")
        return v


class RouteConfig(BaseModel):
    """Static route configuration."""
    
    destination: str = Field(..., description="Destination network (CIDR format)")
    gateway: str = Field(..., description="Gateway IP address")
    interface: Optional[str] = Field(None, description="Output interface")
    metric: int = Field(default=1, description="Route metric")
    description: Optional[str] = Field(None, description="Route description")
    
    @field_validator('destination')
    @classmethod
    def validate_destination(cls, v):
        try:
            IPv4Network(v, strict=False)
            return v
        except AddressValueError:
            raise ValueError(f"Invalid destination network: {v}")
    
    @field_validator('gateway')
    @classmethod
    def validate_gateway(cls, v):
        try:
            IPvAnyAddress(v)
            return v
        except Exception:
            raise ValueError(f"Invalid gateway IP address: {v}")


class DNSConfig(BaseModel):
    """DNS configuration."""
    
    enabled: bool = Field(default=True, description="Enable DNS resolver")
    dns_servers: List[str] = Field(default_factory=list, description="DNS server addresses")
    domain_name: Optional[str] = Field(None, description="Default domain name")
    search_domains: List[str] = Field(default_factory=list, description="DNS search domains")
    
    # DNS forwarding
    forwarding_enabled: bool = Field(default=False, description="Enable DNS forwarding")
    forwarders: List[str] = Field(default_factory=list, description="DNS forwarder addresses")
    
    @field_validator('dns_servers', 'forwarders')
    @classmethod
    def validate_dns_addresses(cls, v):
        for dns in v:
            try:
                IPvAnyAddress(dns)
            except Exception:
                raise ValueError(f"Invalid DNS server IP address: {dns}")
        return v


class DHCPPool(BaseModel):
    """DHCP pool configuration."""
    
    interface: str = Field(..., description="Interface for DHCP pool")
    enabled: bool = Field(default=True, description="Enable DHCP pool")
    
    # Range configuration
    start_ip: str = Field(..., description="DHCP range start IP")
    end_ip: str = Field(..., description="DHCP range end IP")
    subnet_mask: str = Field(..., description="Subnet mask")
    
    # DHCP options
    lease_time: int = Field(default=7200, description="Lease time in seconds")
    gateway: Optional[str] = Field(None, description="Default gateway")
    dns_servers: List[str] = Field(default_factory=list, description="DNS servers")
    domain_name: Optional[str] = Field(None, description="Domain name")
    ntp_servers: List[str] = Field(default_factory=list, description="NTP servers")
    
    # Advanced options
    failover_peer: Optional[str] = Field(None, description="DHCP failover peer")
    ignore_client_uids: bool = Field(default=False, description="Ignore client UIDs")
    
    @field_validator('start_ip', 'end_ip', 'subnet_mask', 'gateway')
    @classmethod
    def validate_ip_addresses(cls, v):
        if v is None:
            return v
        try:
            IPvAnyAddress(v)
            return v
        except Exception:
            raise ValueError(f"Invalid IP address: {v}")
    
    @field_validator('dns_servers', 'ntp_servers')
    @classmethod
    def validate_server_addresses(cls, v):
        for server in v:
            try:
                IPvAnyAddress(server)
            except Exception:
                raise ValueError(f"Invalid server IP address: {server}")
        return v


class DHCPReservation(BaseModel):
    """DHCP static mapping/reservation."""
    
    mac_address: str = Field(..., description="Client MAC address")
    ip_address: str = Field(..., description="Reserved IP address")
    hostname: Optional[str] = Field(None, description="Client hostname")
    description: Optional[str] = Field(None, description="Reservation description")
    
    @field_validator('mac_address')
    @classmethod
    def validate_mac_address(cls, v):
        import re
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', v):
            raise ValueError(f"Invalid MAC address format: {v}")
        return v.lower().replace('-', ':')
    
    @field_validator('ip_address')
    @classmethod
    def validate_ip_address(cls, v):
        try:
            IPvAnyAddress(v)
            return v
        except Exception:
            raise ValueError(f"Invalid IP address: {v}")


class NetworkSettings(BaseModel):
    """Complete network settings configuration."""
    
    # Basic settings
    hostname: str = Field(..., description="System hostname")
    domain: Optional[str] = Field(None, description="System domain")
    
    # Interface configuration
    interfaces: List[NetworkInterface] = Field(default_factory=list, description="Network interfaces")
    routes: List[RouteConfig] = Field(default_factory=list, description="Static routes")
    
    # DNS configuration
    dns: DNSConfig = Field(default_factory=DNSConfig, description="DNS configuration")
    
    # DHCP configuration
    dhcp_pools: List[DHCPPool] = Field(default_factory=list, description="DHCP pools")
    dhcp_reservations: List[DHCPReservation] = Field(default_factory=list, description="DHCP reservations")
    
    # Network services
    ssh_enabled: bool = Field(default=True, description="Enable SSH service")
    ssh_port: int = Field(default=22, description="SSH port")
    web_gui_port: int = Field(default=443, description="Web GUI port")
    web_gui_protocol: str = Field(default="https", description="Web GUI protocol")
    
    @field_validator('hostname')
    @classmethod
    def validate_hostname(cls, v):
        import re
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$', v):
            raise ValueError("Invalid hostname format")
        return v
    
    @field_validator('ssh_port', 'web_gui_port')
    @classmethod
    def validate_ports(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v
    
    @field_validator('web_gui_protocol')
    @classmethod
    def validate_protocol(cls, v):
        if v.lower() not in ['http', 'https']:
            raise ValueError("Protocol must be 'http' or 'https'")
        return v.lower()
    
    class Config:
        use_enum_values = True
        validate_assignment = True