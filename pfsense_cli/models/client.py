"""
Client configuration data models for pfSense automation.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator, IPvAnyAddress
from ipaddress import IPv4Network, AddressValueError
from enum import Enum


class ClientStatus(str, Enum):
    """Client operational status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    ERROR = "error"


class ClientType(str, Enum):
    """Client type definitions."""
    CORPORATE = "corporate"
    BRANCH_OFFICE = "branch_office"
    REMOTE_USER = "remote_user"
    GUEST = "guest"


class NetworkConfig(BaseModel):
    """Network configuration for a client."""
    
    network: str = Field(..., description="Network CIDR (e.g., 192.168.50.0/24)")
    gateway: Optional[str] = Field(None, description="Gateway IP address")
    dns_servers: List[str] = Field(default_factory=list, description="DNS server addresses")
    domain_name: Optional[str] = Field(None, description="Domain name for the network")
    
    @validator('network')
    def validate_network(cls, v):
        try:
            IPv4Network(v, strict=False)
            return v
        except AddressValueError:
            raise ValueError(f"Invalid network CIDR format: {v}")
    
    @validator('gateway')
    def validate_gateway(cls, v):
        if v is None:
            return v
        try:
            IPvAnyAddress(v)
            return v
        except Exception:
            raise ValueError(f"Invalid gateway IP address: {v}")
    
    @validator('dns_servers')
    def validate_dns_servers(cls, v):
        for dns in v:
            try:
                IPvAnyAddress(dns)
            except Exception:
                raise ValueError(f"Invalid DNS server IP address: {dns}")
        return v


class VLANConfig(BaseModel):
    """VLAN configuration for a client."""
    
    vlan_id: int = Field(..., ge=1, le=4094, description="VLAN ID (1-4094)")
    description: Optional[str] = Field(None, description="VLAN description")
    interface: str = Field(default="em0", description="Parent interface")
    
    @validator('vlan_id')
    def validate_vlan_id(cls, v):
        if not 1 <= v <= 4094:
            raise ValueError("VLAN ID must be between 1 and 4094")
        return v


class DHCPConfig(BaseModel):
    """DHCP configuration for a client."""
    
    enabled: bool = Field(default=True, description="Enable DHCP server")
    start_ip: Optional[str] = Field(None, description="DHCP range start IP")
    end_ip: Optional[str] = Field(None, description="DHCP range end IP")
    lease_time: int = Field(default=7200, description="DHCP lease time in seconds")
    static_mappings: List[Dict[str, str]] = Field(default_factory=list, description="Static DHCP mappings")
    
    @validator('start_ip', 'end_ip')
    def validate_ip_addresses(cls, v):
        if v is None:
            return v
        try:
            IPvAnyAddress(v)
            return v
        except Exception:
            raise ValueError(f"Invalid IP address: {v}")


class FirewallRule(BaseModel):
    """Firewall rule configuration."""
    
    action: str = Field(..., description="Rule action (pass, block)")
    protocol: str = Field(default="any", description="Protocol (tcp, udp, any)")
    source: str = Field(default="any", description="Source address or network")
    destination: str = Field(default="any", description="Destination address or network")
    port: Optional[str] = Field(None, description="Destination port or range")
    description: Optional[str] = Field(None, description="Rule description")
    
    @validator('action')
    def validate_action(cls, v):
        if v.lower() not in ['pass', 'block', 'reject']:
            raise ValueError("Action must be 'pass', 'block', or 'reject'")
        return v.lower()


class NATRule(BaseModel):
    """NAT rule configuration."""
    
    interface: str = Field(..., description="Interface for NAT rule")
    protocol: str = Field(default="tcp", description="Protocol (tcp, udp)")
    external_port: int = Field(..., description="External port")
    internal_ip: str = Field(..., description="Internal IP address")
    internal_port: int = Field(..., description="Internal port")
    description: Optional[str] = Field(None, description="NAT rule description")
    
    @validator('internal_ip')
    def validate_internal_ip(cls, v):
        try:
            IPvAnyAddress(v)
            return v
        except Exception:
            raise ValueError(f"Invalid internal IP address: {v}")


class ClientConfig(BaseModel):
    """Complete client configuration model."""
    
    name: str = Field(..., description="Client name (must be unique)")
    client_type: ClientType = Field(default=ClientType.CORPORATE, description="Client type")
    status: ClientStatus = Field(default=ClientStatus.PENDING, description="Client status")
    
    # Network configuration
    network: NetworkConfig = Field(..., description="Network configuration")
    vlan: Optional[VLANConfig] = Field(None, description="VLAN configuration")
    dhcp: Optional[DHCPConfig] = Field(None, description="DHCP configuration")
    
    # Security rules
    firewall_rules: List[FirewallRule] = Field(default_factory=list, description="Firewall rules")
    nat_rules: List[NATRule] = Field(default_factory=list, description="NAT rules")
    
    # VPN configuration
    vpn_enabled: bool = Field(default=False, description="Enable VPN for this client")
    vpn_port: Optional[int] = Field(None, description="VPN port assignment")
    
    # Metadata
    created_at: Optional[str] = Field(None, description="Creation timestamp")
    updated_at: Optional[str] = Field(None, description="Last update timestamp")
    tags: List[str] = Field(default_factory=list, description="Client tags")
    notes: Optional[str] = Field(None, description="Additional notes")
    
    @validator('name')
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError("Client name cannot be empty")
        if len(v) > 64:
            raise ValueError("Client name must be 64 characters or less")
        # Allow alphanumeric, spaces, hyphens, underscores
        import re
        if not re.match(r'^[a-zA-Z0-9\s_-]+$', v):
            raise ValueError("Client name contains invalid characters")
        return v.strip()
    
    @validator('vpn_port')
    def validate_vpn_port(cls, v):
        if v is None:
            return v
        if not 1024 <= v <= 65535:
            raise ValueError("VPN port must be between 1024 and 65535")
        return v
    
    class Config:
        use_enum_values = True
        validate_assignment = True