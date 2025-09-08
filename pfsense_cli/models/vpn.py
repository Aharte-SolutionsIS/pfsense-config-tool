"""
VPN-related data models for pfSense automation.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator, IPvAnyAddress
from ipaddress import IPv4Network, AddressValueError
from enum import Enum


class VPNType(str, Enum):
    """VPN server types."""
    OPENVPN = "openvpn"
    IPSEC = "ipsec"
    WIREGUARD = "wireguard"


class VPNProtocol(str, Enum):
    """VPN protocols."""
    UDP = "udp"
    TCP = "tcp"


class VPNAuthMode(str, Enum):
    """VPN authentication modes."""
    LOCAL_USER = "local_user"
    LDAP = "ldap"
    RADIUS = "radius"
    PKI = "pki"


class VPNClientStatus(str, Enum):
    """VPN client connection status."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class CertificateConfig(BaseModel):
    """Certificate configuration for VPN."""
    
    name: str = Field(..., description="Certificate name")
    common_name: str = Field(..., description="Certificate common name")
    country: str = Field(default="US", description="Country code")
    state: str = Field(default="", description="State or province")
    city: str = Field(default="", description="City")
    organization: str = Field(default="", description="Organization")
    organizational_unit: str = Field(default="", description="Organizational unit")
    email: Optional[str] = Field(None, description="Email address")
    
    # Certificate settings
    key_length: int = Field(default=2048, description="Key length in bits")
    digest_algorithm: str = Field(default="sha256", description="Digest algorithm")
    lifetime: int = Field(default=3650, description="Certificate lifetime in days")
    
    @field_validator('key_length')
    @classmethod
    def validate_key_length(cls, v):
        if v not in [1024, 2048, 4096]:
            raise ValueError("Key length must be 1024, 2048, or 4096")
        return v
    
    @field_validator('country')
    @classmethod
    def validate_country(cls, v):
        if len(v) != 2:
            raise ValueError("Country must be a 2-character code")
        return v.upper()


class OpenVPNServerConfig(BaseModel):
    """OpenVPN server configuration."""
    
    name: str = Field(..., description="Server configuration name")
    enabled: bool = Field(default=True, description="Enable VPN server")
    
    # Network settings
    interface: str = Field(default="wan", description="Server interface")
    protocol: VPNProtocol = Field(default=VPNProtocol.UDP, description="VPN protocol")
    port: int = Field(default=1194, description="VPN port")
    
    # Tunnel settings
    tunnel_network: str = Field(..., description="VPN tunnel network (CIDR)")
    tunnel_netmask: str = Field(default="255.255.255.0", description="VPN tunnel netmask")
    local_network: Optional[str] = Field(None, description="Local network to push to clients")
    
    # Encryption settings
    encryption_algorithm: str = Field(default="AES-256-CBC", description="Encryption algorithm")
    auth_digest_algorithm: str = Field(default="SHA256", description="Auth digest algorithm")
    hardware_crypto: bool = Field(default=False, description="Use hardware crypto")
    
    # Certificate settings
    ca_certificate: str = Field(..., description="CA certificate name")
    server_certificate: str = Field(..., description="Server certificate name")
    dh_parameters: Optional[str] = Field(None, description="DH parameters")
    tls_auth_key: Optional[str] = Field(None, description="TLS auth key")
    
    # Client settings
    max_clients: int = Field(default=100, description="Maximum concurrent clients")
    compression: bool = Field(default=False, description="Enable compression")
    push_routes: List[str] = Field(default_factory=list, description="Routes to push to clients")
    dns_servers: List[str] = Field(default_factory=list, description="DNS servers to push")
    
    # Advanced settings
    client_to_client: bool = Field(default=False, description="Allow client-to-client communication")
    duplicate_cn: bool = Field(default=False, description="Allow duplicate common names")
    ping_interval: int = Field(default=10, description="Ping interval in seconds")
    ping_timeout: int = Field(default=60, description="Ping timeout in seconds")
    
    @field_validator('tunnel_network')
    @classmethod
    def validate_tunnel_network(cls, v):
        try:
            IPv4Network(v, strict=False)
            return v
        except AddressValueError:
            raise ValueError(f"Invalid tunnel network: {v}")
    
    @field_validator('port')
    @classmethod
    def validate_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v
    
    @field_validator('dns_servers')
    @classmethod
    def validate_dns_servers(cls, v):
        for dns in v:
            try:
                IPvAnyAddress(dns)
            except Exception:
                raise ValueError(f"Invalid DNS server IP: {dns}")
        return v


class VPNClient(BaseModel):
    """VPN client configuration."""
    
    name: str = Field(..., description="Client name")
    common_name: str = Field(..., description="Client certificate common name")
    enabled: bool = Field(default=True, description="Client enabled")
    status: VPNClientStatus = Field(default=VPNClientStatus.DISCONNECTED, description="Client status")
    
    # Client details
    email: Optional[str] = Field(None, description="Client email address")
    description: Optional[str] = Field(None, description="Client description")
    
    # Certificate information
    certificate_name: str = Field(..., description="Client certificate name")
    certificate_issued: Optional[str] = Field(None, description="Certificate issue date")
    certificate_expires: Optional[str] = Field(None, description="Certificate expiry date")
    
    # Connection details
    assigned_ip: Optional[str] = Field(None, description="Assigned IP address")
    last_connected: Optional[str] = Field(None, description="Last connection timestamp")
    bytes_sent: int = Field(default=0, description="Bytes sent")
    bytes_received: int = Field(default=0, description="Bytes received")
    
    # Client-specific overrides
    push_routes: List[str] = Field(default_factory=list, description="Client-specific routes")
    redirect_gateway: bool = Field(default=True, description="Redirect default gateway")
    
    @field_validator('assigned_ip')
    @classmethod
    def validate_assigned_ip(cls, v):
        if v is None:
            return v
        try:
            IPvAnyAddress(v)
            return v
        except Exception:
            raise ValueError(f"Invalid assigned IP: {v}")


class VPNServerStatus(BaseModel):
    """VPN server operational status."""
    
    server_name: str = Field(..., description="Server configuration name")
    status: str = Field(..., description="Server status")
    uptime: Optional[str] = Field(None, description="Server uptime")
    
    # Connection statistics
    connected_clients: int = Field(default=0, description="Number of connected clients")
    max_clients: int = Field(default=100, description="Maximum clients allowed")
    total_connections: int = Field(default=0, description="Total connections since startup")
    
    # Traffic statistics
    bytes_sent: int = Field(default=0, description="Total bytes sent")
    bytes_received: int = Field(default=0, description="Total bytes received")
    
    # Active clients
    active_clients: List[Dict[str, Any]] = Field(default_factory=list, description="Currently connected clients")


class VPNConfig(BaseModel):
    """Complete VPN configuration."""
    
    # Server configurations
    openvpn_servers: List[OpenVPNServerConfig] = Field(default_factory=list, description="OpenVPN servers")
    
    # Certificate authority
    certificate_authority: Optional[CertificateConfig] = Field(None, description="Certificate authority config")
    server_certificates: List[CertificateConfig] = Field(default_factory=list, description="Server certificates")
    
    # Client management
    vpn_clients: List[VPNClient] = Field(default_factory=list, description="VPN clients")
    
    # Global settings
    enable_log: bool = Field(default=True, description="Enable VPN logging")
    log_verbosity: int = Field(default=3, description="Log verbosity level (0-11)")
    
    class Config:
        use_enum_values = True
        validate_assignment = True