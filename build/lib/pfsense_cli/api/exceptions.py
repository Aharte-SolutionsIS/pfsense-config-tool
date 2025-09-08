"""
Custom exceptions for pfSense API operations.
"""


class PfSenseAPIError(Exception):
    """Base exception for pfSense API operations."""
    
    def __init__(self, message: str, status_code: int = None, response_data: dict = None):
        self.message = message
        self.status_code = status_code
        self.response_data = response_data or {}
        super().__init__(self.message)


class AuthenticationError(PfSenseAPIError):
    """Authentication failed with pfSense API."""
    pass


class AuthorizationError(PfSenseAPIError):
    """Insufficient permissions for pfSense API operation."""
    pass


class ConnectionError(PfSenseAPIError):
    """Failed to connect to pfSense API."""
    pass


class TimeoutError(PfSenseAPIError):
    """API request timed out."""
    pass


class ValidationError(PfSenseAPIError):
    """Request validation failed."""
    pass


class ConfigurationError(PfSenseAPIError):
    """Configuration-related error."""
    pass


class ClientNotFoundError(PfSenseAPIError):
    """Client configuration not found."""
    pass


class ClientAlreadyExistsError(PfSenseAPIError):
    """Client configuration already exists."""
    pass


class NetworkConflictError(PfSenseAPIError):
    """Network configuration conflict detected."""
    pass


class VLANConflictError(PfSenseAPIError):
    """VLAN ID conflict detected."""
    pass


class CertificateError(PfSenseAPIError):
    """Certificate-related error."""
    pass


class VPNConfigError(PfSenseAPIError):
    """VPN configuration error."""
    pass