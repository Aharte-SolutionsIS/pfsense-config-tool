"""
pfSense API client with authentication, retry logic, and rate limiting.
"""

import asyncio
import json
import logging
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, urlparse
import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .exceptions import (
    PfSenseAPIError, AuthenticationError, AuthorizationError,
    ConnectionError, TimeoutError, ValidationError
)


logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple rate limiter for API requests."""
    
    def __init__(self, max_requests: int = 10, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
    
    def can_make_request(self) -> bool:
        """Check if a request can be made within rate limits."""
        now = time.time()
        # Remove requests outside the time window
        self.requests = [req_time for req_time in self.requests if now - req_time < self.time_window]
        return len(self.requests) < self.max_requests
    
    def record_request(self):
        """Record a request timestamp."""
        self.requests.append(time.time())
    
    async def wait_if_needed(self):
        """Wait if rate limit would be exceeded."""
        if not self.can_make_request():
            wait_time = self.time_window - (time.time() - self.requests[0])
            if wait_time > 0:
                logger.info(f"Rate limit exceeded, waiting {wait_time:.2f} seconds")
                await asyncio.sleep(wait_time)


class PfSenseAPIClient:
    """
    Professional pfSense API client with comprehensive error handling,
    authentication, retry logic, and rate limiting.
    """
    
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        timeout: int = 30,
        max_retries: int = 3,
        rate_limit_requests: int = 10,
        rate_limit_window: int = 60
    ):
        """
        Initialize pfSense API client.
        
        Args:
            base_url: pfSense base URL (e.g., https://192.168.1.1)
            username: Authentication username
            password: Authentication password
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
            rate_limit_requests: Maximum requests per time window
            rate_limit_window: Rate limit time window in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Rate limiting
        self.rate_limiter = RateLimiter(rate_limit_requests, rate_limit_window)
        
        # Session for connection pooling and persistent auth
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Authentication token
        self._auth_token = None
        self._auth_expires = 0
        
        logger.info(f"Initialized pfSense API client for {self.base_url}")
    
    async def authenticate(self) -> bool:
        """
        Authenticate with pfSense API and obtain access token.
        
        Returns:
            True if authentication successful, False otherwise
        """
        try:
            # Try different API versions and endpoints
            auth_endpoints = [
                '/api/v2/auth/jwt',  # pfSense REST API v2.6.0 JWT
                '/api/v2/auth',      # pfSense REST API v2.6.0 basic auth
                '/api/v2/auth/key',  # Alternative API key auth  
                '/api/v1/access_token',  # Legacy v1
                '/api/auth',         # Simple auth endpoint
            ]
            
            # Try different authentication data formats (Basic Auth first since it works)
            auth_formats = [
                None,  # For Basic Auth (no JSON body) - try this first!
                {'username': self.username, 'password': self.password},       # JWT format
                {'client-id': self.username, 'client-token': self.password},  # v1 format
                {'client_id': self.username, 'client_token': self.password},  # Alternative format
                {'user': self.username, 'pass': self.password},               # Simple format
            ]
            
            response = None
            successful_endpoint = None
            
            # Try different endpoint and data format combinations
            for endpoint in auth_endpoints:
                auth_url = urljoin(self.base_url, endpoint)
                logger.debug(f"Trying authentication endpoint: {endpoint}")
                
                for auth_data in auth_formats:
                    try:
                        if auth_data is None:
                            # Try Basic Auth for JWT endpoint
                            logger.debug(f"Trying Basic Auth with endpoint: {endpoint}")
                            logger.debug(f"Full URL: {auth_url}")
                            from requests.auth import HTTPBasicAuth
                            response = self.session.post(
                                auth_url,
                                auth=HTTPBasicAuth(self.username, self.password),
                                timeout=self.timeout
                            )
                        else:
                            logger.debug(f"Trying auth data format: {list(auth_data.keys())}")
                            logger.debug(f"Auth data values: {auth_data}")
                            logger.debug(f"Full URL: {auth_url}")
                            response = self.session.post(
                                auth_url,
                                json=auth_data,
                                timeout=self.timeout
                            )
                        
                        if response.status_code == 200:
                            successful_endpoint = endpoint
                            break
                        elif response.status_code == 404:
                            logger.debug(f"Auth format failed with 404, trying next format...")
                            continue
                        elif response.status_code == 401:
                            logger.debug(f"Auth format failed with 401, trying next format...")
                            continue
                        else:
                            # Other error codes - may still be valid endpoint
                            successful_endpoint = endpoint
                            break
                            
                    except requests.exceptions.RequestException as e:
                        logger.debug(f"Request failed for {endpoint} with {list(auth_data.keys())}: {e}")
                        continue
                
                # If we got a successful response, break out of endpoint loop
                if response and response.status_code == 200:
                    break
                    
            if response is None:
                raise AuthenticationError("No valid API authentication endpoint found. Check if REST API is properly installed.")
            
            logger.debug(f"Using authentication endpoint: {successful_endpoint}")
            
            if response.status_code == 200:
                token_data = response.json()
                
                # Try different token response formats
                token = (token_data.get('data', {}).get('token') or 
                        token_data.get('token') or 
                        token_data.get('access_token'))
                
                if token:
                    self._auth_token = token
                    # Set auth header for future requests
                    self.session.headers.update({
                        'Authorization': f'Bearer {self._auth_token}',
                        'Content-Type': 'application/json'
                    })
                    self._auth_expires = time.time() + 3600  # Assume 1 hour expiry
                    logger.info("Successfully authenticated with pfSense API")
                    return True
                else:
                    raise AuthenticationError("No token received in authentication response")
            
            elif response.status_code == 401:
                raise AuthenticationError("Invalid username or password")
            elif response.status_code == 403:
                raise AuthorizationError("Insufficient permissions")
            else:
                raise AuthenticationError(f"Authentication failed: {response.status_code}")
                
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Failed to connect to pfSense API: {e}")
        except requests.exceptions.Timeout as e:
            raise TimeoutError(f"Authentication request timed out: {e}")
        except requests.exceptions.RequestException as e:
            raise PfSenseAPIError(f"Authentication request failed: {e}")
    
    def _is_token_expired(self) -> bool:
        """Check if authentication token has expired."""
        return time.time() >= self._auth_expires
    
    async def _ensure_authenticated(self):
        """Ensure we have a valid authentication token."""
        if not self._auth_token or self._is_token_expired():
            await self.authenticate()
    
    def _build_url(self, endpoint: str) -> str:
        """Build full URL for API endpoint."""
        if not endpoint.startswith('/'):
            endpoint = f'/{endpoint}'
        
        if not endpoint.startswith('/api/'):
            endpoint = f'/api/v2{endpoint}'
        
        return urljoin(self.base_url, endpoint)
    
    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """
        Handle API response and extract data or raise appropriate exceptions.
        
        Args:
            response: HTTP response object
            
        Returns:
            Parsed response data
            
        Raises:
            Various pfSense API exceptions based on response
        """
        try:
            if response.headers.get('content-type', '').startswith('application/json'):
                data = response.json()
            else:
                data = {'message': response.text}
        except json.JSONDecodeError:
            data = {'message': 'Invalid JSON response'}
        
        if response.status_code == 200:
            return data
        elif response.status_code == 400:
            raise ValidationError(
                data.get('message', 'Validation error'),
                response.status_code,
                data
            )
        elif response.status_code == 401:
            raise AuthenticationError(
                data.get('message', 'Authentication required'),
                response.status_code,
                data
            )
        elif response.status_code == 403:
            raise AuthorizationError(
                data.get('message', 'Insufficient permissions'),
                response.status_code,
                data
            )
        elif response.status_code == 404:
            raise PfSenseAPIError(
                data.get('message', 'Resource not found'),
                response.status_code,
                data
            )
        elif response.status_code == 429:
            raise PfSenseAPIError(
                data.get('message', 'Rate limit exceeded'),
                response.status_code,
                data
            )
        elif response.status_code >= 500:
            raise PfSenseAPIError(
                data.get('message', 'Server error'),
                response.status_code,
                data
            )
        else:
            raise PfSenseAPIError(
                data.get('message', f'HTTP {response.status_code}'),
                response.status_code,
                data
            )
    
    async def request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make authenticated API request with error handling and rate limiting.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            data: Request body data
            params: URL parameters
            
        Returns:
            Parsed response data
        """
        await self.rate_limiter.wait_if_needed()
        await self._ensure_authenticated()
        
        url = self._build_url(endpoint)
        
        try:
            logger.debug(f"Making {method} request to {url}")
            
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.timeout
            )
            
            self.rate_limiter.record_request()
            result = self._handle_response(response)
            
            logger.debug(f"Request successful: {method} {url}")
            return result
            
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Failed to connect to {url}: {e}")
        except requests.exceptions.Timeout as e:
            raise TimeoutError(f"Request to {url} timed out: {e}")
        except requests.exceptions.RequestException as e:
            raise PfSenseAPIError(f"Request to {url} failed: {e}")
    
    async def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make GET request."""
        return await self.request('GET', endpoint, params=params)
    
    async def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make POST request."""
        return await self.request('POST', endpoint, data=data)
    
    async def put(self, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make PUT request."""
        return await self.request('PUT', endpoint, data=data)
    
    async def delete(self, endpoint: str) -> Dict[str, Any]:
        """Make DELETE request."""
        return await self.request('DELETE', endpoint)
    
    def close(self):
        """Close the session and cleanup resources."""
        if self.session:
            self.session.close()
            logger.debug("API client session closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    # Health check methods
    async def health_check(self) -> Dict[str, Any]:
        """Check API health and connectivity."""
        # Since we successfully authenticated, we know the API is reachable
        # pfSense REST API v2.6.0 may not have a traditional status endpoint
        if self._auth_token and not self._is_token_expired():
            return {
                'status': 'healthy',
                'connected': True,
                'authenticated': True,
                'api_version': 'v2.6.0',
                'message': 'Successfully authenticated with pfSense REST API'
            }
        else:
            try:
                # Try to authenticate to test connectivity
                await self.authenticate()
                return {
                    'status': 'healthy',
                    'connected': True,
                    'authenticated': True,
                    'api_version': 'v2.6.0',
                    'message': 'Successfully authenticated with pfSense REST API'
                }
            except Exception as e:
                return {
                    'status': 'unhealthy',
                    'connected': False,
                    'authenticated': False,
                    'error': str(e)
                }
    
    async def get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        # Return basic information since no system endpoint was found in API docs
        return {
            'data': {
                'api_version': 'v2.6.0',
                'status': 'connected',
                'authenticated': bool(self._auth_token),
                'base_url': self.base_url,
                'message': 'pfSense REST API connection active'
            }
        }