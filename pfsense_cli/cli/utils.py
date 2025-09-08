"""
Shared utilities for CLI commands.
"""

import sys
import click
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .main import PfSenseContext

from ..api.client import PfSenseAPIClient
from ..api.endpoints import PfSenseEndpoints


def get_api_client(ctx: 'PfSenseContext') -> PfSenseAPIClient:
    """Get configured API client."""
    if ctx.api_client:
        return ctx.api_client
    
    # Get connection settings
    base_url = ctx.config_manager.get_setting('pfsense.base_url')
    username = ctx.config_manager.get_setting('pfsense.username')
    password = ctx.config_manager.get_setting('pfsense.password')
    verify_ssl = ctx.config_manager.get_setting('pfsense.verify_ssl', False)
    timeout = ctx.config_manager.get_setting('pfsense.timeout', 30)
    
    if not all([base_url, username, password]):
        click.echo("[ERROR] pfSense connection not configured. Run 'pfsense-cli setup' first.")
        sys.exit(1)
    
    ctx.api_client = PfSenseAPIClient(
        base_url=base_url,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        timeout=timeout
    )
    
    return ctx.api_client


def get_endpoints(ctx: 'PfSenseContext') -> PfSenseEndpoints:
    """Get API endpoints wrapper."""
    if ctx.endpoints:
        return ctx.endpoints
    
    api_client = get_api_client(ctx)
    ctx.endpoints = PfSenseEndpoints(api_client)
    return ctx.endpoints