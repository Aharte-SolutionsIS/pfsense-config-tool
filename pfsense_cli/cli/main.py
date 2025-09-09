"""
Main CLI entry point for pfSense configuration tool.
"""

import asyncio
import sys
from pathlib import Path
import click
from typing import Optional

from ..utils.logging import setup_logging, get_logger
from ..config.manager import ConfigManager
from ..api.client import PfSenseAPIClient
from ..api.endpoints import PfSenseEndpoints
from ..api.exceptions import PfSenseAPIError

# We'll import command groups after defining the context to avoid circular imports

logger = get_logger(__name__)


class PfSenseContext:
    """Context object to pass between CLI commands."""
    
    def __init__(self):
        self.config_manager = None
        self.api_client = None
        self.endpoints = None
        self.verbose = False


pass_context = click.pass_obj


@click.group()
@click.option('--config-dir', type=click.Path(), help='Configuration directory path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--quiet', '-q', is_flag=True, help='Suppress output except errors')
@click.option('--log-file', type=click.Path(), help='Log to file')
@click.version_option(version='1.0.0', prog_name='pfsense-cli')
@click.pass_context
def cli(ctx: click.Context, config_dir: Optional[str], verbose: bool, quiet: bool, log_file: Optional[str]):
    """
    pfSense Configuration Management CLI Tool
    
    A professional automation tool for managing pfSense configurations
    including client management, network operations, and VPN setup.
    """
    # Determine log level
    if quiet:
        log_level = 'ERROR'
    elif verbose:
        log_level = 'DEBUG'
    else:
        log_level = 'INFO'
    
    # Setup logging
    setup_logging(
        level=log_level,
        log_file=log_file,
        console_output=not quiet
    )
    
    # Initialize context
    pfsense_ctx = PfSenseContext()
    pfsense_ctx.verbose = verbose
    ctx.obj = pfsense_ctx
    
    try:
        # Initialize configuration manager
        pfsense_ctx.config_manager = ConfigManager(config_dir)
        logger.info("pfSense CLI initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize pfSense CLI: {e}")
        sys.exit(1)


@cli.command()
@pass_context
def setup(ctx):
    """Initial setup and configuration wizard."""
    click.echo("pfSense CLI Setup Wizard")
    click.echo("=" * 25)
    
    # Get pfSense connection details
    base_url = click.prompt("pfSense base URL", default="https://192.168.1.1")
    username = click.prompt("pfSense username", default="admin")
    password = click.prompt("pfSense password", hide_input=True)
    
    verify_ssl = click.confirm("Verify SSL certificates?", default=False)
    
    # Save settings
    settings = {
        'pfsense': {
            'base_url': base_url,
            'username': username,
            'password': password,
            'verify_ssl': verify_ssl
        }
    }
    
    ctx.config_manager.save_settings(settings)
    
    click.echo("\n[OK] Configuration saved successfully!")
    click.echo(f"Config directory: {ctx.config_manager.config_dir}")
    
    # Test connection
    if click.confirm("Test connection now?", default=True):
        try:
            api_client = PfSenseAPIClient(
                base_url=base_url,
                username=username,
                password=password,
                verify_ssl=verify_ssl
            )
            
            async def test_connection():
                health = await api_client.health_check()
                return health
            
            health = asyncio.run(test_connection())
            
            if health['connected']:
                click.echo("[OK] Connection test successful!")
            else:
                click.echo(f"[ERROR] Connection test failed: {health.get('error')}")
                
        except Exception as e:
            click.echo(f"[ERROR] Connection test failed: {e}")


@cli.command()
@pass_context
def status(ctx):
    """Show pfSense connection status and system information."""
    try:
        # Initialize API client
        from .utils import get_api_client
        ctx.api_client = get_api_client(ctx)
        
        # Authenticate synchronously first
        ctx.api_client.authenticate()
        
        # Then run async operations
        async def get_status():
            try:
                health = await ctx.api_client.health_check()
                if health['connected']:
                    system_info = await ctx.api_client.get_system_info()
                    return health, system_info
                return health, None
            except Exception as e:
                logger.error(f"Status check failed: {e}")
                return {'connected': False, 'error': str(e)}, None
        
        # Create new event loop to avoid conflicts
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            health, system_info = loop.run_until_complete(get_status())
        finally:
            loop.close()
        
        click.echo("pfSense Connection Status")
        click.echo("=" * 25)
        
        if health['connected']:
            click.echo(f"Status: [OK] Connected")
            click.echo(f"Authenticated: {'[OK] Yes' if health['authenticated'] else '[ERROR] No'}")
            click.echo(f"API Version: {health.get('api_version', 'Unknown')}")
            
            if system_info:
                data = system_info.get('data', {})
                click.echo(f"System Version: {data.get('version', 'Unknown')}")
                click.echo(f"System Time: {data.get('datetime', 'Unknown')}")
        else:
            click.echo(f"Status: [ERROR] Disconnected")
            click.echo(f"Error: {health.get('error', 'Unknown error')}")
            
    except Exception as e:
        click.echo(f"[ERROR] Failed to get status: {e}")
        sys.exit(1)


@cli.command()
@click.option('--format', type=click.Choice(['table', 'json', 'yaml']), default='table')
@pass_context
def config(ctx, format: str):
    """Show current configuration settings."""
    settings = ctx.config_manager.settings
    
    if format == 'json':
        import json
        click.echo(json.dumps(settings, indent=2))
    elif format == 'yaml':
        import yaml
        click.echo(yaml.dump(settings, default_flow_style=False))
    else:
        # Table format
        click.echo("Current Configuration")
        click.echo("=" * 20)
        
        pfsense = settings.get('pfsense', {})
        click.echo(f"pfSense URL: {pfsense.get('base_url', 'Not set')}")
        click.echo(f"Username: {pfsense.get('username', 'Not set')}")
        click.echo(f"SSL Verification: {pfsense.get('verify_ssl', 'Not set')}")
        click.echo(f"Timeout: {pfsense.get('timeout', 'Not set')}s")
        
        network = settings.get('network', {})
        click.echo(f"\nNetwork Defaults:")
        click.echo(f"  Domain: {network.get('default_domain', 'Not set')}")
        click.echo(f"  DNS Servers: {', '.join(network.get('default_dns_servers', []))}")
        click.echo(f"  Interface: {network.get('default_interface', 'Not set')}")


@cli.command('set-config')
@click.argument('key')
@click.argument('value')
@pass_context
def set_config(ctx, key: str, value: str):
    """Set configuration value using dot notation (e.g., pfsense.base_url)."""
    try:
        # Try to parse as JSON for complex values
        import json
        try:
            parsed_value = json.loads(value)
        except json.JSONDecodeError:
            parsed_value = value
        
        ctx.config_manager.set_setting(key, parsed_value)
        click.echo(f"[OK] Set {key} = {parsed_value}")
        
    except Exception as e:
        click.echo(f"[ERROR] Failed to set configuration: {e}")
        sys.exit(1)




# Import and add command groups after avoiding circular imports
from .client import client_group
from .network import network_group  
from .vpn import vpn_group

# Import command groups - circular import resolved

cli.add_command(client_group)
cli.add_command(network_group)
cli.add_command(vpn_group)


def main():
    """Main entry point for the CLI."""
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\n\nOperation cancelled by user.")
        sys.exit(130)
    except PfSenseAPIError as e:
        click.echo(f"[ERROR] API Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception("Unexpected error occurred")
        click.echo(f"[ERROR] Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()