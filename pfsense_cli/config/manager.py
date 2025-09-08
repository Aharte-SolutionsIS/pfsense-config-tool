"""
Configuration management with YAML support, templates, and validation.
"""

import os
import yaml
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import shutil
from jinja2 import Environment, FileSystemLoader, Template

from ..models.client import ClientConfig, ClientType
from ..models.network import NetworkSettings
from ..models.vpn import VPNConfig
from ..api.exceptions import ConfigurationError, ValidationError

logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Configuration manager for pfSense CLI tool.
    Handles YAML-based configurations, templates, validation, and backups.
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_dir: Base configuration directory path
        """
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            # Default to user's home directory
            self.config_dir = Path.home() / '.pfsense-cli'
        
        # Setup directory structure
        self.clients_dir = self.config_dir / 'clients'
        self.templates_dir = self.config_dir / 'templates'
        self.backups_dir = self.config_dir / 'backups'
        self.settings_file = self.config_dir / 'settings.yaml'
        
        # Create directories if they don't exist
        self._ensure_directories()
        
        # Initialize Jinja2 template environment
        self.template_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Load global settings
        self.settings = self._load_settings()
        
        logger.info(f"Configuration manager initialized at {self.config_dir}")
    
    def _ensure_directories(self):
        """Create necessary directories if they don't exist."""
        for directory in [self.config_dir, self.clients_dir, self.templates_dir, self.backups_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Create default templates if they don't exist
        self._create_default_templates()
    
    def _create_default_templates(self):
        """Create default configuration templates."""
        templates = {
            'corporate_client.yaml': '''
name: "{{ client_name }}"
client_type: "corporate"
status: "pending"

network:
  network: "{{ network_cidr }}"
  gateway: "{{ gateway_ip }}"
  dns_servers:
    - "8.8.8.8"
    - "8.8.4.4"
  domain_name: "{{ domain_name | default('local') }}"

vlan:
  vlan_id: {{ vlan_id }}
  description: "{{ client_name }} Corporate Network"
  interface: "{{ parent_interface | default('em0') }}"

dhcp:
  enabled: true
  start_ip: "{{ dhcp_start }}"
  end_ip: "{{ dhcp_end }}"
  lease_time: 7200

firewall_rules:
  - action: "pass"
    protocol: "any"
    source: "{{ network_cidr }}"
    destination: "any"
    description: "Allow {{ client_name }} internet access"

vpn_enabled: {{ vpn_enabled | default(false) }}
tags:
  - "corporate"
  - "{{ client_type | default('standard') }}"
''',
            
            'branch_office.yaml': '''
name: "{{ client_name }}"
client_type: "branch_office"
status: "pending"

network:
  network: "{{ network_cidr }}"
  gateway: "{{ gateway_ip }}"
  dns_servers: {{ dns_servers | default(['8.8.8.8', '8.8.4.4']) | tojson }}
  domain_name: "{{ domain_name | default('branch.local') }}"

vlan:
  vlan_id: {{ vlan_id }}
  description: "{{ client_name }} Branch Office"
  interface: "{{ parent_interface | default('em0') }}"

dhcp:
  enabled: true
  start_ip: "{{ dhcp_start }}"
  end_ip: "{{ dhcp_end }}"
  lease_time: 3600

firewall_rules:
  - action: "pass"
    protocol: "tcp"
    source: "{{ network_cidr }}"
    destination: "any"
    port: "80,443"
    description: "Allow {{ client_name }} web access"
  
  - action: "pass"
    protocol: "udp"
    source: "{{ network_cidr }}"
    destination: "any"
    port: "53"
    description: "Allow {{ client_name }} DNS"

vpn_enabled: true
vpn_port: {{ vpn_port | default(1194) }}

tags:
  - "branch_office"
  - "vpn_enabled"
''',
            
            'remote_user.yaml': '''
name: "{{ client_name }}"
client_type: "remote_user"
status: "pending"

network:
  network: "{{ network_cidr }}"
  dns_servers:
    - "8.8.8.8"
    - "1.1.1.1"

firewall_rules:
  - action: "pass"
    protocol: "any"
    source: "{{ network_cidr }}"
    destination: "any"
    description: "Allow {{ client_name }} access"

vpn_enabled: true
vpn_port: {{ vpn_port | default(1194) }}

tags:
  - "remote_user"
  - "vpn_only"
'''
        }
        
        for template_name, content in templates.items():
            template_file = self.templates_dir / template_name
            if not template_file.exists():
                template_file.write_text(content)
                logger.debug(f"Created default template: {template_name}")
    
    def _load_settings(self) -> Dict[str, Any]:
        """Load global settings from YAML file."""
        if self.settings_file.exists():
            try:
                with open(self.settings_file, 'r') as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                logger.warning(f"Failed to load settings: {e}")
                return {}
        else:
            # Create default settings
            default_settings = {
                'pfsense': {
                    'base_url': 'https://192.168.1.1',
                    'verify_ssl': False,
                    'timeout': 30,
                    'max_retries': 3
                },
                'network': {
                    'default_domain': 'local',
                    'default_dns_servers': ['8.8.8.8', '8.8.4.4'],
                    'default_interface': 'em0'
                },
                'vpn': {
                    'default_port_range': [1194, 1204],
                    'encryption': 'AES-256-CBC',
                    'auth_digest': 'SHA256'
                },
                'backup': {
                    'enabled': True,
                    'retention_days': 30,
                    'compress': True
                }
            }
            
            self.save_settings(default_settings)
            return default_settings
    
    def save_settings(self, settings: Dict[str, Any]):
        """Save global settings to YAML file."""
        try:
            with open(self.settings_file, 'w') as f:
                yaml.dump(settings, f, default_flow_style=False, indent=2)
            self.settings = settings
            logger.info("Settings saved successfully")
        except Exception as e:
            raise ConfigurationError(f"Failed to save settings: {e}")
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """
        Get setting value using dot notation (e.g., 'pfsense.base_url').
        
        Args:
            key: Setting key in dot notation
            default: Default value if key not found
            
        Returns:
            Setting value or default
        """
        keys = key.split('.')
        value = self.settings
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set_setting(self, key: str, value: Any):
        """
        Set setting value using dot notation.
        
        Args:
            key: Setting key in dot notation
            value: Value to set
        """
        keys = key.split('.')
        settings = self.settings
        
        # Navigate to parent dict
        for k in keys[:-1]:
            if k not in settings:
                settings[k] = {}
            settings = settings[k]
        
        # Set the value
        settings[keys[-1]] = value
        self.save_settings(self.settings)
    
    def list_client_configs(self) -> List[str]:
        """List all client configuration files."""
        configs = []
        for file_path in self.clients_dir.glob('*.yaml'):
            configs.append(file_path.stem)
        return sorted(configs)
    
    def load_client_config(self, client_name: str) -> ClientConfig:
        """
        Load client configuration from YAML file.
        
        Args:
            client_name: Name of the client
            
        Returns:
            ClientConfig object
            
        Raises:
            ConfigurationError: If config file not found or invalid
        """
        config_file = self.clients_dir / f'{client_name}.yaml'
        
        if not config_file.exists():
            raise ConfigurationError(f"Client configuration '{client_name}' not found")
        
        try:
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
            
            # Validate and return ClientConfig
            return ClientConfig(**config_data)
            
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in {config_file}: {e}")
        except Exception as e:
            raise ValidationError(f"Invalid client configuration for '{client_name}': {e}")
    
    def save_client_config(self, client_config: ClientConfig, backup: bool = True):
        """
        Save client configuration to YAML file.
        
        Args:
            client_config: ClientConfig object to save
            backup: Whether to create backup of existing config
        """
        config_file = self.clients_dir / f'{client_config.name}.yaml'
        
        # Create backup if requested and file exists
        if backup and config_file.exists():
            self._backup_config(client_config.name)
        
        try:
            # Convert to dict and clean up None values
            config_dict = self._clean_config_dict(client_config.dict())
            
            # Add metadata
            config_dict['created_at'] = config_dict.get('created_at') or datetime.now().isoformat()
            config_dict['updated_at'] = datetime.now().isoformat()
            
            with open(config_file, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2, sort_keys=True)
            
            logger.info(f"Saved client configuration: {client_config.name}")
            
        except Exception as e:
            raise ConfigurationError(f"Failed to save client configuration '{client_config.name}': {e}")
    
    def delete_client_config(self, client_name: str, backup: bool = True):
        """
        Delete client configuration file.
        
        Args:
            client_name: Name of the client
            backup: Whether to create backup before deletion
        """
        config_file = self.clients_dir / f'{client_name}.yaml'
        
        if not config_file.exists():
            raise ConfigurationError(f"Client configuration '{client_name}' not found")
        
        if backup:
            self._backup_config(client_name)
        
        config_file.unlink()
        logger.info(f"Deleted client configuration: {client_name}")
    
    def create_from_template(
        self,
        template_name: str,
        client_name: str,
        template_vars: Dict[str, Any]
    ) -> ClientConfig:
        """
        Create client configuration from template.
        
        Args:
            template_name: Name of the template file (without .yaml extension)
            client_name: Name for the new client
            template_vars: Variables to substitute in template
            
        Returns:
            ClientConfig object
        """
        template_file = self.templates_dir / f'{template_name}.yaml'
        
        if not template_file.exists():
            raise ConfigurationError(f"Template '{template_name}' not found")
        
        try:
            # Load and render template
            template = self.template_env.get_template(f'{template_name}.yaml')
            
            # Add client_name to template vars
            template_vars['client_name'] = client_name
            
            # Render template
            rendered_config = template.render(**template_vars)
            
            # Parse YAML and create ClientConfig
            config_data = yaml.safe_load(rendered_config)
            client_config = ClientConfig(**config_data)
            
            # Save the generated configuration
            self.save_client_config(client_config, backup=False)
            
            logger.info(f"Created client '{client_name}' from template '{template_name}'")
            return client_config
            
        except Exception as e:
            raise ConfigurationError(f"Failed to create client from template: {e}")
    
    def validate_config(self, config_data: Dict[str, Any]) -> List[str]:
        """
        Validate configuration data and return list of validation errors.
        
        Args:
            config_data: Configuration dictionary
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        try:
            ClientConfig(**config_data)
        except Exception as e:
            errors.append(str(e))
        
        # Additional business logic validation
        if 'network' in config_data and 'vlan' in config_data:
            network = config_data['network']
            vlan = config_data['vlan']
            
            # Check for common network/VLAN conflicts
            if network.get('network') and vlan.get('vlan_id'):
                existing_configs = self.list_client_configs()
                for existing_name in existing_configs:
                    try:
                        existing_config = self.load_client_config(existing_name)
                        if existing_config.vlan and existing_config.vlan.vlan_id == vlan['vlan_id']:
                            errors.append(f"VLAN ID {vlan['vlan_id']} already used by client '{existing_name}'")
                        
                        if existing_config.network.network == network['network']:
                            errors.append(f"Network {network['network']} already used by client '{existing_name}'")
                    except Exception:
                        continue
        
        return errors
    
    def _clean_config_dict(self, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Remove None values and empty lists from configuration dictionary."""
        cleaned = {}
        
        for key, value in config_dict.items():
            if value is None:
                continue
            elif isinstance(value, dict):
                cleaned_nested = self._clean_config_dict(value)
                if cleaned_nested:
                    cleaned[key] = cleaned_nested
            elif isinstance(value, list):
                if value:  # Only include non-empty lists
                    cleaned[key] = value
            else:
                cleaned[key] = value
        
        return cleaned
    
    def _backup_config(self, client_name: str):
        """Create backup of existing client configuration."""
        config_file = self.clients_dir / f'{client_name}.yaml'
        
        if not config_file.exists():
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = self.backups_dir / f'{client_name}_{timestamp}.yaml'
        
        shutil.copy2(config_file, backup_file)
        logger.debug(f"Created backup: {backup_file}")
        
        # Cleanup old backups if retention is set
        self._cleanup_old_backups()
    
    def _cleanup_old_backups(self):
        """Remove old backup files based on retention settings."""
        retention_days = self.get_setting('backup.retention_days', 30)
        
        if retention_days <= 0:
            return
        
        cutoff_time = datetime.now().timestamp() - (retention_days * 24 * 3600)
        
        for backup_file in self.backups_dir.glob('*.yaml'):
            if backup_file.stat().st_mtime < cutoff_time:
                backup_file.unlink()
                logger.debug(f"Removed old backup: {backup_file}")
    
    def export_config(self, client_name: str, format: str = 'yaml') -> str:
        """
        Export client configuration in specified format.
        
        Args:
            client_name: Name of the client
            format: Export format ('yaml', 'json')
            
        Returns:
            Configuration as string
        """
        client_config = self.load_client_config(client_name)
        config_dict = self._clean_config_dict(client_config.dict())
        
        if format.lower() == 'json':
            return json.dumps(config_dict, indent=2, default=str)
        elif format.lower() == 'yaml':
            return yaml.dump(config_dict, default_flow_style=False, indent=2, sort_keys=True)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def import_config(self, config_data: str, format: str = 'yaml') -> ClientConfig:
        """
        Import client configuration from string data.
        
        Args:
            config_data: Configuration data as string
            format: Data format ('yaml', 'json')
            
        Returns:
            ClientConfig object
        """
        try:
            if format.lower() == 'json':
                data = json.loads(config_data)
            elif format.lower() == 'yaml':
                data = yaml.safe_load(config_data)
            else:
                raise ValueError(f"Unsupported import format: {format}")
            
            # Validate the configuration
            errors = self.validate_config(data)
            if errors:
                raise ValidationError(f"Configuration validation failed: {', '.join(errors)}")
            
            return ClientConfig(**data)
            
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            raise ConfigurationError(f"Failed to parse {format} data: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to import configuration: {e}")
    
    def list_templates(self) -> List[str]:
        """List available configuration templates."""
        templates = []
        for template_file in self.templates_dir.glob('*.yaml'):
            templates.append(template_file.stem)
        return sorted(templates)
    
    def get_template_info(self, template_name: str) -> Dict[str, Any]:
        """Get information about a template including required variables."""
        template_file = self.templates_dir / f'{template_name}.yaml'
        
        if not template_file.exists():
            raise ConfigurationError(f"Template '{template_name}' not found")
        
        # Read template content
        content = template_file.read_text()
        
        # Extract variables using simple regex
        import re
        variables = set(re.findall(r'{{\s*(\w+)', content))
        
        return {
            'name': template_name,
            'path': str(template_file),
            'variables': sorted(list(variables)),
            'size': template_file.stat().st_size,
            'modified': datetime.fromtimestamp(template_file.stat().st_mtime).isoformat()
        }