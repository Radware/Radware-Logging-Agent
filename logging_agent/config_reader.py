import yaml
import re
from urllib.parse import urlparse
from .app_info import supported_features  # Import supported_features from app_info
import importlib.util
import platform
import yaml
import os
from pathlib import Path

class Config:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance.load_config()
        return cls._instance

    def normalize_path(self, raw_path):
        if raw_path.startswith('/') or raw_path[1:3] == ':\\':
            return Path(raw_path)
        else:
            return Path(os.getcwd()) / raw_path

    def process_env_vars(self, value):
        if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
            env_var_name = value[2:-1]
            return os.getenv(env_var_name, '')
        elif isinstance(value, dict):
            return {k: self.process_env_vars(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self.process_env_vars(v) for v in value]
        return value

    def transform_single_agent_config(self):
        # Extract the single agent configuration
        single_agent_config = self.config.pop('agent')


        # Transform and add the single agent to the agents list
        self.config['agents'] = [{
            'name': "cloud_waap",
            'type': "sqs",
            'num_worker_threads': single_agent_config.get('num_worker_threads', 5),
            'product': "cloud_waap",
            'sqs_settings': {
                'queue_name': single_agent_config.get('sqs_name', ''),
                'delete_on_failure': single_agent_config.get('delete_on_failure', False)
            },
            'logs': single_agent_config.get('logs', {})
        }]

    def load_config(self, file_path='rla.yaml'):
        base_dir = Path(__file__).parent.parent.resolve()
        config_path = base_dir / file_path
        try:
            with open(config_path, 'r') as stream:
                self.config = yaml.safe_load(stream)
                # Transform the configuration if it's using the old single-agent structure
                if 'agent' in self.config and not 'agents' in self.config:
                    self.transform_single_agent_config()

                # Process environment variable placeholders in the configuration
                self.config = self.process_env_vars(self.config)

            self.validate_destination()
            # Process general, aws_credentials, output, formats, tls, http, and https
            self.config['general'] = self.config.get('general', {})
            self.config['aws_credentials'] = self.config.get('aws_credentials', {})
            self.config['output'] = self.config.get('output', {})
            self.config['formats'] = self.config.get('formats', {})
            # Additional normalization for TLS configuration paths
            tls_config = self.config.get('tls', {})
            if tls_config.get('verify', False):
                if 'ca_cert' in tls_config:
                    tls_config['ca_cert'] = str(self.normalize_path(tls_config['ca_cert']))
                if 'client_cert' in tls_config:
                    tls_config['client_cert'] = str(self.normalize_path(tls_config['client_cert']))
                if 'client_key' in tls_config:
                    tls_config['client_key'] = str(self.normalize_path(tls_config['client_key']))

                # Update the TLS configuration back into self.config
                self.config['tls'] = tls_config

            self.config['http'] = self.config.get('http', {})
            # Additional normalization for HTTPS configuration paths
            https_config = self.config.get('https', {})
            if https_config.get('verify', False):
                if 'ca_cert' in https_config and https_config['ca_cert']:
                    https_config['ca_cert'] = str(self.normalize_path(https_config['ca_cert']))
                if 'client_cert' in https_config and https_config['client_cert']:
                    https_config['client_cert'] = str(self.normalize_path(https_config['client_cert']))
                if 'client_key' in https_config and https_config['client_key']:
                    https_config['client_key'] = str(self.normalize_path(https_config['client_key']))

                # Update the https configuration back into self.config
                self.config['https'] = https_config
            # Normalize paths and set defaults based on OS
            default_output_dir = '/tmp/' if platform.system() == 'Linux' else 'C:\\Temp\\'
            default_log_dir = '/var/log/rla/' if platform.system() == 'Linux' else 'C:\\Logs\\rla\\'
            default_log_file = 'agent.log'

            # Setting default for output directory if it does not exist or is empty
            if 'output_directory' not in self.config['general'] or not self.config['general']['output_directory']:
                self.config['general']['output_directory'] = default_output_dir
            else:
                self.config['general']['output_directory'] = str(
                    self.normalize_path(self.config['general']['output_directory']))

            # Setting default for log directory if it does not exist or is empty
            if 'log_directory' not in self.config['general'] or not self.config['general']['log_directory']:
                self.config['general']['log_directory'] = default_log_dir
            else:
                self.config['general']['log_directory'] = str(
                    self.normalize_path(self.config['general']['log_directory']))

            # Setting default log file name if it does not exist or is empty
            if 'log_file' not in self.config['general'] or not self.config['general']['log_file']:
                self.config['general']['log_file'] = default_log_file

            # Process agents
            self.config['agents'] = {agent['name']: agent for agent in self.config.get('agents', [])}

        except yaml.YAMLError as exc:
            raise Exception(f"Error reading YAML: {exc}")
        except FileNotFoundError:
            self.config = {}
            raise Exception(f"Configuration file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Unexpected error: {e}")

    def get_agent_config(self, agent_name):
        agent_config = self.config['agents'].get(agent_name, {})
        if agent_config:
            # Combine general and agent-specific settings
            combined_config = {**self.config['general'], **agent_config}
            combined_config['aws_credentials'] = self.config['aws_credentials']
            combined_config['output'] = self.config['output']
            combined_config['formats'] = self.config['formats']
            output_type = self.config['output'].get('type')
            combined_config[output_type] = self.config.get(output_type, {})

            # Define default settings
            defaults = {
                'tls': {'batch': False, 'verify': False, 'ca_cert': '', 'client_cert': '', 'client_key': ''},
                'http': {'batch': False, 'authentication': {'auth_type': 'none'}, 'custom_headers': {}},
                'https': {'batch': False, 'verify': False, 'ca_cert': '', 'client_cert': '', 'client_key': '',
                          'authentication': {'auth_type': 'none'}, 'custom_headers': {}},
                'udp': {'batch': False},
                'tcp': {'batch': False}
            }

            # Merge configurations carefully, with special handling for nested structures

            # Apply configurations based on the output type, preserving existing settings
            output_type = self.config['output'].get('type')
            if output_type in defaults:
                specific_config = combined_config.get(output_type, {})
                self._merge_configs(specific_config, defaults[output_type])  # Merge with defaults carefully
                combined_config[output_type] = specific_config

            output_format = combined_config['output'].get('output_format')
            default_format_values = self.get_default_format_values()
            format_defaults = default_format_values.get(output_format, {})

            # Check if the specific format is already in 'formats'; if not, initialize it
            if output_format not in combined_config['formats']:
                combined_config['formats'][output_format] = {}



            # Apply defaults specifically within the sub-dictionary for the output format
            self._apply_format_defaults(combined_config['formats'][output_format], format_defaults)

            return combined_config
        return None

    def get_default_format_values(self):
        # Default values for each format
        return {
            'cef': {
                'delimiter': "\n",
                'time_format': "ISO8601",
                'unify_fields': True,
                'severity_format': 1,
                'syslog_header': {
                    'generate_header': True,
                    'host': "product"
                }
            },
            'json': {
                'time_format': "ISO8601",
                'unify_fields': True
            },
            'leef': {
                'delimiter': "\n",
                'time_format': "ISO8601",
                'unify_fields': True,
                'syslog_header': {
                    'generate_header': True,
                    'host': "product"
                }
            }
        }

    def _merge_configs(self, base, updates):
        for key, value in updates.items():
            if key in base:
                if isinstance(base[key], dict) and isinstance(value, dict):
                    self._merge_configs(base[key], value)  # Recursively merge dictionaries
            else:
                base[key] = value

    def _apply_format_defaults(self, target_format_dict, defaults):
        for key, default_value in defaults.items():
            existing_value = target_format_dict.get(key, None)
            if existing_value in [None, "", {}]:  # If value is None, empty string, or empty dict
                target_format_dict[key] = default_value
            elif isinstance(existing_value, dict) and isinstance(default_value, dict):
                self._apply_format_defaults(existing_value, default_value)
    def get_all_products(self):
        """
        Returns a list of all unique products assigned to agents.

        Returns:
            list: A list of unique product names.
        """
        products = set()
        for agent_name, agent_value in self.config.get('agents', []).items():
            products.add(agent_value.get('product'))
        return list(products)

    def get_all_agent_names(self):
        """
        Returns a list of all unique agent names from the configuration.

        Returns:
            list: A list of unique agent names.
        """
        agent_names = set()
        for agent_name, agent_values in self.config.get('agents', []).items():
            agent_names.add(agent_name)
        return list(agent_names)

    def validate_destination(self):
        # Validate and parse destination for output
        destination = self.config['output'].get('destination', '')
        url_parse = urlparse(destination)
        default_ports = {
            'http': 80,
            'https': 443,
            'tcp': 514,
            'udp': 514,
            'tls': 6514
        }

        if url_parse.scheme in ['http', 'https']:
            # Strip the port from the destination and update the port separately
            self.config['output']['destination'] = url_parse.hostname
            port = url_parse.port if url_parse.port else default_ports[url_parse.scheme]
            self.config['output']['port'] = port
        else:
            # Extract port for non-HTTP/HTTPS schemes
            match = re.search(r':(\d+)$', destination)
            if match:
                # If a port is found, strip it from the destination
                port = int(match.group(1))
                self.config['output']['destination'] = destination.replace(f':{port}', '')
            else:
                # Use default port if no port is specified in the destination
                port = default_ports.get(self.config['output']['type'], 514)
                self.config['output']['destination'] = destination

            if not (0 < port < 65536):
                raise ValueError(f"Invalid port: {port}. Must be an integer between 1 and 65535.")

            self.config['output']['port'] = port

