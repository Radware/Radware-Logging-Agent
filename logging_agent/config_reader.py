import yaml
import os
import re
from urllib.parse import urlparse
from .app_info import supported_features  # Import supported_features from app_info
from pathlib import Path
import importlib.util


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
            self.config['https'] = self.config.get('https', {})

            # Normalize paths
            if 'output_directory' in self.config['general']:
                self.config['general']['output_directory'] = str(self.normalize_path(self.config['general']['output_directory']))
            if 'log_directory' in self.config['general']:
                self.config['general']['log_directory'] = str(self.normalize_path(self.config['general']['log_directory']))

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
            # combined_config = {}
            # combined_config['general'] = self.config['general']
            combined_config = {**self.config['general'], **agent_config}
            combined_config['aws_credentials'] = self.config['aws_credentials']
            combined_config['output'] = self.config['output']
            combined_config['formats'] = self.config['formats']

            # Apply default TLS settings
            combined_config['tls'] = self.config.get('tls', {}).copy()
            combined_config['tls'].setdefault('verify', False)
            product = combined_config.get('product')
            if product in supported_features['products']:
                supported_log_types = supported_features[product]['supported_log_types']
                combined_config['logs'] = combined_config.get('logs', {})
                for log_type in supported_log_types:
                    combined_config['logs'].setdefault(log_type, False)
            # Apply default format settings based on the output format
            output_format = combined_config['output'].get('output_format')
            default_format_values = self.get_default_format_values()
            format_defaults = default_format_values.get(output_format, {})
            for key, value in format_defaults.items():
                combined_config['formats'].setdefault(key, value)

            # Apply default batch settings for all output types
            for output_type in ['tcp', 'udp', 'tls', 'http', 'https']:
                combined_config.setdefault(output_type, {})
                combined_config[output_type].setdefault('batch', False)

            return combined_config
        return None

    def get_default_format_values(self):
        # Default values for each format
        return {
            'cef': {
                'delimiter': "\n",
                'time_format': "MM dd yyyy HH:mm:ss",
                'unify_fields': True,
                'severity_format': 1,
                'syslog_header': {
                    'generate_header': True,
                    'host': "product"
                }
            },
            'json': {
                'time_format': "MM dd yyyy HH:mm:ss",
                'unify_fields': True
            },
            'ndjson': {
                'time_format': "MM dd yyyy HH:mm:ss",
                'unify_fields': True
            },
            'leef': {
                'delimiter': "\n",
                'time_format': "MM dd yyyy HH:mm:ss",
                'unify_fields': True,
                'syslog_header': {
                    'generate_header': True,
                    'host': "product"
                }
            }
        }

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

#
#
# class Config:
#     _instance = None
#
#     def __new__(cls):
#         if cls._instance is None:
#             cls._instance = super(Config, cls).__new__(cls)
#             cls._instance.load_config()
#         return cls._instance
#
#     def normalize_path(self, raw_path):
#         # Normalizes a raw path string to the path format of the current operating system.
#         if raw_path[1:3] == ':\\' or raw_path.startswith('/'):
#             return Path(raw_path)
#         else:
#             # Adjust this part according to how you'd like to handle relative paths
#             return Path(os.getcwd()) / raw_path
#
#     def process_env_vars(self, value):
#         # Function to replace placeholders with environment variable values
#         if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
#             env_var_name = value[2:-1]
#             return os.getenv(env_var_name, '')
#         elif isinstance(value, dict):
#             return {k: self.process_env_vars(v) for k, v in value.items()}
#         elif isinstance(value, list):
#             return [self.process_env_vars(v) for v in value]
#         return value
#
    # def validate_destination(self):
    #     # Validate and parse destination for output
    #     destination = self.config['output'].get('destination', '')
    #     url_parse = urlparse(destination)
    #     default_ports = {
    #         'http': 80,
    #         'https': 443,
    #         'tcp': 514,
    #         'udp': 514,
    #         'tls': 6514
    #     }
    #
    #     if url_parse.scheme in ['http', 'https']:
    #         # Strip the port from the destination and update the port separately
    #         self.config['output']['destination'] = url_parse.hostname
    #         port = url_parse.port if url_parse.port else default_ports[url_parse.scheme]
    #         self.config['output'][url_parse.scheme]['port'] = port
    #     else:
    #         # Extract port for non-HTTP/HTTPS schemes
    #         match = re.search(r':(\d+)$', destination)
    #         if match:
    #             # If a port is found, strip it from the destination
    #             port = int(match.group(1))
    #             self.config['output']['destination'] = destination.replace(f':{port}', '')
    #         else:
    #             # Use default port if no port is specified in the destination
    #             port = default_ports[self.config['output']['type']]
    #             self.config['output']['destination'] = destination
    #
    #         if not (0 < port < 65536):
    #             raise ValueError(f"Invalid port: {port}. Must be an integer between 1 and 65535.")
    #
    #         output_type = self.config['output']['type']
    #         self.config['output'][output_type] = {}
    #         self.config['output'][output_type]['port'] = port
#
#     def load_config(self, file_path='rla.yaml'):
#         # Adjust the path to load from the root folder of the app
#         base_dir = Path(__file__).parent.parent.resolve()
#         config_path = base_dir / file_path
#         try:
#             with open(config_path, 'r') as stream:
#                 self.config = yaml.safe_load(stream)
#
#             # Process environment variable placeholders in the configuration
#             self.config = self.process_env_vars(self.config)
#
#             # List of required configuration keys
#             required_keys = [
#                 'output_format', 'sqs_access_key_id', 'sqs_secret_access_key',
#                 'sqs_region', 'sqs_name', 'output'
#             ]
#
#             self.config['product'] = "cloud_waap"
#             self.config['products'] = ["cloud_waap"]
#             self.config['input_type'] = "sqs"
#
#             # Check if the 'general' section exists
#             if 'general' in self.config:
#                 general_config = self.config['general']
#
#                 # Normalize and set paths
#                 if 'output_directory' in general_config:
#                     self.config['output_directory'] = str(self.normalize_path(general_config['output_directory']))
#                 if 'log_directory' in general_config:
#                     self.config['log_directory'] = str(self.normalize_path(general_config['log_directory']))
#
#             tls_config = self.config.get('output', {}).get('tls', {})
#             if tls_config.get('verify', False):
#                 if 'ca_cert' in tls_config:
#                     tls_config['ca_cert'] = str(self.normalize_path(tls_config['ca_cert']))
#                 if 'client_cert' in tls_config:
#                     tls_config['client_cert'] = str(self.normalize_path(tls_config['client_cert']))
#                 if 'client_key' in tls_config:
#                     tls_config['client_key'] = str(self.normalize_path(tls_config['client_key']))
#
#             # Check for required configuration values and provide descriptive errors
#             missing_keys = []
#             for key in required_keys:
#                 if key not in self.config or not self.config[key]:
#                     missing_keys.append(key)
#
#             if missing_keys:
#                 raise ValueError(f"Missing configuration(s): {', '.join(missing_keys)}")
#
#             # Specific checks for certain values
#             if self.config['output_format'].lower() not in ['ndjson', 'json', 'cef', 'leef']:
#                 raise ValueError(f"Invalid output format: {self.config['output_format']}")
#
#             if 'type' not in self.config['output'] or self.config['output']['type'] not in ['http', 'https', 'udp', 'tcp', 'tls']:
#                 raise ValueError(f"Invalid or missing output type: {self.config.get('output', {}).get('type')}")
#
#             self.validate_destination()
#
#
#             # Handle unify_fields setting based on output_format
#             output_format = self.config.get('output_format', '').lower()
#             if output_format in ['json', 'ndjson']:
#                 output_key = output_format  # 'json' or 'ndjson'
#                 output_config = self.config.get('output', {}).get(output_key, {})
#                 if output_config:
#                     unify_fields = output_config.get('unify_fields', True)
#                     self.config['output'][output_key]['unify_fields'] = unify_fields
#                 else:
#                 # Ensure the subfield for the output_format does not mistakenly contain unify_fields
#                     self.config['output'][output_key] = {}
#                     self.config['output'][output_key]['unify_fields'] = True
#             else:
#                 output_key = output_format  # 'json' or 'ndjson'
#                 output_config = self.config.get('output', {}).get(output_key, {})
#                 if not output_config:
#                     self.config['output'][output_key] = {}
#                     self.config['output'][output_key]['unify_fields'] = True
#
#             # Additional validation for TLS TCP output
#             if self.config['output']['type'] == 'tls':
#                 if self.config['output']['tls'].get('verify', False):
#                     if 'ca_cert' not in self.config['output']['tls']:
#                         raise ValueError(
#                             "Missing TLS configuration: 'output.tls.ca_cert' must be specified if verification is enabled.")
#                     # Optionally, validate the existence of the specified certificate file
#                     if not os.path.isfile(self.config['output']['tls']['ca_cert']):
#                         raise ValueError(f"CA Certificate file not found: {self.config['output']['tls']['ca_cert']}")
#
#                 # Validate client certificate and key if provided
#                 if 'client_cert' in self.config['output']['tls'] and not os.path.isfile(self.config['output']['tls']['client_cert']):
#                     raise ValueError(f"Client Certificate file not found: {self.config['output']['tls']['client_cert']}")
#                 if 'client_key' in self.config['output']['tls'] and not os.path.isfile(self.config['output']['tls']['client_key']):
#                     raise ValueError(f"Client Key file not found: {self.config['output']['tls']['client_key']}")
#
#
#         except yaml.YAMLError as exc:
#             raise Exception(f"Error reading YAML: {exc}")
#         except FileNotFoundError:
#             self.config = {}  # Or handle the error as needed
#             raise Exception(f"Configuration file not found: {file_path}")
#         except Exception as e:
#             raise Exception(f"Unexpected error: {e}")
