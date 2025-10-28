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
            output_type = self.config['output']['type']
            self.config['formats'] = self.config.get('formats', {})
            # Check if 'compatibility_mode' exists and is not None
            if 'compatibility_mode' in self.config['output']:
                # Check if the value is of type str and equals "none" (case-insensitive)
                if (isinstance(self.config['output']['compatibility_mode'], str) and
                        self.config['output']['compatibility_mode'].lower() == "none"):
                    self.config['output']['compatibility_mode'] = None
            else:
                # If 'compatibility_mode' does not exist, set it to None
                self.config['output']['compatibility_mode'] = None

            if 'compatibility_mode' in self.config['output'] and self.config['output']['compatibility_mode'] != None:
                self.config['output']['compatibility_mode'] = self.config['output']['compatibility_mode'].lower()

            # set debug field default values or override values
            debug = self.config.get('debug', None)
            if not debug:
                self.config['debug'] = {}
                self.config['debug']['verify_destination_connectivity'] = True
                self.config['debug']['config_verification'] = True
            else:
                self.config['debug']['verify_destination_connectivity'] = self.config['debug'].get('verify_destination_connectivity', True)
                self.config['debug']['config_verification'] = self.config['debug'].get('config_verification', True)

            # Set output type defaults
            type_config = self.config.get(output_type, None)
            if type_config == None:
                self.config[output_type] = {}
                if output_type in ['http', 'https']:
                    self.config[output_type]['authentication'] = {}
                    self.config[output_type]['authentication']['auth_type'] = None
                if output_type == 'https':
                    self.config[output_type]['verify'] = False
            else:
                if output_type == 'https':
                    if type_config.get('verify', None):
                        self.config[output_type]['verify'] = False


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

            if self.config['output']['type'] == "udp":
                self.config['output']['batch'] = False

            # Process agents
            normalized_agents = []
            for agent in self.config.get('agents', []):
                normalized_agents.append(self._normalize_agent(agent))
            self.config['agents'] = {agent['name']: agent for agent in normalized_agents}

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
            product = combined_config['product']
            output_type = self.config['output'].get('type')
            combined_config[output_type] = self.config.get(output_type, {})

            # Define default settings
            defaults = {
                'tls': {'verify': False, 'ca_cert': '', 'client_cert': '', 'client_key': ''},
                'http': {'authentication': {'auth_type': 'none'}, 'custom_headers': {}},
                'https': {'verify': False, 'ca_cert': '', 'client_cert': '', 'client_key': '',
                          'authentication': {'auth_type': 'none'}, 'custom_headers': {}},
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

    def _normalize_authorized_key_entry(self, entry):
        """
        Normalize a single authorized_keys entry. Supports both filesystem paths and inline keys.

        When the entry looks like an SSH public key (for example begins with ``ssh-`` or ``ecdsa-``),
        it is returned as-is (trimmed). Otherwise we assume it is a path and normalize accordingly.
        """
        if isinstance(entry, dict):
            path_value = entry.get('path')
            inline_value = entry.get('key') or entry.get('inline')
            if inline_value:
                return str(inline_value).strip()
            if path_value:
                return str(self.normalize_path(str(path_value)))
            entry = entry.get('value', '')

        entry_str = str(entry).strip()
        key_prefixes = (
            "ssh-", "ecdsa-sha2-", "sk-ssh-ed25519@", "sk-ssh-rsa@", "rsa-sha2-",
        )
        if entry_str.startswith(key_prefixes):
            return entry_str

        return str(self.normalize_path(entry_str))

    def _normalize_agent(self, agent):
        agent_type = (agent.get('type') or '').lower()
        product = agent.get('product')

        logs = agent.get('logs') or {}
        if not isinstance(logs, dict):
            logs = {}
        log_configuration = supported_features.get(product or 'cloud_waap', {}).get('log_configuration', {})
        unknown_option = log_configuration.get('unknown_option')
        if unknown_option and unknown_option not in logs:
            logs[unknown_option] = False
        agent['logs'] = logs

        if agent_type == 'file':
            file_settings = agent.get('file_settings', {}) or {}
            root_path = file_settings.get('root_path')
            if root_path:
                file_settings['root_path'] = str(self.normalize_path(root_path))

            polling_interval = file_settings.get('polling_interval_seconds')
            if polling_interval is not None:
                try:
                    file_settings['polling_interval_seconds'] = int(polling_interval)
                except (TypeError, ValueError):
                    file_settings['polling_interval_seconds'] = polling_interval

            completion_strategy = file_settings.get('completion_strategy')
            if isinstance(completion_strategy, str):
                completion_strategy = {'mode': completion_strategy}
            elif completion_strategy is None:
                completion_strategy = {}
            else:
                completion_strategy = dict(completion_strategy)

            archive_directory = completion_strategy.get('archive_directory')
            if archive_directory:
                completion_strategy['archive_directory'] = str(self.normalize_path(archive_directory))

            file_settings['completion_strategy'] = completion_strategy
            agent['file_settings'] = file_settings

        elif agent_type == 'sftp':
            sftp_settings = agent.get('sftp_settings', {}) or {}

            listen = sftp_settings.pop('listen_address', None) or sftp_settings.get('listen', {})
            listen_host = '0.0.0.0'
            listen_port = None

            if isinstance(listen, str):
                host_part, _, port_part = listen.partition(':')
                if host_part:
                    listen_host = host_part
                if port_part:
                    try:
                        listen_port = int(port_part)
                    except ValueError:
                        listen_port = None
            elif isinstance(listen, dict):
                listen_host = listen.get('host', listen_host)
                port_value = listen.get('port')
                try:
                    listen_port = int(port_value) if port_value is not None else None
                except (TypeError, ValueError):
                    listen_port = None

            requirements = supported_features.get(product or 'cloud_waap', {}).get('input_type_requirements', {})
            default_port = requirements.get('sftp', {}).get('default_port', 2222)
            if listen_port is None:
                listen_port = default_port

            sftp_settings['listen'] = {'host': listen_host, 'port': listen_port}

            host_keys = sftp_settings.get('host_keys', [])
            if isinstance(host_keys, (str, Path)):
                host_keys = [host_keys]
            normalized_host_keys = []
            for key_path in host_keys:
                if key_path:
                    normalized_host_keys.append(str(self.normalize_path(str(key_path))))
            sftp_settings['host_keys'] = normalized_host_keys

            drop_directory = sftp_settings.get('drop_directory')
            if drop_directory:
                sftp_settings['drop_directory'] = str(self.normalize_path(drop_directory))

            credential_policy = sftp_settings.get('credential_policy')
            if isinstance(credential_policy, str):
                credential_policy = {'mode': credential_policy}
            elif credential_policy is None:
                credential_policy = {}
            else:
                credential_policy = dict(credential_policy)

            users = credential_policy.get('users', [])
            if isinstance(users, dict):
                users = [users]

            normalized_users = []
            for user in users:
                normalized_user = dict(user)
                home_dir = normalized_user.get('home_directory')
                if home_dir:
                    normalized_user['home_directory'] = str(self.normalize_path(home_dir))

                authorized_keys = normalized_user.get('authorized_keys')
                if isinstance(authorized_keys, (str, Path)):
                    authorized_keys = [authorized_keys]
                if authorized_keys:
                    normalized_user['authorized_keys'] = [
                        self._normalize_authorized_key_entry(key_entry)
                        for key_entry in authorized_keys
                        if key_entry
                    ]

                normalized_users.append(normalized_user)

            if normalized_users:
                credential_policy['users'] = normalized_users

            sftp_settings['credential_policy'] = credential_policy
            agent['sftp_settings'] = sftp_settings

        return agent
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
        output_type = self.config['output'].get('type', '')

        # Temporarily prepend the scheme for proper urlparse handling if it's HTTP/HTTPS
        if output_type in ['http', 'https'] and not (
                destination.startswith('http://') or destination.startswith('https://')):
            scheme = f"{output_type}://"
            destination_temp = scheme + destination
        else:
            destination_temp = "http://" + destination

        url_parse = urlparse(destination_temp)
        default_ports = {
            'http': 80,
            'https': 443,
            'tcp': 514,
            'udp': 514,
            'tls': 6514
        }

        # Update configuration with parsed values
        self.config['output']['destination'] = url_parse.hostname
        self.config['output']['port'] = url_parse.port if url_parse.port else default_ports.get(output_type, 514)
        self.config['output']['uri'] = url_parse.path if url_parse.path else ""

        if not (0 < self.config['output']['port'] < 65536):
            raise ValueError(f"Invalid port: {self.config['output']['port']}. Must be an integer between 1 and 65535.")
