import yaml
import os
import re
from urllib.parse import urlparse
from pathlib import Path
import importlib.util



class Config:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance.load_config()
        return cls._instance

    def normalize_path(self, raw_path):
        # Normalizes a raw path string to the path format of the current operating system.
        if raw_path[1:3] == ':\\' or raw_path.startswith('/'):
            return Path(raw_path)
        else:
            # Adjust this part according to how you'd like to handle relative paths
            return Path(os.getcwd()) / raw_path

    def process_env_vars(self, value):
        # Function to replace placeholders with environment variable values
        if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
            env_var_name = value[2:-1]
            return os.getenv(env_var_name, '')
        elif isinstance(value, dict):
            return {k: self.process_env_vars(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self.process_env_vars(v) for v in value]
        return value

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
            self.config['output'][url_parse.scheme]['port'] = port
        else:
            # Extract port for non-HTTP/HTTPS schemes
            match = re.search(r':(\d+)$', destination)
            if match:
                # If a port is found, strip it from the destination
                port = int(match.group(1))
                self.config['output']['destination'] = destination.replace(f':{port}', '')
            else:
                # Use default port if no port is specified in the destination
                port = default_ports[self.config['output']['type']]
                self.config['output']['destination'] = destination

            if not (0 < port < 65536):
                raise ValueError(f"Invalid port: {port}. Must be an integer between 1 and 65535.")

            output_type = self.config['output']['type']
            self.config['output'][output_type] = {}
            self.config['output'][output_type]['port'] = port

    def load_config(self, file_path='rla.yaml'):
        # Adjust the path to load from the root folder of the app
        base_dir = Path(__file__).parent.parent.resolve()
        config_path = base_dir / file_path
        try:
            with open(config_path, 'r') as stream:
                self.config = yaml.safe_load(stream)

            # Process environment variable placeholders in the configuration
            self.config = self.process_env_vars(self.config)

            # List of required configuration keys
            required_keys = [
                'output_format', 'sqs_access_key_id', 'sqs_secret_access_key',
                'sqs_region', 'sqs_name', 'output'
            ]


            # Normalize paths after loading the config
            if 'output_directory' in self.config:
                self.config['output_directory'] = str(self.normalize_path(self.config['output_directory']))
            if 'log_directory' in self.config:
                self.config['log_directory'] = str(self.normalize_path(self.config['log_directory']))

            tls_config = self.config.get('output', {}).get('tls', {})
            if tls_config.get('verify', False):
                if 'ca_cert' in tls_config:
                    tls_config['ca_cert'] = str(self.normalize_path(tls_config['ca_cert']))
                if 'client_cert' in tls_config:
                    tls_config['client_cert'] = str(self.normalize_path(tls_config['client_cert']))
                if 'client_key' in tls_config:
                    tls_config['client_key'] = str(self.normalize_path(tls_config['client_key']))

            # Check for required configuration values and provide descriptive errors
            missing_keys = []
            for key in required_keys:
                if key not in self.config or not self.config[key]:
                    missing_keys.append(key)

            if missing_keys:
                raise ValueError(f"Missing configuration(s): {', '.join(missing_keys)}")

            # Specific checks for certain values
            if self.config['output_format'].lower() not in ['ndjson', 'json', 'cef', 'leef']:
                raise ValueError(f"Invalid output format: {self.config['output_format']}")

            if 'type' not in self.config['output'] or self.config['output']['type'] not in ['http', 'https', 'udp', 'tcp', 'tls']:
                raise ValueError(f"Invalid or missing output type: {self.config.get('output', {}).get('type')}")

            self.validate_destination()


            # Handle unify_fields setting based on output_format
            output_format = self.config.get('output_format', '').lower()
            if output_format in ['json', 'ndjson']:
                output_key = output_format  # 'json' or 'ndjson'
                output_config = self.config.get('output', {}).get(output_key, {})
                if output_config:
                    unify_fields = output_config.get('unify_fields', True)
                    self.config['output'][output_key]['unify_fields'] = unify_fields
                else:
                # Ensure the subfield for the output_format does not mistakenly contain unify_fields
                    self.config['output'][output_key] = {}
                    self.config['output'][output_key]['unify_fields'] = True
            else:
                output_key = output_format  # 'json' or 'ndjson'
                output_config = self.config.get('output', {}).get(output_key, {})
                if not output_config:
                    self.config['output'][output_key] = {}
                    self.config['output'][output_key]['unify_fields'] = True

            # Additional validation for TLS TCP output
            if self.config['output']['type'] == 'tls':
                if self.config['output']['tls'].get('verify', False):
                    if 'ca_cert' not in self.config['output']['tls']:
                        raise ValueError(
                            "Missing TLS configuration: 'output.tls.ca_cert' must be specified if verification is enabled.")
                    # Optionally, validate the existence of the specified certificate file
                    if not os.path.isfile(self.config['output']['tls']['ca_cert']):
                        raise ValueError(f"CA Certificate file not found: {self.config['output']['tls']['ca_cert']}")

                # Validate client certificate and key if provided
                if 'client_cert' in self.config['output']['tls'] and not os.path.isfile(self.config['output']['tls']['client_cert']):
                    raise ValueError(f"Client Certificate file not found: {self.config['output']['tls']['client_cert']}")
                if 'client_key' in self.config['output']['tls'] and not os.path.isfile(self.config['output']['tls']['client_key']):
                    raise ValueError(f"Client Key file not found: {self.config['output']['tls']['client_key']}")


        except yaml.YAMLError as exc:
            raise Exception(f"Error reading YAML: {exc}")
        except FileNotFoundError:
            self.config = {}  # Or handle the error as needed
            raise Exception(f"Configuration file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Unexpected error: {e}")
