
supported_features = {
    "products": ['cloud_waap'],
    "cloud_waap":{
        "mapping": {
            "path": "cloud_waap/field_mapping.json",
            "required_for": ['cef', 'leef'],
            "compatibility_mode_conversion": ['ecs']
        },
        "supported_conversions": ['cef', 'leef', "json"],
        "supported_log_types": ['CSP', "Access", "WAF", "Bot", "DDoS", "WebDDoS"],
        "supported_input_type": ['sqs', 'file', 'sftp'],
        "input_type_requirements": {
            "file": {
                "completion_modes": ["delete", "archive"],
                "polling_interval_seconds": {
                    "min": 1,
                    "max": 3600
                }
            },
            "sftp": {
                "credential_modes": ["static", "public_key"],
                "default_port": 2222
            }
        },
        "compatibility_mode_conversion_function": ['splunk hec', 'ecs'],
        "compatibility_mode": ['splunk hec', 'ecs'],
        "compatibility_mode_requirements": {
            "splunk hec": {
                "output": {
                    "type": ['http', 'https'],
                    "output_format": ['json']
                }
            },
            "ecs": {
                "output": {
                    "type": ['http', 'https', 'tcp', 'tls'],
                    "output_format": ['json']
                }
            }
        }
    }
}
