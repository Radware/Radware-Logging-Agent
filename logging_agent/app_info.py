
supported_features = {
    "products": ['cloud_waap'],
    "cloud_waap":{
        "mapping" : {
            "path" : "cloud_waap/field_mapping.json",
            "required_for": ['cef', 'leef'],
            "compatibility_mode_conversion": ['ecs']
        },
        "supported_conversions": ['cef', 'leef', "json"],
        "supported_log_types": ['CSP', "Access", "WAF", "Bot", "DDoS", "WebDDoS"],
        "supported_input_type": ['sqs'],
        "compatibility_mode_conversion_function": ['Splunk HEC', 'ecs'],
        "compatibility_mode": ['Splunk HEC'],
        "compatibility_mode_requirements": {
            "Splunk HEC": {
                "output": {
                    "type": ['http', 'https'],
                    "output_format": ['json']
                }
            }
        }
    }
}