
supported_features = {
    "products": ['cloud_waap'],
    "cloud_waap":{
        "mapping" : {
            "path" : "cloud_waap/field_mapping.json",
            "required_for": ['cef', 'leef']
        },
        "supported_conversions": ['cef', 'leef', "json"],
        "supported_log_types": ['CSP', "Access", "WAF", "Bot", "DDoS", "WebDDoS"],
        "supported_input_type": ['sqs']

    }
}