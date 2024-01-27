import json
import os
import pathlib
from .app_info import supported_features
from .logging_config import get_logger

class FieldMappings:
    _instance = None
    _field_mappings = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(FieldMappings, cls).__new__(cls)
            cls.logger = get_logger('FieldMappings')
        return cls._instance

    @classmethod
    def load_field_mappings(cls, products, output_format):
        base_dir = pathlib.Path(__file__).parent.resolve()
        for product in products:
            if output_format in supported_features[product]['mapping']['required_for']:
                mapping_file_path = os.path.join(base_dir, supported_features[product]['mapping']['path'])
                try:
                    with open(mapping_file_path, 'r') as file:
                        cls._field_mappings[product] = json.load(file)
                except FileNotFoundError:
                    cls.logger.error(f"Field mapping file not found for product {product}: {mapping_file_path}")
                    raise

    @classmethod
    def get_mappings(cls, products, output_format):
        if not cls._field_mappings:
            cls.load_field_mappings(products, output_format)
        return {product: cls._field_mappings.get(product, {}) for product in products}

    @classmethod
    def get_mapping_for_product(cls, product):
        """Returns the field mapping for a specific product."""
        return cls._field_mappings.get(product, {})
