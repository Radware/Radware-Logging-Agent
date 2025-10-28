import copy
import json

import pytest

from logging_agent.field_mappings import FieldMappings
from logging_agent.transformer import Transformer


@pytest.fixture
def transformer_config(config_fixture):
    return copy.deepcopy(config_fixture)


def test_enrich_event_normalizes_unknown_log_json(transformer_config):
    transformer_config['output']['output_format'] = 'json'
    transformer_config.setdefault('formats', {}).setdefault('json', {})
    FieldMappings.load_field_mappings(['cloud_waap'], 'json', transformer_config['output'].get('compatibility_mode'))

    transformer = Transformer(config=transformer_config)

    event = {
        'source_ip': '192.0.2.1',
        'nested_field': {'inner_key': 'value'},
        'list_field': [{'child_key': 1}, 'unchanged'],
    }

    enriched = transformer.enrich_event(event, 'UnknownType', {'unify_fields': True}, {})

    assert 'sourceIp' in enriched and enriched['sourceIp'] == '192.0.2.1'
    assert 'source_ip' not in enriched
    assert enriched['nestedField']['innerKey'] == 'value'
    assert isinstance(enriched['listField'][0], dict)
    assert enriched['listField'][0]['childKey'] == 1
    assert enriched['logType'] == 'UnknownType'
    assert enriched['product'] == 'Cloud WAAP'


def test_enrich_event_normalizes_unknown_log_cef(transformer_config):
    transformer_config['output']['output_format'] = 'cef'
    FieldMappings.load_field_mappings(['cloud_waap'], 'cef', transformer_config['output'].get('compatibility_mode'))

    transformer = Transformer(config=transformer_config)

    event = {
        'attack_type': 'HTTP Flood',
        'http-method': 'GET',
    }

    enriched = transformer.enrich_event(event, 'Unmapped', {'unify_fields': True}, {})

    assert 'rdwrCldAttackType' in enriched and enriched['rdwrCldAttackType'] == 'HTTP Flood'
    assert 'rdwrCldHttpMethod' in enriched and enriched['rdwrCldHttpMethod'] == 'GET'
    assert enriched['logType'] == 'Unmapped'


def test_transform_content_ecs_mode_preserves_normalized_keys(transformer_config):
    transformer_config['output']['output_format'] = 'json'
    transformer_config['output']['compatibility_mode'] = 'ecs'
    transformer_config.setdefault('formats', {}).setdefault('json', {})
    FieldMappings.load_field_mappings(['cloud_waap'], 'json', 'ecs')

    transformer = Transformer(config=transformer_config)

    event = {'source_ip': '203.0.113.10', 'user_agent': 'ExampleAgent/1.0'}

    transformed = transformer.transform_content(
        [event],
        {'log_type': 'UnknownType', 'metadata': {}},
        {'unify_fields': True}
    )

    assert isinstance(transformed, list)
    ecs_payload = json.loads(transformed[0])
    raw_log = ecs_payload['radware']['cloud_waap']
    source_ip_value = raw_log['sourceIp']
    if isinstance(source_ip_value, list):
        assert '203.0.113.10' in source_ip_value
    else:
        assert source_ip_value == '203.0.113.10'
    assert raw_log['userAgent'] == 'ExampleAgent/1.0'
    assert raw_log['logType'] == 'UnknownType'

