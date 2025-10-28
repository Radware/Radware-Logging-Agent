from __future__ import annotations

import json

import pytest

from logging_agent.transformer import Transformer


@pytest.fixture
def base_config() -> dict[str, object]:
    return {
        "product": "cloud_waap",
        "output": {"output_format": "json", "type": "tcp", "batch": False},
        "formats": {"json": {}},
    }


def test_transform_content_returns_json_strings(base_config: dict[str, object]) -> None:
    transformer = Transformer(base_config)
    data = [{"foo": "bar"}]
    data_fields = {"log_type": "Unknown", "metadata": {}}

    result = transformer.transform_content(data, data_fields, {})

    assert isinstance(result, list)
    assert json.loads(result[0])["foo"] == "bar"
    assert json.loads(result[0])["logType"] == "Unknown"


def test_transform_content_invokes_cef_conversion(base_config: dict[str, object], monkeypatch: pytest.MonkeyPatch) -> None:
    base_config = json.loads(json.dumps(base_config))
    base_config["output"]["output_format"] = "cef"
    base_config["formats"]["cef"] = {}

    field_mappings = {
        "cloud_waap": {
            "Access": {
                "cef": {
                    "prefix": "rdwrCld",
                    "header": {
                        "vendor": "Radware",
                        "product": "Cloud WAAP",
                        "version": "1.0",
                        "log_type": "Access",
                        "title": "fromlog",
                        "severity": "fromlog",
                    },
                    "static_mapping": {"action": "act"},
                }
            }
        }
    }

    monkeypatch.setattr(
        "logging_agent.transformer.FieldMappings.get_mapping_for_product",
        lambda _product: field_mappings,
    )

    transformer = Transformer(base_config)
    data = [{"action": "Allowed", "severity": "high", "name": "Example"}]
    data_fields = {"log_type": "Access", "metadata": {}}

    result = transformer.transform_content(data, data_fields, {"severity_format": 2})

    assert isinstance(result, list)
    assert result[0].startswith("CEF:0|Radware|Cloud WAAP")
    assert "act=Allowed" in result[0]


def test_transform_content_rejects_unsupported_format(base_config: dict[str, object]) -> None:
    base_config = json.loads(json.dumps(base_config))
    base_config["output"]["output_format"] = "xml"
    base_config["formats"]["xml"] = {}

    transformer = Transformer(base_config)
    data = [{"foo": "bar"}]
    data_fields = {"log_type": "Access", "metadata": {}}

    assert transformer.transform_content(data, data_fields, {}) is None

