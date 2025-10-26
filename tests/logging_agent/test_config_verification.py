import os

import pytest

os.environ.setdefault("RLA_VERIFY_MODE", "1")

from logging_agent import config_verification


class DummyResponse:
    def __init__(self, status_code, json_data=None, text='', ok=None, json_exc=False):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self._json_exc = json_exc
        self.ok = ok if ok is not None else 200 <= status_code < 300

    def json(self):
        if self._json_exc:
            raise ValueError("Invalid JSON")
        if self._json_data is None:
            raise ValueError("Invalid JSON")
        return self._json_data


class DummySession:
    def __init__(self, response):
        self._response = response
        self.headers = {}
        self.auth = None
        self.cert = None
        self.verify = True

    def post(self, url, data='', timeout=5):
        return self._response

    def get(self, url, timeout=5):
        return self._response


def patch_session(monkeypatch, response):
    monkeypatch.setattr(
        config_verification.requests,
        "Session",
        lambda: DummySession(response),
    )


def test_splunk_hec_http_accepts_no_data(monkeypatch):
    response = DummyResponse(400, json_data={"text": "No data"})
    monkeypatch.setattr(
        config_verification.requests,
        "post",
        lambda *args, **kwargs: response,
    )

    assert config_verification.test_http_connection("http://example", compatibility="splunk hec")


def test_splunk_hec_https_accepts_no_data(monkeypatch):
    response = DummyResponse(400, json_data={"text": "No data"})
    patch_session(monkeypatch, response)

    assert config_verification.test_https_connection("https://example", compatibility="splunk hec")


def test_splunk_hec_accepts_cribl_success(monkeypatch):
    http_response = DummyResponse(200, json_data={"code": 0})
    monkeypatch.setattr(
        config_verification.requests,
        "post",
        lambda *args, **kwargs: http_response,
    )

    https_response = DummyResponse(200, json_data={"text": "Success"})
    patch_session(monkeypatch, https_response)

    assert config_verification.test_http_connection("http://example", compatibility="splunk hec")
    assert config_verification.test_https_connection("https://example", compatibility="splunk hec")


def test_splunk_hec_accepts_non_json_success(monkeypatch):
    response = DummyResponse(200, text="OK", json_exc=True)
    monkeypatch.setattr(
        config_verification.requests,
        "post",
        lambda *args, **kwargs: response,
    )
    patch_session(monkeypatch, response)

    assert config_verification.test_http_connection("http://example", compatibility="splunk hec")
    assert config_verification.test_https_connection("https://example", compatibility="splunk hec")


@pytest.mark.parametrize(
    "response",
    [
        DummyResponse(500, json_data={"text": "error"}),
        DummyResponse(200, json_data={"text": "Unexpected"}),
    ],
)
def test_splunk_hec_rejects_unexpected_responses(monkeypatch, response):
    monkeypatch.setattr(
        config_verification.requests,
        "post",
        lambda *args, **kwargs: response,
    )
    patch_session(monkeypatch, response)

    assert not config_verification.test_http_connection("http://example", compatibility="splunk hec")
    assert not config_verification.test_https_connection("https://example", compatibility="splunk hec")
