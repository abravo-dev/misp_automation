import pytest
import requests
from imap_to_misp import MISPClient

class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code
    def json(self):
        return self.json_data
    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError()

def mock_post_attribute_exists(*args, **kwargs):
    """Simula una respuesta de MISP donde el atributo ya existe."""
    return MockResponse({
        "response": {"Attribute": [{"id": "123", "value": "8.8.8.8"}]}
    }, 200)

def mock_post_attribute_not_exists(*args, **kwargs):
    """Simula una respuesta de MISP donde el atributo no existe."""
    return MockResponse({"response": {"Attribute": []}}, 200)

def test_search_attribute_returns_true_when_exists(monkeypatch):
    """Verifica que search_attribute devuelve True si la API encuentra el atributo."""
    monkeypatch.setattr(requests, "request", mock_post_attribute_exists)
    misp_client = MISPClient(url="http://localhost", api_key="test")
    assert misp_client.search_attribute("8.8.8.8") is True

def test_search_attribute_returns_false_when_not_exists(monkeypatch):
    """Verifica que search_attribute devuelve False si la API no encuentra el atributo."""
    monkeypatch.setattr(requests, "request", mock_post_attribute_not_exists)
    misp_client = MISPClient(url="http://localhost", api_key="test")
    assert misp_client.search_attribute("1.2.3.4") is False