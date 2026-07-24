from pathlib import Path

import pytest
import tomllib
from fastapi.testclient import TestClient

from cryptosentry import api


@pytest.fixture
def client():
    api._survey_summary = None
    yield TestClient(api.app)
    api._survey_summary = None


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_model_info(client):
    resp = client.get("/model")
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == api.__version__


def test_assess_valid_rsa(client):
    resp = client.post("/assess", json={"algorithm": "RSA", "key_size_bits": 1024})
    assert resp.status_code == 200
    body = resp.json()
    assert body["classical_risk"] == "critical"
    assert body["quantum_readiness"] == "not quantum resistant"


def test_assess_valid_ec(client):
    resp = client.post("/assess", json={"algorithm": "EC", "key_size_bits": 384})
    assert resp.status_code == 200
    assert resp.json()["classical_risk"] == "low"


def test_assess_rejects_unsupported_algorithm(client):
    resp = client.post("/assess", json={"algorithm": "DSA", "key_size_bits": 2048})
    assert resp.status_code == 400


def test_assess_rejects_missing_field(client):
    resp = client.post("/assess", json={"algorithm": "RSA"})
    assert resp.status_code == 422


def test_assess_rejects_absurd_key_size(client):
    resp = client.post("/assess", json={"algorithm": "RSA", "key_size_bits": 999999999})
    assert resp.status_code == 422


def test_survey_endpoint_reports_missing_data_gracefully(client, monkeypatch):
    monkeypatch.setenv("CRYPTOSENTRY_SURVEY_PATH", "/nonexistent/path.csv")
    resp = client.get("/survey")
    assert resp.status_code == 200
    assert "error" in resp.json()


def test_metrics_endpoint_exposes_prometheus_format(client):
    client.get("/healthz")
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "cryptosentry_requests_total" in resp.text


def test_model_version_matches_pyproject(client):
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as f:
        declared_version = tomllib.load(f)["project"]["version"]

    resp = client.get("/model")
    assert resp.json()["version"] == declared_version
