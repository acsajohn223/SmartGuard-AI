"""
API level tests for Module 1 and Module 2 endpoints.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app

SAMPLES = Path(__file__).resolve().parents[2] / "samples" / "contracts"

VULNERABLE = (SAMPLES / "VulnerableVault.sol").read_text(encoding="utf-8")


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_root_banner(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["name"] == "SmartGuard AI"


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_detectors_endpoint_reports_57_eligible(client):
    response = client.get("/api/detectors")
    assert response.status_code == 200
    payload = response.json()
    assert payload["eligible_count"] == 57
    assert payload["included_impacts"] == ["High", "Medium"]


def test_upload_rejects_wrong_extension(client):
    response = client.post(
        "/api/analyze/upload",
        files={"file": ("contract.py", b"contract C {}", "text/x-python")},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "INVALID_EXTENSION"


def test_upload_rejects_empty_file(client):
    response = client.post(
        "/api/analyze/upload",
        files={"file": ("contract.sol", b"", "text/plain")},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "EMPTY_FILE"


def test_upload_accepts_valid_sol_file(client):
    response = client.post(
        "/api/analyze/upload",
        files={"file": ("VulnerableVault.sol", VULNERABLE.encode(), "text/plain")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["contract_name"] == "VulnerableVault.sol"
    assert payload["analysis_id"]
    assert payload["status"] == "queued"


def test_source_endpoint_rejects_empty(client):
    response = client.post(
        "/api/analyze/source", json={"content": "   ", "filename": "C.sol"}
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "EMPTY_SOURCE"


def test_sync_scan_returns_findings(client):
    response = client.post(
        "/api/scan/sync", json={"content": VULNERABLE, "filename": "VulnerableVault.sol"}
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    assert len(payload["findings"]) > 0
    assert payload["summary"]["total"] == len(payload["findings"])
    assert payload["detectors_ran"] == 57


def test_sync_scan_reports_failure_for_invalid_source(client):
    response = client.post(
        "/api/scan/sync", json={"content": "contract Broken { oops }", "filename": "B.sol"}
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "failed"
    assert payload["error_code"] == "COMPILATION_FAILED"


def test_analysis_polling_returns_stored_result(client):
    response = client.post(
        "/api/scan/sync", json={"content": VULNERABLE, "filename": "VulnerableVault.sol"}
    )
    analysis_id = response.json()["analysis_id"]

    poll = client.get(f"/api/analysis/{analysis_id}")
    assert poll.status_code == 200
    assert poll.json()["analysis_id"] == analysis_id


def test_analysis_polling_unknown_id(client):
    response = client.get("/api/analysis/does-not-exist")
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "NOT_FOUND"
