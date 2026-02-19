"""
Tests du dashboard IAMGuardian — pages HTML et API JSON.

Vérifie que toutes les pages et endpoints fonctionnent correctement
avec des données de test injectées via monkeypatch.
"""

import pytest
from fastapi.testclient import TestClient

from src.dashboard.app import app
from src.scanners.aws_scanner import AwsScanner
from src.storage.local_storage import LocalStorage


@pytest.fixture(autouse=True)
def test_storage(tmp_path, monkeypatch):
    """Injecter un stockage de test avec 8 findings AWS."""
    storage = LocalStorage(str(tmp_path / "findings.json"))
    scanner = AwsScanner()
    findings = scanner.scan()
    storage.save_findings(findings)
    monkeypatch.setattr("src.dashboard.app.storage", storage)
    return storage


@pytest.fixture()
def client():
    """Client de test FastAPI."""
    return TestClient(app)


# --- Tests pages HTML ---


class TestHTMLPages:
    """Vérifier que les pages HTML se chargent correctement."""

    def test_home_page_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_home_page_contains_title(self, client):
        response = client.get("/")
        assert "IAMGuardian" in response.text

    def test_home_page_shows_stats(self, client):
        response = client.get("/")
        assert "Findings totaux" in response.text

    def test_home_page_shows_priority(self, client):
        response = client.get("/")
        assert "f-aws-" in response.text

    def test_findings_page(self, client):
        response = client.get("/findings")
        assert response.status_code == 200
        assert "f-aws-001" in response.text

    def test_findings_filter_by_cloud(self, client):
        response = client.get("/findings?cloud=aws")
        assert response.status_code == 200
        assert "f-aws-001" in response.text

    def test_findings_filter_by_severity(self, client):
        response = client.get("/findings?severity=critical")
        assert response.status_code == 200

    def test_findings_filter_no_results(self, client):
        response = client.get("/findings?cloud=azure")
        assert response.status_code == 200
        assert "Aucun finding" in response.text

    def test_finding_detail(self, client):
        response = client.get("/findings/f-aws-001")
        assert response.status_code == 200
        assert "f-aws-001" in response.text

    def test_finding_detail_shows_recommendation(self, client):
        response = client.get("/findings/f-aws-001")
        assert "Recommandation" in response.text

    def test_finding_not_found(self, client):
        response = client.get("/findings/f-nonexistent")
        assert response.status_code == 404

    def test_stats_page(self, client):
        response = client.get("/stats")
        assert response.status_code == 200
        assert "Statistiques" in response.text

    def test_compliance_iso27001(self, client):
        response = client.get("/compliance/iso27001")
        assert response.status_code == 200
        assert "ISO 27001" in response.text

    def test_compliance_nist(self, client):
        response = client.get("/compliance/nist_csf")
        assert response.status_code == 200
        assert "NIST" in response.text

    def test_compliance_soc2(self, client):
        response = client.get("/compliance/soc2")
        assert response.status_code == 200
        assert "SOC" in response.text

    def test_compliance_invalid_framework(self, client):
        response = client.get("/compliance/invalid")
        assert response.status_code == 400


# --- Tests API JSON ---


class TestAPIEndpoints:
    """Vérifier que l'API JSON fonctionne sous /api/."""

    def test_api_findings_returns_json(self, client):
        response = client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 8

    def test_api_findings_filter_cloud(self, client):
        response = client.get("/api/findings?cloud=aws")
        assert response.status_code == 200
        data = response.json()
        assert all(f["cloud"] == "aws" for f in data)

    def test_api_findings_filter_severity(self, client):
        response = client.get("/api/findings?severity=critical")
        assert response.status_code == 200
        data = response.json()
        assert all(f["severity"] == "critical" for f in data)

    def test_api_findings_invalid_cloud_returns_422(self, client):
        response = client.get("/api/findings?cloud=alibaba")
        assert response.status_code == 422

    def test_api_finding_detail(self, client):
        response = client.get("/api/findings/f-aws-001")
        assert response.status_code == 200
        data = response.json()
        assert data["finding_id"] == "f-aws-001"

    def test_api_finding_not_found(self, client):
        response = client.get("/api/findings/nonexistent")
        assert response.status_code == 404

    def test_api_stats(self, client):
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 8

    def test_api_compliance(self, client):
        response = client.get("/api/compliance/iso27001")
        assert response.status_code == 200
        data = response.json()
        assert "score" in data
        assert "controls" in data

    def test_api_priority(self, client):
        response = client.get("/api/priority")
        assert response.status_code == 200
        data = response.json()
        assert all(f["severity"] in ("high", "critical") for f in data)


# --- Tests empty state ---


class TestEmptyState:
    """Vérifier le comportement sans données."""

    def test_home_empty(self, client, tmp_path, monkeypatch):
        empty_storage = LocalStorage(str(tmp_path / "empty.json"))
        monkeypatch.setattr("src.dashboard.app.storage", empty_storage)
        response = client.get("/")
        assert response.status_code == 200
        assert "Aucun finding" in response.text

    def test_api_empty(self, client, tmp_path, monkeypatch):
        empty_storage = LocalStorage(str(tmp_path / "empty.json"))
        monkeypatch.setattr("src.dashboard.app.storage", empty_storage)
        response = client.get("/api/findings")
        assert response.status_code == 200
        assert response.json() == []
