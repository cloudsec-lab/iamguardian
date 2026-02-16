"""
Tests pour le stockage local (LocalStorage).

Ces tests vérifient que :
- On peut sauvegarder et relire des findings
- Le filtrage par sévérité/cloud fonctionne
- La remédiation met à jour correctement le finding
- La suppression fonctionne
- Le fichier JSON est correctement écrit/lu
"""

import json
from pathlib import Path

import pytest

from src.models.finding import (
    Category,
    Cloud,
    ComplianceMapping,
    Finding,
    ResourceType,
    Severity,
)
from src.storage.local_storage import LocalStorage


@pytest.fixture
def tmp_storage(tmp_path):
    """
    Créer un stockage temporaire pour les tests.

    tmp_path est un dossier temporaire fourni par pytest,
    automatiquement nettoyé après chaque test.
    """
    storage_file = str(tmp_path / "test_findings.json")
    return LocalStorage(file_path=storage_file)


@pytest.fixture
def sample_finding():
    """Créer un finding de test."""
    return Finding(
        finding_id="f-test-001",
        cloud=Cloud.AWS,
        resource_type=ResourceType.IAM_ROLE,
        resource_id="arn:aws:iam::123:role/TestRole",
        severity=Severity.HIGH,
        category=Category.EXCESSIVE_PERMISSIONS,
        description="Test finding for storage",
    )


@pytest.fixture
def multiple_findings():
    """Créer plusieurs findings de test pour les filtres."""
    return [
        Finding(
            finding_id="f-aws-high",
            cloud=Cloud.AWS,
            resource_type=ResourceType.IAM_ROLE,
            resource_id="arn:aws:iam::123:role/Admin",
            severity=Severity.HIGH,
            category=Category.EXCESSIVE_PERMISSIONS,
            description="AWS high severity",
        ),
        Finding(
            finding_id="f-aws-low",
            cloud=Cloud.AWS,
            resource_type=ResourceType.IAM_USER,
            resource_id="arn:aws:iam::123:user/test",
            severity=Severity.LOW,
            category=Category.DORMANT_ACCOUNT,
            description="AWS low severity",
        ),
        Finding(
            finding_id="f-azure-high",
            cloud=Cloud.AZURE,
            resource_type=ResourceType.SERVICE_PRINCIPAL,
            resource_id="/subscriptions/sub-123/ra-456",
            severity=Severity.HIGH,
            category=Category.EXCESSIVE_PERMISSIONS,
            description="Azure high severity",
        ),
        Finding(
            finding_id="f-gcp-medium",
            cloud=Cloud.GCP,
            resource_type=ResourceType.SERVICE_ACCOUNT,
            resource_id="projects/test/serviceAccounts/sa@test.iam",
            severity=Severity.MEDIUM,
            category=Category.OLD_ACCESS_KEY,
            description="GCP medium severity",
        ),
    ]


class TestSaveAndLoad:
    """Tests de sauvegarde et chargement."""

    def test_save_and_get_finding(self, tmp_storage, sample_finding):
        """Sauvegarder un finding puis le relire."""
        tmp_storage.save_finding(sample_finding)
        result = tmp_storage.get_finding("f-test-001")

        assert result is not None
        assert result.finding_id == "f-test-001"
        assert result.severity == Severity.HIGH

    def test_get_nonexistent_finding(self, tmp_storage):
        """Chercher un finding qui n'existe pas retourne None."""
        result = tmp_storage.get_finding("does-not-exist")
        assert result is None

    def test_save_findings_bulk(self, tmp_storage, multiple_findings):
        """Sauvegarder plusieurs findings d'un coup."""
        tmp_storage.save_findings(multiple_findings)
        assert tmp_storage.count() == 4

    def test_save_replaces_existing(self, tmp_storage, sample_finding):
        """Sauvegarder un finding avec le même ID le remplace."""
        tmp_storage.save_finding(sample_finding)
        assert tmp_storage.count() == 1

        # Modifier la description et re-sauvegarder
        updated = sample_finding.model_copy(update={"description": "Updated"})
        tmp_storage.save_finding(updated)

        assert tmp_storage.count() == 1
        result = tmp_storage.get_finding("f-test-001")
        assert result.description == "Updated"

    def test_empty_storage(self, tmp_storage):
        """Un stockage vide retourne une liste vide."""
        assert tmp_storage.get_all_findings() == []
        assert tmp_storage.count() == 0


class TestFiltering:
    """Tests des filtres."""

    def test_filter_by_severity(self, tmp_storage, multiple_findings):
        """Filtrer les findings par sévérité."""
        tmp_storage.save_findings(multiple_findings)

        high = tmp_storage.get_findings_by_severity(Severity.HIGH)
        assert len(high) == 2

        low = tmp_storage.get_findings_by_severity(Severity.LOW)
        assert len(low) == 1

        critical = tmp_storage.get_findings_by_severity(Severity.CRITICAL)
        assert len(critical) == 0

    def test_filter_by_cloud(self, tmp_storage, multiple_findings):
        """Filtrer les findings par cloud."""
        tmp_storage.save_findings(multiple_findings)

        aws = tmp_storage.get_findings_by_cloud(Cloud.AWS)
        assert len(aws) == 2

        azure = tmp_storage.get_findings_by_cloud(Cloud.AZURE)
        assert len(azure) == 1

        gcp = tmp_storage.get_findings_by_cloud(Cloud.GCP)
        assert len(gcp) == 1


class TestRemediation:
    """Tests de la remédiation."""

    def test_mark_as_remediated(self, tmp_storage, sample_finding):
        """Marquer un finding comme remédié."""
        tmp_storage.save_finding(sample_finding)

        result = tmp_storage.mark_as_remediated("f-test-001")
        assert result is True

        finding = tmp_storage.get_finding("f-test-001")
        assert finding.remediated is True
        assert finding.remediated_at is not None

    def test_mark_nonexistent_as_remediated(self, tmp_storage):
        """Tenter de remédier un finding inexistant retourne False."""
        result = tmp_storage.mark_as_remediated("does-not-exist")
        assert result is False


class TestDeletion:
    """Tests de suppression."""

    def test_delete_finding(self, tmp_storage, sample_finding):
        """Supprimer un finding existant."""
        tmp_storage.save_finding(sample_finding)
        assert tmp_storage.count() == 1

        result = tmp_storage.delete_finding("f-test-001")
        assert result is True
        assert tmp_storage.count() == 0

    def test_delete_nonexistent_finding(self, tmp_storage):
        """Supprimer un finding inexistant retourne False."""
        result = tmp_storage.delete_finding("does-not-exist")
        assert result is False


class TestJsonFile:
    """Tests du fichier JSON sur disque."""

    def test_file_is_valid_json(self, tmp_storage, sample_finding):
        """Le fichier écrit est du JSON valide."""
        tmp_storage.save_finding(sample_finding)

        content = Path(tmp_storage._file_path).read_text(encoding="utf-8")
        data = json.loads(content)

        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["finding_id"] == "f-test-001"

    def test_persistence_across_instances(self, tmp_path, sample_finding):
        """Les données persistent entre deux instances de LocalStorage."""
        file_path = str(tmp_path / "persist_test.json")

        # Écrire avec une première instance
        storage1 = LocalStorage(file_path=file_path)
        storage1.save_finding(sample_finding)

        # Lire avec une seconde instance
        storage2 = LocalStorage(file_path=file_path)
        result = storage2.get_finding("f-test-001")

        assert result is not None
        assert result.finding_id == "f-test-001"
