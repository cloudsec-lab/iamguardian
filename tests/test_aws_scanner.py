"""
Tests pour le scanner IAM AWS.

Ces tests vérifient que :
- Le scanner retourne le bon nombre de findings
- Toutes les catégories sont couvertes
- Toutes les sévérités attendues sont présentes
- Le mapping de conformité est correct
- L'intégration avec LocalStorage fonctionne
- La CLI fonctionne correctement
"""

import subprocess
import sys
from pathlib import Path

import pytest

from src.models.finding import Category, Cloud, Severity
from src.scanners.aws_scanner import AwsScanner
from src.storage.local_storage import LocalStorage


@pytest.fixture
def scanner():
    """Créer une instance du scanner AWS."""
    return AwsScanner()


@pytest.fixture
def findings(scanner):
    """Exécuter un scan et retourner les findings."""
    return scanner.scan()


class TestAwsScannerBasics:
    """Tests de base du scanner."""

    def test_cloud_name(self, scanner):
        """Le scanner identifie correctement son cloud."""
        assert scanner.cloud_name == "aws"

    def test_scan_returns_findings(self, findings):
        """Le scan retourne une liste non vide."""
        assert len(findings) > 0

    def test_scan_returns_8_findings(self, findings):
        """Le scan mock retourne exactement 8 findings."""
        assert len(findings) == 8

    def test_all_findings_are_aws(self, findings):
        """Tous les findings sont taggés AWS."""
        for f in findings:
            assert f.cloud == Cloud.AWS

    def test_all_findings_have_unique_ids(self, findings):
        """Chaque finding a un ID unique."""
        ids = [f.finding_id for f in findings]
        assert len(ids) == len(set(ids))

    def test_all_findings_have_recommendations(self, findings):
        """Chaque finding a une recommandation."""
        for f in findings:
            assert f.recommendation is not None
            assert len(f.recommendation.summary) > 0


class TestAwsScannerCategories:
    """Tests de couverture des catégories."""

    def test_covers_excessive_permissions(self, findings):
        """Au moins un finding de type permissions excessives."""
        cats = [f.category for f in findings]
        assert Category.EXCESSIVE_PERMISSIONS in cats

    def test_covers_dormant_account(self, findings):
        """Au moins un finding de type compte dormant."""
        cats = [f.category for f in findings]
        assert Category.DORMANT_ACCOUNT in cats

    def test_covers_no_mfa(self, findings):
        """Au moins un finding de type MFA manquant."""
        cats = [f.category for f in findings]
        assert Category.NO_MFA in cats

    def test_covers_old_access_key(self, findings):
        """Au moins un finding de type clé ancienne."""
        cats = [f.category for f in findings]
        assert Category.OLD_ACCESS_KEY in cats

    def test_covers_privilege_escalation(self, findings):
        """Au moins un finding de type escalade de privilèges."""
        cats = [f.category for f in findings]
        assert Category.PRIVILEGE_ESCALATION in cats

    def test_covers_shared_credentials(self, findings):
        """Au moins un finding de type credentials partagés."""
        cats = [f.category for f in findings]
        assert Category.SHARED_CREDENTIALS in cats

    def test_covers_public_access(self, findings):
        """Au moins un finding de type accès public."""
        cats = [f.category for f in findings]
        assert Category.PUBLIC_ACCESS in cats

    def test_all_7_categories_covered(self, findings):
        """Les 7 catégories de l'enum sont toutes couvertes."""
        categories_found = {f.category for f in findings}
        all_categories = set(Category)
        assert categories_found == all_categories


class TestAwsScannerSeverities:
    """Tests des niveaux de sévérité."""

    def test_has_critical_findings(self, findings):
        """Au moins un finding CRITICAL."""
        severities = [f.severity for f in findings]
        assert Severity.CRITICAL in severities

    def test_has_high_findings(self, findings):
        """Au moins un finding HIGH."""
        severities = [f.severity for f in findings]
        assert Severity.HIGH in severities

    def test_has_medium_findings(self, findings):
        """Au moins un finding MEDIUM."""
        severities = [f.severity for f in findings]
        assert Severity.MEDIUM in severities

    def test_severity_distribution(self, findings):
        """Vérifier la distribution des sévérités (2 CRITICAL, 3 HIGH, 3 MEDIUM)."""
        counts = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        assert counts[Severity.CRITICAL] == 2
        assert counts[Severity.HIGH] == 3
        assert counts[Severity.MEDIUM] == 3


class TestAwsScannerCompliance:
    """Tests du mapping de conformité."""

    def test_all_findings_have_compliance_mapping(self, findings):
        """Chaque finding a au moins un contrôle ISO 27001."""
        for f in findings:
            assert len(f.compliance_mapping.iso27001) > 0

    def test_iso27001_controls_present(self, findings):
        """Les contrôles ISO 27001 clés sont couverts."""
        all_controls = set()
        for f in findings:
            all_controls.update(f.compliance_mapping.iso27001)
        assert "A.5.15" in all_controls  # Contrôle d'accès
        assert "A.5.17" in all_controls  # Authentification
        assert "A.5.18" in all_controls  # Droits d'accès

    def test_nist_controls_present(self, findings):
        """Les fonctions NIST CSF clés sont couvertes."""
        all_controls = set()
        for f in findings:
            all_controls.update(f.compliance_mapping.nist_csf)
        assert "PR.AC-4" in all_controls  # Access permissions
        assert "PR.AC-1" in all_controls  # Identities and credentials


class TestAwsScannerStorage:
    """Tests d'intégration avec LocalStorage."""

    def test_save_findings_to_storage(self, findings, tmp_path):
        """Les findings du scanner se sauvegardent correctement."""
        storage = LocalStorage(file_path=str(tmp_path / "test_scan.json"))
        storage.save_findings(findings)
        assert storage.count() == 8

    def test_reload_findings_from_storage(self, findings, tmp_path):
        """Les findings sauvegardés se rechargent correctement."""
        storage = LocalStorage(file_path=str(tmp_path / "test_scan.json"))
        storage.save_findings(findings)

        # Recharger depuis le fichier
        reloaded = storage.get_all_findings()
        assert len(reloaded) == 8
        assert reloaded[0].finding_id == "f-aws-001"

    def test_filter_saved_findings_by_severity(self, findings, tmp_path):
        """Filtrer les findings sauvegardés par sévérité fonctionne."""
        storage = LocalStorage(file_path=str(tmp_path / "test_scan.json"))
        storage.save_findings(findings)

        critical = storage.get_findings_by_severity(Severity.CRITICAL)
        assert len(critical) == 2

    def test_rescan_replaces_findings(self, findings, tmp_path):
        """Un second scan remplace les findings existants (même IDs)."""
        storage = LocalStorage(file_path=str(tmp_path / "test_scan.json"))
        storage.save_findings(findings)
        assert storage.count() == 8

        # Re-sauvegarder (mêmes IDs = remplacement)
        storage.save_findings(findings)
        assert storage.count() == 8  # Pas de doublons


class TestAwsScannerCli:
    """Tests de la CLI."""

    def test_cli_mock_flag(self):
        """La CLI fonctionne avec --mock."""
        result = subprocess.run(
            [sys.executable, "-m", "src.scanners.aws_scanner", "--mock"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        assert "8 findings détectés" in result.stdout

    def test_cli_no_flag_exits_with_error(self):
        """La CLI sans --mock affiche une erreur."""
        result = subprocess.run(
            [sys.executable, "-m", "src.scanners.aws_scanner"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 1
        assert "mode réel" in result.stdout

    def test_cli_mock_save(self, tmp_path):
        """La CLI avec --mock --save crée le fichier."""
        output_file = tmp_path / "cli_test.json"
        result = subprocess.run(
            [
                sys.executable, "-m", "src.scanners.aws_scanner",
                "--mock", "--save", "--output", str(output_file),
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        assert output_file.exists()
        assert "sauvegardés" in result.stdout
