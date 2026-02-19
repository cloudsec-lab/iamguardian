"""
Tests pour le modèle Finding.

Ces tests vérifient que :
- On peut créer un Finding avec les champs obligatoires
- La validation Pydantic rejette les valeurs invalides
- La sérialisation JSON fonctionne correctement
- Le chargement depuis le fichier sample_findings.json fonctionne
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

from src.models.finding import (
    Category,
    Cloud,
    ComplianceMapping,
    Finding,
    Recommendation,
    ResourceType,
    Severity,
)


class TestFindingCreation:
    """Tests de création de Finding."""

    def test_create_minimal_finding(self):
        """Créer un finding avec uniquement les champs obligatoires."""
        finding = Finding(
            finding_id="f-test-001",
            cloud=Cloud.AWS,
            resource_type=ResourceType.IAM_ROLE,
            resource_id="arn:aws:iam::123:role/TestRole",
            severity=Severity.HIGH,
            category=Category.EXCESSIVE_PERMISSIONS,
            description="Test finding",
        )
        assert finding.finding_id == "f-test-001"
        assert finding.cloud == Cloud.AWS
        assert finding.severity == Severity.HIGH
        assert finding.remediated is False
        assert finding.recommendation is None

    def test_create_full_finding(self):
        """Créer un finding avec tous les champs."""
        finding = Finding(
            finding_id="f-test-002",
            cloud=Cloud.AZURE,
            timestamp=datetime(2025, 1, 15, 6, 0, 0),
            resource_type=ResourceType.SERVICE_PRINCIPAL,
            resource_id="/subscriptions/sub-123/roleAssignments/ra-456",
            severity=Severity.CRITICAL,
            category=Category.EXCESSIVE_PERMISSIONS,
            description="Service principal has Owner role",
            affected_principals=["sp/legacy-app"],
            compliance_mapping=ComplianceMapping(
                iso27001=["A.5.15"],
                nist_csf=["PR.AC-4"],
                soc2=["CC6.1"],
            ),
            recommendation=Recommendation(
                summary="Réduire les permissions",
                code_fix="az role assignment delete ...",
                risk_of_fix="high",
                auto_remediable=False,
            ),
        )
        assert finding.cloud == Cloud.AZURE
        assert finding.severity == Severity.CRITICAL
        assert finding.recommendation.summary == "Réduire les permissions"
        assert len(finding.compliance_mapping.iso27001) == 1

    def test_invalid_cloud_rejected(self):
        """Vérifier que Pydantic rejette un cloud invalide."""
        with pytest.raises(Exception):
            Finding(
                finding_id="f-test-003",
                cloud="invalid_cloud",
                resource_type=ResourceType.IAM_USER,
                resource_id="test",
                severity=Severity.LOW,
                category=Category.NO_MFA,
                description="Test",
            )

    def test_invalid_severity_rejected(self):
        """Vérifier que Pydantic rejette une sévérité invalide."""
        with pytest.raises(Exception):
            Finding(
                finding_id="f-test-004",
                cloud=Cloud.AWS,
                resource_type=ResourceType.IAM_USER,
                resource_id="test",
                severity="super_high",
                category=Category.NO_MFA,
                description="Test",
            )


class TestFindingSerialization:
    """Tests de sérialisation/désérialisation JSON."""

    def test_to_json_and_back(self):
        """Vérifier qu'un finding survit à un aller-retour JSON."""
        original = Finding(
            finding_id="f-test-json",
            cloud=Cloud.GCP,
            resource_type=ResourceType.SERVICE_ACCOUNT,
            resource_id="projects/test/serviceAccounts/sa@test.iam.gserviceaccount.com",
            severity=Severity.MEDIUM,
            category=Category.OLD_ACCESS_KEY,
            description="Service account key is 180 days old",
            compliance_mapping=ComplianceMapping(
                iso27001=["A.5.17"],
                nist_csf=["PR.AC-1"],
                soc2=["CC6.1"],
            ),
        )
        # Sérialiser en JSON puis reconstruire
        json_str = original.model_dump_json()
        restored = Finding.model_validate_json(json_str)

        assert restored.finding_id == original.finding_id
        assert restored.cloud == original.cloud
        assert restored.severity == original.severity
        assert restored.compliance_mapping.iso27001 == ["A.5.17"]

    def test_load_sample_findings(self):
        """Charger les données de test depuis sample_findings.json."""
        sample_path = Path(__file__).parent.parent / "data" / "sample_findings.json"
        if not sample_path.exists():
            pytest.skip("sample_findings.json not found")

        with open(sample_path, encoding="utf-8") as f:
            raw_data = json.load(f)

        findings = [Finding.model_validate(item) for item in raw_data]
        assert len(findings) == 8
        assert findings[0].finding_id == "f-aws-001"
        # Tous les findings sont AWS (scanner mock Phase 2)
        for f in findings:
            assert f.cloud == Cloud.AWS


class TestComplianceMapping:
    """Tests du mapping de conformité."""

    def test_empty_mapping(self):
        """Un mapping vide est valide (par défaut)."""
        mapping = ComplianceMapping()
        assert mapping.iso27001 == []
        assert mapping.nist_csf == []
        assert mapping.soc2 == []

    def test_mapping_with_controls(self):
        """Vérifier qu'on peut créer un mapping avec des contrôles."""
        mapping = ComplianceMapping(
            iso27001=["A.5.15", "A.5.16", "A.5.17", "A.5.18"],
            nist_csf=["PR.AC-4", "PR.AC-6"],
            soc2=["CC6.1"],
        )
        assert len(mapping.iso27001) == 4
        assert "A.5.15" in mapping.iso27001


class TestRecommendation:
    """Tests du modèle Recommendation."""

    def test_minimal_recommendation(self):
        """Créer une recommandation avec le minimum requis."""
        reco = Recommendation(summary="Corriger le problème")
        assert reco.summary == "Corriger le problème"
        assert reco.code_fix is None
        assert reco.auto_remediable is False

    def test_full_recommendation(self):
        """Créer une recommandation complète."""
        reco = Recommendation(
            summary="Réduire les permissions",
            code_fix="aws iam detach-role-policy ...",
            terraform_fix="resource \"aws_iam_role\" { ... }",
            risk_of_fix="low",
            auto_remediable=True,
        )
        assert reco.auto_remediable is True
        assert reco.risk_of_fix == "low"
