"""
Scanner IAM AWS — détecte les problèmes de permissions sur AWS.

Phase actuelle : mode mock (données simulées, pas besoin de compte AWS).
Phase 4 : connexion réelle via boto3.

Problèmes détectés :
- Rôles avec AdministratorAccess ou PowerUserAccess
- Utilisateurs sans MFA
- Access keys de plus de 90 jours
- Comptes dormants (pas de login > 90 jours)
"""

from datetime import UTC, datetime

from src.models.finding import (
    Category,
    Cloud,
    ComplianceMapping,
    Finding,
    Recommendation,
    ResourceType,
    Severity,
)
from src.scanners.base_scanner import BaseScanner


class AwsScanner(BaseScanner):
    """Scanner IAM pour Amazon Web Services."""

    @property
    def cloud_name(self) -> str:
        return "aws"

    def scan(self) -> list[Finding]:
        """
        Scanner les permissions IAM AWS.

        Pour l'instant, retourne des données mockées réalistes.
        En Phase 4, ce code sera remplacé par de vrais appels boto3.
        """
        # TODO Phase 4 : remplacer par de vrais appels boto3
        return self._mock_scan()

    def _mock_scan(self) -> list[Finding]:
        """Générer des findings simulés pour le développement."""
        return [
            Finding(
                finding_id="f-aws-001",
                cloud=Cloud.AWS,
                timestamp=datetime.now(UTC),
                resource_type=ResourceType.IAM_ROLE,
                resource_id="arn:aws:iam::123456789012:role/AdminRole",
                severity=Severity.HIGH,
                category=Category.EXCESSIVE_PERMISSIONS,
                description="Role has AdministratorAccess policy attached",
                affected_principals=["user/dev-user-1", "user/dev-user-2"],
                compliance_mapping=ComplianceMapping(
                    iso27001=["A.5.15", "A.5.18"],
                    nist_csf=["PR.AC-4", "PR.AC-6"],
                    soc2=["CC6.1", "CC6.3"],
                ),
                recommendation=Recommendation(
                    summary="Réduire les permissions au minimum nécessaire",
                    code_fix="aws iam detach-role-policy --role-name AdminRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                    risk_of_fix="medium",
                    auto_remediable=False,
                ),
            ),
            Finding(
                finding_id="f-aws-002",
                cloud=Cloud.AWS,
                timestamp=datetime.now(UTC),
                resource_type=ResourceType.IAM_USER,
                resource_id="arn:aws:iam::123456789012:user/old-contractor",
                severity=Severity.MEDIUM,
                category=Category.DORMANT_ACCOUNT,
                description="User has not logged in for 120 days",
                affected_principals=["user/old-contractor"],
                compliance_mapping=ComplianceMapping(
                    iso27001=["A.5.16", "A.5.18"],
                    nist_csf=["PR.AC-1", "PR.AC-6"],
                    soc2=["CC6.1", "CC6.2"],
                ),
                recommendation=Recommendation(
                    summary="Désactiver ce compte dormant",
                    code_fix="aws iam delete-login-profile --user-name old-contractor",
                    risk_of_fix="low",
                    auto_remediable=True,
                ),
            ),
            Finding(
                finding_id="f-aws-003",
                cloud=Cloud.AWS,
                timestamp=datetime.now(UTC),
                resource_type=ResourceType.IAM_USER,
                resource_id="arn:aws:iam::123456789012:user/dev-user-1",
                severity=Severity.HIGH,
                category=Category.NO_MFA,
                description="User does not have MFA enabled",
                affected_principals=["user/dev-user-1"],
                compliance_mapping=ComplianceMapping(
                    iso27001=["A.5.17"],
                    nist_csf=["PR.AC-7"],
                    soc2=["CC6.1"],
                ),
                recommendation=Recommendation(
                    summary="Activer l'authentification multi-facteur (MFA)",
                    risk_of_fix="low",
                    auto_remediable=False,
                ),
            ),
        ]
