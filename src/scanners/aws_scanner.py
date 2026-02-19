"""
Scanner IAM AWS — détecte les problèmes de permissions sur AWS.

Phase actuelle : mode mock (données simulées, pas besoin de compte AWS).
Phase 4 : connexion réelle via boto3.

Problèmes détectés (8 scénarios) :
- Rôles avec AdministratorAccess ou PowerUserAccess
- Utilisateurs sans MFA
- Access keys de plus de 90 jours
- Comptes dormants (pas de login > 90 jours)
- Policies trop permissives (wildcard *)
- Escalade de privilèges potentielle (iam:PassRole)
- Access keys partagées entre services
- Bucket S3 avec politique publique liée à un rôle IAM

Utilisation en CLI :
    python -m src.scanners.aws_scanner --mock
    python -m src.scanners.aws_scanner --mock --save
    python -m src.scanners.aws_scanner --mock --save --output data/findings.json
"""

import argparse
import json
import sys
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
from src.storage.local_storage import LocalStorage


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
        """
        Générer 8 findings simulés couvrant toutes les catégories.

        Chaque finding représente un problème IAM réaliste qu'on
        trouverait dans un vrai compte AWS mal configuré.
        """
        now = datetime.now(UTC)

        return [
            # --- 1. Permissions excessives : rôle avec AdministratorAccess ---
            Finding(
                finding_id="f-aws-001",
                cloud=Cloud.AWS,
                timestamp=now,
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
                    summary="Réduire les permissions au minimum nécessaire. "
                    "Ce rôle a un accès administrateur complet.",
                    code_fix=(
                        "aws iam detach-role-policy --role-name AdminRole "
                        "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
                    ),
                    risk_of_fix="medium",
                    auto_remediable=False,
                ),
            ),
            # --- 2. Compte dormant : pas de login depuis 120 jours ---
            Finding(
                finding_id="f-aws-002",
                cloud=Cloud.AWS,
                timestamp=now,
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
                    summary="Désactiver ce compte dormant. L'utilisateur ne "
                    "s'est pas connecté depuis 120 jours.",
                    code_fix=(
                        "aws iam delete-login-profile "
                        "--user-name old-contractor"
                    ),
                    risk_of_fix="low",
                    auto_remediable=True,
                ),
            ),
            # --- 3. Pas de MFA : utilisateur sans double authentification ---
            Finding(
                finding_id="f-aws-003",
                cloud=Cloud.AWS,
                timestamp=now,
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
                    summary="Activer l'authentification multi-facteur (MFA). "
                    "Sans MFA, le compte est vulnérable au vol de credentials.",
                    risk_of_fix="low",
                    auto_remediable=False,
                ),
            ),
            # --- 4. Clé d'accès ancienne : access key > 90 jours ---
            Finding(
                finding_id="f-aws-004",
                cloud=Cloud.AWS,
                timestamp=now,
                resource_type=ResourceType.ACCESS_KEY,
                resource_id="arn:aws:iam::123456789012:user/deploy-bot/access-key/AKIA1234567890ABCDEF",
                severity=Severity.MEDIUM,
                category=Category.OLD_ACCESS_KEY,
                description="Access key is 185 days old (threshold: 90 days)",
                affected_principals=["user/deploy-bot"],
                compliance_mapping=ComplianceMapping(
                    iso27001=["A.5.17"],
                    nist_csf=["PR.AC-1"],
                    soc2=["CC6.1", "CC6.6"],
                ),
                recommendation=Recommendation(
                    summary="Effectuer une rotation de cette clé d'accès. "
                    "Les clés de plus de 90 jours augmentent le risque.",
                    code_fix=(
                        "aws iam create-access-key --user-name deploy-bot && "
                        "aws iam delete-access-key --user-name deploy-bot "
                        "--access-key-id AKIA1234567890ABCDEF"
                    ),
                    risk_of_fix="medium",
                    auto_remediable=True,
                ),
            ),
            # --- 5. Permissions excessives : policy avec wildcard * ---
            Finding(
                finding_id="f-aws-005",
                cloud=Cloud.AWS,
                timestamp=now,
                resource_type=ResourceType.IAM_POLICY,
                resource_id="arn:aws:iam::123456789012:policy/LegacyFullAccess",
                severity=Severity.CRITICAL,
                category=Category.EXCESSIVE_PERMISSIONS,
                description=(
                    "Custom policy allows Action:* on Resource:* "
                    "(equivalent to admin access)"
                ),
                affected_principals=[
                    "role/legacy-app-role",
                    "user/qa-engineer",
                ],
                compliance_mapping=ComplianceMapping(
                    iso27001=["A.5.15", "A.5.18", "A.8.2"],
                    nist_csf=["PR.AC-4", "PR.AC-6"],
                    soc2=["CC6.1", "CC6.3"],
                ),
                recommendation=Recommendation(
                    summary="Remplacer cette policy wildcard par des permissions "
                    "spécifiques. Action:* Resource:* donne un accès total "
                    "identique à AdministratorAccess.",
                    code_fix=(
                        "aws iam create-policy-version "
                        "--policy-arn arn:aws:iam::123456789012:policy/LegacyFullAccess "
                        '--policy-document file://restricted-policy.json '
                        "--set-as-default"
                    ),
                    risk_of_fix="high",
                    auto_remediable=False,
                ),
            ),
            # --- 6. Escalade de privilèges : iam:PassRole sans restriction ---
            Finding(
                finding_id="f-aws-006",
                cloud=Cloud.AWS,
                timestamp=now,
                resource_type=ResourceType.IAM_ROLE,
                resource_id="arn:aws:iam::123456789012:role/DevOpsRole",
                severity=Severity.HIGH,
                category=Category.PRIVILEGE_ESCALATION,
                description=(
                    "Role can pass any IAM role to any service "
                    "(iam:PassRole on Resource:*), enabling privilege escalation"
                ),
                affected_principals=["user/devops-lead", "user/devops-jr"],
                compliance_mapping=ComplianceMapping(
                    iso27001=["A.5.15", "A.5.18"],
                    nist_csf=["PR.AC-4"],
                    soc2=["CC6.1", "CC6.3"],
                ),
                recommendation=Recommendation(
                    summary="Restreindre iam:PassRole à des rôles spécifiques. "
                    "Un PassRole sans restriction permet d'escalader "
                    "ses privilèges en s'attribuant n'importe quel rôle.",
                    code_fix=None,
                    terraform_fix=(
                        'resource "aws_iam_policy" "restricted_passrole" {\n'
                        '  statement {\n'
                        '    actions   = ["iam:PassRole"]\n'
                        '    resources = [\n'
                        '      "arn:aws:iam::123456789012:role/AllowedRole1",\n'
                        '      "arn:aws:iam::123456789012:role/AllowedRole2",\n'
                        '    ]\n'
                        '  }\n'
                        '}'
                    ),
                    risk_of_fix="medium",
                    auto_remediable=False,
                ),
            ),
            # --- 7. Credentials partagés : même access key sur plusieurs services ---
            Finding(
                finding_id="f-aws-007",
                cloud=Cloud.AWS,
                timestamp=now,
                resource_type=ResourceType.IAM_USER,
                resource_id="arn:aws:iam::123456789012:user/shared-ci-user",
                severity=Severity.MEDIUM,
                category=Category.SHARED_CREDENTIALS,
                description=(
                    "IAM user access key is used by 3 different CI/CD pipelines "
                    "(detected via CloudTrail source IP analysis)"
                ),
                affected_principals=[
                    "service/github-actions",
                    "service/jenkins",
                    "service/gitlab-ci",
                ],
                compliance_mapping=ComplianceMapping(
                    iso27001=["A.5.17", "A.5.18"],
                    nist_csf=["PR.AC-1", "PR.AC-3"],
                    soc2=["CC6.1", "CC6.2"],
                ),
                recommendation=Recommendation(
                    summary="Créer un utilisateur IAM dédié par service CI/CD. "
                    "Le partage de credentials empêche la traçabilité et "
                    "augmente le rayon d'impact en cas de compromission.",
                    code_fix=(
                        "aws iam create-user --user-name github-actions-ci && "
                        "aws iam create-user --user-name jenkins-ci && "
                        "aws iam create-user --user-name gitlab-ci"
                    ),
                    risk_of_fix="medium",
                    auto_remediable=False,
                ),
            ),
            # --- 8. Accès public : rôle avec trust policy ouverte ---
            Finding(
                finding_id="f-aws-008",
                cloud=Cloud.AWS,
                timestamp=now,
                resource_type=ResourceType.IAM_ROLE,
                resource_id="arn:aws:iam::123456789012:role/PublicLambdaRole",
                severity=Severity.CRITICAL,
                category=Category.PUBLIC_ACCESS,
                description=(
                    "Role trust policy allows assumption from any AWS account "
                    '(Principal: {"AWS": "*"})'
                ),
                affected_principals=["role/PublicLambdaRole"],
                compliance_mapping=ComplianceMapping(
                    iso27001=["A.5.15", "A.5.18", "A.8.2"],
                    nist_csf=["PR.AC-3", "PR.AC-4"],
                    soc2=["CC6.1", "CC6.6"],
                ),
                recommendation=Recommendation(
                    summary="Restreindre la trust policy à des comptes spécifiques. "
                    "Un Principal:* permet à n'importe quel compte AWS "
                    "d'assumer ce rôle.",
                    code_fix=(
                        "aws iam update-assume-role-policy "
                        "--role-name PublicLambdaRole "
                        "--policy-document file://restricted-trust-policy.json"
                    ),
                    risk_of_fix="low",
                    auto_remediable=False,
                ),
            ),
        ]


def main():
    """
    Point d'entrée CLI pour le scanner AWS.

    Exemples :
        python -m src.scanners.aws_scanner --mock
        python -m src.scanners.aws_scanner --mock --save
        python -m src.scanners.aws_scanner --mock --save --output data/scan_results.json
    """
    parser = argparse.ArgumentParser(
        description="IAMGuardian — Scanner IAM AWS",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Utiliser des données simulées (pas besoin de compte AWS)",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Sauvegarder les findings dans le stockage local",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./data/findings.json",
        help="Chemin du fichier de stockage (défaut: ./data/findings.json)",
    )
    args = parser.parse_args()

    # Vérifier qu'on a au moins --mock (Phase 4 : mode réel)
    if not args.mock:
        print("Erreur : le mode réel n'est pas encore implémenté (Phase 4).")
        print("Utilisez --mock pour lancer un scan avec des données simulées.")
        sys.exit(1)

    # Lancer le scan
    scanner = AwsScanner()
    print(f"Lancement du scan IAM AWS (mode mock)...")
    findings = scanner.scan()
    print(f"Scan terminé : {len(findings)} findings détectés.\n")

    # Afficher un résumé par sévérité
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    print("Résumé par sévérité :")
    for sev in ["critical", "high", "medium", "low"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"  {sev.upper():10s} : {count}")
    print()

    # Afficher chaque finding
    for f in findings:
        print(f"  [{f.severity.value.upper():8s}] {f.finding_id} — {f.description}")
        if f.recommendation:
            print(f"             → {f.recommendation.summary[:80]}")
        print()

    # Sauvegarder si demandé
    if args.save:
        storage = LocalStorage(file_path=args.output)
        storage.save_findings(findings)
        print(f"Findings sauvegardés dans {args.output}")
        print(f"Total en stockage : {storage.count()} findings")


if __name__ == "__main__":
    main()
