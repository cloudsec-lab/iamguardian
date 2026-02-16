"""
Modèle de données Finding — représente un problème IAM détecté.

Ce fichier définit la structure de données principale du projet IAMGuardian.
Chaque "finding" est un problème de sécurité IAM trouvé lors d'un scan
(ex: un rôle avec des permissions trop larges, un utilisateur sans MFA, etc.)

Le format est normalisé pour fonctionner avec les 3 clouds (AWS, Azure, GCP).
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# --- Énumérations (listes de valeurs possibles) ---

class Cloud(str, Enum):
    """Les 3 clouds supportés par IAMGuardian."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class Severity(str, Enum):
    """Niveau de gravité d'un finding, du plus bas au plus élevé."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    """Type de problème IAM détecté."""
    EXCESSIVE_PERMISSIONS = "excessive_permissions"    # Permissions trop larges
    DORMANT_ACCOUNT = "dormant_account"                # Compte inactif > 90 jours
    NO_MFA = "no_mfa"                                  # Pas d'authentification multi-facteur
    OLD_ACCESS_KEY = "old_access_key"                  # Clé d'accès > 90 jours
    PUBLIC_ACCESS = "public_access"                    # Ressource exposée publiquement
    PRIVILEGE_ESCALATION = "privilege_escalation"      # Possibilité d'escalade de privilèges
    SHARED_CREDENTIALS = "shared_credentials"          # Credentials partagés entre services


class ResourceType(str, Enum):
    """Type de ressource IAM concernée."""
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    IAM_GROUP = "iam_group"
    SERVICE_ACCOUNT = "service_account"    # GCP
    SERVICE_PRINCIPAL = "service_principal"  # Azure
    ACCESS_KEY = "access_key"


# --- Sous-modèles ---

class ComplianceMapping(BaseModel):
    """
    Mapping vers les frameworks de conformité.

    Chaque finding est lié à des contrôles spécifiques dans les frameworks
    ISO 27001, NIST CSF et SOC2. Cela permet de générer des rapports
    de conformité automatiquement.
    """
    iso27001: list[str] = Field(
        default_factory=list,
        description="Contrôles ISO 27001:2022 (ex: A.5.15, A.5.18)",
    )
    nist_csf: list[str] = Field(
        default_factory=list,
        description="Fonctions NIST CSF 2.0 (ex: PR.AC-4, PR.AC-6)",
    )
    soc2: list[str] = Field(
        default_factory=list,
        description="Critères SOC2 (ex: CC6.1, CC6.3)",
    )


class Recommendation(BaseModel):
    """
    Recommandation de remédiation pour un finding.

    Générée par l'analyseur (et enrichie par Gemini API en Phase 5).
    Contient le résumé du problème et le code pour le corriger.
    """
    summary: str = Field(
        description="Résumé de la recommandation en français",
    )
    code_fix: Optional[str] = Field(
        default=None,
        description="Commande CLI pour corriger (aws cli, az, gcloud)",
    )
    terraform_fix: Optional[str] = Field(
        default=None,
        description="Code Terraform pour corriger",
    )
    risk_of_fix: str = Field(
        default="medium",
        description="Risque lié à l'application du fix (low/medium/high)",
    )
    auto_remediable: bool = Field(
        default=False,
        description="True si le fix peut être appliqué automatiquement",
    )


# --- Modèle principal ---

class Finding(BaseModel):
    """
    Un finding IAM — problème de sécurité détecté lors d'un scan.

    C'est l'objet central du projet IAMGuardian. Il est créé par les scanners,
    enrichi par l'analyseur IA, et affiché dans le dashboard.

    Exemple :
        finding = Finding(
            finding_id="f-aws-001",
            cloud=Cloud.AWS,
            resource_type=ResourceType.IAM_ROLE,
            resource_id="arn:aws:iam::123456789:role/AdminRole",
            severity=Severity.HIGH,
            category=Category.EXCESSIVE_PERMISSIONS,
            description="Role has AdministratorAccess policy attached",
        )
    """
    finding_id: str = Field(
        description="Identifiant unique (ex: f-aws-001, f-azure-003)",
    )
    cloud: Cloud = Field(
        description="Cloud source (aws, azure, gcp)",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Date/heure de détection",
    )
    resource_type: ResourceType = Field(
        description="Type de ressource IAM concernée",
    )
    resource_id: str = Field(
        description="Identifiant de la ressource (ARN AWS, ID Azure, path GCP)",
    )
    severity: Severity = Field(
        description="Niveau de gravité (low, medium, high, critical)",
    )
    category: Category = Field(
        description="Catégorie du problème détecté",
    )
    description: str = Field(
        description="Description du problème en anglais",
    )
    affected_principals: list[str] = Field(
        default_factory=list,
        description="Utilisateurs/rôles affectés par ce problème",
    )
    compliance_mapping: ComplianceMapping = Field(
        default_factory=ComplianceMapping,
        description="Mapping vers ISO 27001, NIST CSF, SOC2",
    )
    recommendation: Optional[Recommendation] = Field(
        default=None,
        description="Recommandation de remédiation (ajoutée par l'analyseur)",
    )
    remediated: bool = Field(
        default=False,
        description="True si le problème a été corrigé",
    )
    remediated_at: Optional[datetime] = Field(
        default=None,
        description="Date de remédiation",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "finding_id": "f-aws-001",
                    "cloud": "aws",
                    "timestamp": "2025-01-15T06:00:00Z",
                    "resource_type": "iam_role",
                    "resource_id": "arn:aws:iam::123456789:role/AdminRole",
                    "severity": "high",
                    "category": "excessive_permissions",
                    "description": "Role has AdministratorAccess policy attached",
                    "affected_principals": ["user/dev-user-1", "user/dev-user-2"],
                    "compliance_mapping": {
                        "iso27001": ["A.5.15", "A.5.18"],
                        "nist_csf": ["PR.AC-4", "PR.AC-6"],
                        "soc2": ["CC6.1", "CC6.3"],
                    },
                    "recommendation": {
                        "summary": "Réduire les permissions au minimum nécessaire",
                        "code_fix": "aws iam detach-role-policy --role-name AdminRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                        "terraform_fix": "# Voir PR #123",
                        "risk_of_fix": "low",
                        "auto_remediable": False,
                    },
                    "remediated": False,
                }
            ]
        }
    }
