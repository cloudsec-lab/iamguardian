"""
Scanner IAM GCP — détecte les problèmes de permissions sur Google Cloud.

Phase actuelle : squelette (pas encore implémenté).
Phase 7 : connexion réelle via google-cloud-iam.

Problèmes à détecter :
- Service accounts avec roles/owner ou roles/editor
- Clés de service account de plus de 90 jours
- Recommandations IAM Recommender non appliquées
"""

from src.models.finding import Finding
from src.scanners.base_scanner import BaseScanner


class GcpScanner(BaseScanner):
    """Scanner IAM pour Google Cloud Platform."""

    @property
    def cloud_name(self) -> str:
        return "gcp"

    def scan(self) -> list[Finding]:
        """
        Scanner les permissions IAM GCP.

        TODO Phase 7 : Implémenter avec google-cloud-iam et google-cloud-recommender.
        """
        # Retourne une liste vide pour l'instant
        return []
