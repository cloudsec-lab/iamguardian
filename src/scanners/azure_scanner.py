"""
Scanner IAM Azure — détecte les problèmes de permissions sur Azure.

Phase actuelle : squelette (pas encore implémenté).
Phase 6 : connexion réelle via azure-identity + azure-mgmt-authorization.

Problèmes à détecter :
- Service principals avec rôle Owner/Contributor au scope subscription
- Comptes sans MFA (via Microsoft Graph API)
- Role assignments excessifs
"""

from src.models.finding import Finding
from src.scanners.base_scanner import BaseScanner


class AzureScanner(BaseScanner):
    """Scanner IAM pour Microsoft Azure."""

    @property
    def cloud_name(self) -> str:
        return "azure"

    def scan(self) -> list[Finding]:
        """
        Scanner les permissions IAM Azure.

        TODO Phase 6 : Implémenter avec azure-identity et azure-mgmt-authorization.
        """
        # Retourne une liste vide pour l'instant
        return []
