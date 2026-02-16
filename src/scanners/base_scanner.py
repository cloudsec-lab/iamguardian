"""
Classe abstraite BaseScanner — contrat pour tous les scanners IAM.

Chaque scanner (AWS, Azure, GCP) hérite de cette classe et implémente
la méthode scan() qui retourne une liste de findings.

Cela garantit que tous les scanners fonctionnent de la même façon,
ce qui simplifie l'orchestrateur qui les appelle.
"""

from abc import ABC, abstractmethod

from src.models.finding import Finding


class BaseScanner(ABC):
    """
    Classe de base pour les scanners IAM.

    Chaque scanner doit implémenter :
    - scan() : exécuter le scan et retourner les findings
    - cloud_name : propriété indiquant le cloud scanné
    """

    @property
    @abstractmethod
    def cloud_name(self) -> str:
        """Nom du cloud scanné (aws, azure, gcp)."""
        ...

    @abstractmethod
    def scan(self) -> list[Finding]:
        """
        Exécuter le scan IAM et retourner les findings détectés.

        Returns:
            Liste de Finding normalisés
        """
        ...
