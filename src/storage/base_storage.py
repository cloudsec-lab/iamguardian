"""
Interface abstraite pour le stockage des findings.

Ce fichier définit le "contrat" que tout système de stockage doit respecter.
Aujourd'hui on utilise LocalStorage (fichier JSON), plus tard on migrera
vers Firestore (GCP) sans changer le reste du code.

C'est le principe d'abstraction : le code qui utilise le stockage n'a pas
besoin de savoir si les données sont dans un fichier ou dans le cloud.
"""

from abc import ABC, abstractmethod

from src.models.finding import Finding, Severity, Cloud


class BaseStorage(ABC):
    """
    Classe abstraite — définit les méthodes que tout stockage doit avoir.

    ABC = Abstract Base Class. On ne peut pas créer un objet BaseStorage
    directement, il faut créer une sous-classe (ex: LocalStorage) qui
    implémente toutes les méthodes marquées @abstractmethod.
    """

    @abstractmethod
    def save_finding(self, finding: Finding) -> None:
        """Sauvegarder un finding."""
        ...

    @abstractmethod
    def save_findings(self, findings: list[Finding]) -> None:
        """Sauvegarder plusieurs findings d'un coup."""
        ...

    @abstractmethod
    def get_finding(self, finding_id: str) -> Finding | None:
        """Récupérer un finding par son identifiant. Retourne None si introuvable."""
        ...

    @abstractmethod
    def get_all_findings(self) -> list[Finding]:
        """Récupérer tous les findings."""
        ...

    @abstractmethod
    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Filtrer les findings par niveau de gravité."""
        ...

    @abstractmethod
    def get_findings_by_cloud(self, cloud: Cloud) -> list[Finding]:
        """Filtrer les findings par cloud (aws, azure, gcp)."""
        ...

    @abstractmethod
    def mark_as_remediated(self, finding_id: str) -> bool:
        """
        Marquer un finding comme corrigé.
        Retourne True si le finding a été trouvé et mis à jour, False sinon.
        """
        ...

    @abstractmethod
    def delete_finding(self, finding_id: str) -> bool:
        """Supprimer un finding. Retourne True si trouvé et supprimé."""
        ...

    @abstractmethod
    def count(self) -> int:
        """Retourner le nombre total de findings."""
        ...
