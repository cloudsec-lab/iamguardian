"""
Stockage local des findings en fichier JSON.

Cette implémentation sauvegarde les findings dans un fichier JSON sur le disque.
C'est le stockage utilisé pendant les phases 0 à 3 (développement local).
Plus tard, on migrera vers Firestore (GCP) en créant une classe FirestoreStorage
qui hérite aussi de BaseStorage.

Utilisation :
    storage = LocalStorage("./data/findings.json")
    storage.save_finding(my_finding)
    all_findings = storage.get_all_findings()
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from src.models.finding import Cloud, Finding, Severity
from src.storage.base_storage import BaseStorage


class LocalStorage(BaseStorage):
    """
    Stockage des findings dans un fichier JSON local.

    Le fichier est lu/écrit à chaque opération. Ce n'est pas performant
    pour des milliers de findings, mais c'est parfait pour le développement
    et les tests (on attend < 100 findings en dev).
    """

    def __init__(self, file_path: str = "./data/findings.json"):
        """
        Initialiser le stockage local.

        Args:
            file_path: Chemin vers le fichier JSON (créé s'il n'existe pas)
        """
        self._file_path = Path(file_path)
        # Créer le dossier parent s'il n'existe pas
        self._file_path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> list[Finding]:
        """Lire tous les findings depuis le fichier JSON."""
        if not self._file_path.exists():
            return []
        content = self._file_path.read_text(encoding="utf-8")
        if not content.strip():
            return []
        raw_list = json.loads(content)
        return [Finding.model_validate(item) for item in raw_list]

    def _save(self, findings: list[Finding]) -> None:
        """Écrire tous les findings dans le fichier JSON."""
        data = [f.model_dump(mode="json") for f in findings]
        self._file_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def save_finding(self, finding: Finding) -> None:
        """Ajouter un finding (ou le remplacer s'il existe déjà)."""
        findings = self._load()
        # Remplacer si un finding avec le même ID existe déjà
        findings = [f for f in findings if f.finding_id != finding.finding_id]
        findings.append(finding)
        self._save(findings)

    def save_findings(self, new_findings: list[Finding]) -> None:
        """Ajouter plusieurs findings d'un coup."""
        existing = self._load()
        # Créer un dict des existants pour remplacement rapide
        existing_dict = {f.finding_id: f for f in existing}
        for finding in new_findings:
            existing_dict[finding.finding_id] = finding
        self._save(list(existing_dict.values()))

    def get_finding(self, finding_id: str) -> Finding | None:
        """Récupérer un finding par son ID."""
        for finding in self._load():
            if finding.finding_id == finding_id:
                return finding
        return None

    def get_all_findings(self) -> list[Finding]:
        """Récupérer tous les findings."""
        return self._load()

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Filtrer par gravité (low, medium, high, critical)."""
        return [f for f in self._load() if f.severity == severity]

    def get_findings_by_cloud(self, cloud: Cloud) -> list[Finding]:
        """Filtrer par cloud (aws, azure, gcp)."""
        return [f for f in self._load() if f.cloud == cloud]

    def mark_as_remediated(self, finding_id: str) -> bool:
        """Marquer un finding comme corrigé."""
        findings = self._load()
        for finding in findings:
            if finding.finding_id == finding_id:
                finding.remediated = True
                finding.remediated_at = datetime.now(UTC)
                self._save(findings)
                return True
        return False

    def delete_finding(self, finding_id: str) -> bool:
        """Supprimer un finding par son ID."""
        findings = self._load()
        new_findings = [f for f in findings if f.finding_id != finding_id]
        if len(new_findings) == len(findings):
            return False  # Pas trouvé
        self._save(new_findings)
        return True

    def count(self) -> int:
        """Nombre total de findings stockés."""
        return len(self._load())
