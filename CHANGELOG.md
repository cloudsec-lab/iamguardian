# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

---

## [Unreleased]

### En cours
- Phase 3 : Dashboard FastAPI avec pages HTML

---

## [0.2.0] - 2026-02-18

### Ajouté
- Scanner AWS mock complet : 8 findings couvrant les 7 catégories
  - Permissions excessives (AdminRole + policy wildcard *)
  - Compte dormant (120 jours sans login)
  - Utilisateur sans MFA
  - Access key ancienne (185 jours)
  - Escalade de privilèges (iam:PassRole sans restriction)
  - Credentials partagés (même clé sur 3 pipelines CI/CD)
  - Accès public (trust policy ouverte Principal:*)
- CLI avec argparse : `python -m src.scanners.aws_scanner --mock [--save] [--output]`
- `__main__.py` pour exécution via `python -m src.scanners`
- Résumé par sévérité dans la sortie CLI
- 28 tests unitaires scanner AWS (basics, categories, severities, compliance, storage, CLI)

### Amélioré
- `LocalStorage._save` : suppression double sérialisation (`model_dump(mode="json")` au lieu de `json.loads(model_dump_json())`)
- Dashboard `/findings` : filtres `cloud` et `severity` utilisent les enums `Cloud` et `Severity` pour validation automatique FastAPI (422 si valeur invalide)

### Stats
- 51 tests unitaires passants (modèles: 10, stockage: 13, scanner: 28)

---

## [0.1.0] - 2026-02-16

### Ajouté
- Modèle de données `Finding` (Pydantic) avec validation
  - Enums : Cloud (aws/azure/gcp), Severity, Category, ResourceType
  - ComplianceMapping : ISO 27001, NIST CSF, SOC2
  - Recommendation : summary, code_fix, terraform_fix, risk_of_fix
- Stockage local JSON (`LocalStorage`)
  - CRUD complet : save, get, list, delete
  - Filtrage par sévérité et par cloud
  - Marquage de remédiation avec timestamp
- Scanner AWS mock avec 3 findings réalistes
  - Permissions excessives (AdminRole)
  - Compte dormant (120 jours)
  - Utilisateur sans MFA
- Squelettes scanners Azure et GCP
- Analyseur IAM
  - Statistiques par sévérité, cloud, catégorie
  - Score de conformité par framework
  - Détection des findings haute priorité
- Dashboard FastAPI (squelette)
  - `GET /findings` avec filtres cloud/severity
  - `GET /findings/{id}` détail
  - `GET /stats` statistiques globales
  - `GET /compliance/{framework}` score conformité
  - `GET /priority` findings HIGH/CRITICAL
- 23 tests unitaires (modèles + stockage)
- 5 findings d'exemple dans `sample_findings.json`
- Documentation architecture (4 diagrammes Mermaid)
- Squelettes Terraform (providers, variables, outputs)
- README bilingue FR/EN
