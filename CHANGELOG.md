# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

---

## [Unreleased]

### En cours
- Phase 2 : Scanner AWS mock complet avec CLI

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
