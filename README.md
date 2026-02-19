# Lab 1 — IAMGuardian

> **Audit et remédiation automatisée des permissions IAM multi-cloud**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Terraform](https://img.shields.io/badge/Terraform-1.5+-purple.svg)](https://terraform.io)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](../LICENSE)

---

## Description

IAMGuardian analyse en continu les politiques IAM/RBAC des trois clouds (AWS, Azure, GCP) pour détecter les permissions excessives, les comptes dormants et les violations du principe de moindre privilège.

Le système :
1. **Scanne** les permissions IAM des 3 clouds
2. **Analyse** et détecte les violations de sécurité
3. **Enrichit** les résultats avec des recommandations IA (Gemini API)
4. **Remédie** automatiquement les problèmes "safe" ou crée des PRs
5. **Génère** des rapports de conformité (ISO 27001, NIST CSF, SOC2)

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  IAMGuardian                      │
├─────────────────────────────────────────────────┤
│                                                   │
│   [AWS IAM]  [Azure Entra ID]  [GCP IAM]        │
│       │            │              │               │
│       └────────────┼──────────────┘               │
│                    ▼                              │
│           [Orchestrateur]                         │
│                    │                              │
│                    ▼                              │
│           [Analyseur + IA]                        │
│                    │                              │
│            ┌───────┴───────┐                     │
│            ▼               ▼                      │
│     [Stockage]     [Remédiation]                 │
│            │                                      │
│            ▼                                      │
│      [Dashboard]                                  │
└─────────────────────────────────────────────────┘
```

Voir [docs/architecture.md](docs/architecture.md) pour le diagramme Mermaid détaillé.

## Quick Start

```bash
# 1. Cloner et entrer dans le dossier
cd iamguardian

# 2. Créer un environnement virtuel Python
python -m venv venv
source venv/bin/activate  # Linux/Mac

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Lancer les tests
pytest tests/ -v

# 5. Générer des données de test
python -m src.scanners.aws_scanner --mock --save

# 6. Lancer le dashboard → http://localhost:8000
uvicorn src.dashboard.app:app --reload
```

## Structure du projet

```
iamguardian/
├── src/
│   ├── models/          # Modèle de données Finding
│   ├── scanners/        # Scanners IAM (AWS, Azure, GCP)
│   ├── analyzer/        # Analyse et statistiques
│   ├── storage/         # Stockage (local JSON → Firestore)
│   └── dashboard/       # Dashboard web + API JSON
│       ├── templates/   # Pages HTML (Jinja2)
│       └── static/css/  # Styles CSS
├── tests/               # Tests unitaires (pytest)
├── data/                # Données de test
├── docs/                # Documentation et diagrammes
└── infrastructure/      # Terraform (déploiement cloud)
```

## Frameworks de conformité

| Framework | Contrôles couverts |
|-----------|-------------------|
| ISO 27001:2022 | A.5.15, A.5.16, A.5.17, A.5.18, A.8.2 |
| NIST CSF 2.0 | PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-6, PR.AC-7 |
| SOC2 | CC6.1, CC6.2, CC6.3, CC6.6 |

## Statut

- [x] Phase 0 — Structure du projet
- [x] Phase 1 — Modèle de données + stockage local
- [x] Phase 2 — Scanner AWS (mode mock) — 8 findings, CLI, 51 tests
- [x] Phase 3 — Dashboard FastAPI local — Jinja2, filtres, conformité, 78 tests
- [ ] Phase 4 — Scanner AWS réel (boto3)
- [ ] Phase 5 — Analyseur IA (Gemini API)
- [ ] Phase 6 — Scanner Azure
- [ ] Phase 7 — Scanner GCP
- [ ] Phase 8-12 — Remédiation, Terraform, CI/CD, Rapports

## Documentation

- [Architecture](docs/architecture.md) — Diagrammes Mermaid
- [Backlog](docs/BACKLOG.md) — Suivi des phases et tâches
- [Decisions](docs/DECISIONS.md) — Journal des décisions techniques
- [Changelog](CHANGELOG.md) — Historique des changements

## Licence

Code sous [Apache License 2.0](LICENSE) — Contenu sous [CC BY-NC-SA 4.0](LICENSE-CONTENT)

---

# Lab 1 — IAMGuardian (English)

> **Automated IAM permission audit and remediation across multi-cloud**

IAMGuardian continuously scans IAM/RBAC policies across AWS, Azure and GCP to detect excessive permissions, dormant accounts, and least privilege violations.

See the French section above for full documentation. English README will be completed in Phase 12.
