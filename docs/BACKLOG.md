# IAMGuardian — Backlog

> Dernière mise à jour : 2026-02-18

---

## Sprint actuel : Phase 3 — Dashboard FastAPI local

**Objectif** : Visualiser les findings dans un navigateur avec pages HTML.

| Item | Statut | Notes |
|------|--------|-------|
| Pages HTML avec Jinja2 | A faire | Templates pour liste, détail, stats |
| Filtres interactifs (cloud, sévérité) | A faire | Déjà validés par enum côté API |
| Vue détaillée d'un finding | A faire | Page HTML avec recommandation |
| Vue conformité par framework | A faire | Score + liste des contrôles |

---

## Completed

### Phase 2 — Scanner AWS mock complet (2026-02-18)

- [x] CLI `python -m src.scanners.aws_scanner --mock` avec argparse
- [x] 8 findings mockés couvrant les 7 catégories
- [x] Intégration scanner → LocalStorage (`--save` flag)
- [x] 28 tests unitaires scanner (basics, categories, severities, compliance, storage, CLI)
- [x] `__main__.py` pour `python -m src.scanners`
- [x] Résumé par sévérité dans la sortie CLI
- [x] Review code : fix double sérialisation LocalStorage (`model_dump(mode="json")`)
- [x] Review code : filtres dashboard avec validation enum (Cloud, Severity)
- [x] 51 tests unitaires passants au total

### Phase 0 — Structure du projet (2026-02-16)

- [x] Arborescence du projet créée
- [x] `requirements.txt` + `.env.example`
- [x] Modèle Finding Pydantic avec enums (Cloud, Severity, Category, ResourceType)
- [x] ComplianceMapping (ISO 27001, NIST CSF, SOC2)
- [x] Recommendation model
- [x] LocalStorage (JSON) : CRUD + filtrage par sévérité/cloud
- [x] BaseScanner (interface abstraite)
- [x] AwsScanner avec mode mock (3 findings réalistes)
- [x] AzureScanner + GcpScanner (squelettes)
- [x] IAM Analyzer : stats, scoring conformité, findings prioritaires
- [x] Dashboard FastAPI : endpoints /findings, /stats, /compliance, /priority
- [x] 23 tests unitaires passants (modèles + stockage)
- [x] sample_findings.json (5 findings : 3 AWS, 1 Azure, 1 GCP)
- [x] Architecture Mermaid (4 diagrammes)
- [x] Terraform squelettes (main, variables, outputs)
- [x] README bilingue FR/EN
- [x] Repo GitHub public : cloudsec-lab/iamguardian

### Phase 1 — Modèle de données + stockage local (2026-02-16)

- [x] Intégré dans Phase 0 (Finding, LocalStorage, tests — tout fonctionnel)

---

## Backlog futur

### Phase 3 — Dashboard FastAPI local
- [ ] Pages HTML avec Jinja2 (pas juste du JSON)
- [ ] Filtres interactifs (cloud, sévérité)
- [ ] Vue détaillée d'un finding
- [ ] Vue conformité par framework

### Phase 4 — Scanner AWS réel (boto3)
- [ ] Compte AWS créé + MFA + alertes budget
- [ ] AWS CLI configuré
- [ ] Vrais appels boto3 : list_users, list_roles, list_policies
- [ ] IAM Access Analyzer API
- [ ] Détection : users sans MFA, access keys > 90j, rôles admin

### Phase 5 — Analyseur IA (Gemini API)
- [ ] Intégration Gemini API
- [ ] Prompt engineering pour recommandations
- [ ] Enrichissement automatique des findings HIGH/CRITICAL

### Phase 6 — Scanner Azure
- [ ] azure-identity + azure-mgmt-authorization
- [ ] Détection RBAC excessif, service principals Owner

### Phase 7 — Scanner GCP
- [ ] google-cloud-iam + google-cloud-recommender
- [ ] Détection service accounts editor/owner, clés anciennes

### Phase 8 — Remédiation automatique
- [ ] Auto-fix pour findings low/medium auto_remediable
- [ ] Création de PRs GitHub pour findings sensibles

### Phase 9 — Infrastructure Terraform
- [ ] Déploiement Lambda, Firestore, Cloud Run

### Phase 10 — CI/CD GitHub Actions
- [ ] Pipeline : lint, test, security scan, terraform plan/apply

### Phase 11 — Rapports de conformité PDF
- [ ] Génération PDF avec reportlab/weasyprint
- [ ] Format professionnel pour auditeurs

### Phase 12 — Documentation finale
- [ ] README complet bilingue
- [ ] Captures d'écran annotées
- [ ] Diagrammes finaux
- [ ] Section "Défis rencontrés et solutions"
