# IAMGuardian — Backlog

> Dernière mise à jour : 2026-02-18

---

## Sprint actuel : Phase 2 — Scanner AWS mock

**Objectif** : Scanner AWS complet avec CLI et données mockées réalistes.

| Item | Statut | Notes |
|------|--------|-------|
| CLI `python -m src.scanners.aws_scanner --mock` | A faire | Exécutable en ligne de commande |
| Enrichir les findings mockés (plus de scénarios) | A faire | Ajouter : privilege escalation, public access |
| Sauvegarder les findings dans LocalStorage | A faire | Intégration scanner → stockage |
| Tests unitaires du scanner AWS | A faire | |

---

## Completed

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

### Phase 2 — Scanner AWS mock complet
- [ ] CLI exécutable avec argparse
- [ ] Scénarios mockés enrichis (7+ types de findings)
- [ ] Intégration scanner → stockage automatique
- [ ] Tests unitaires scanner

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
