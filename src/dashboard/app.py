"""
Dashboard IAMGuardian — API FastAPI pour visualiser les findings.

Phase actuelle : squelette avec endpoints de base.
Phase 3 : implémentation complète avec pages HTML.

Lancer avec :
    cd iamguardian
    uvicorn src.dashboard.app:app --reload

Endpoints :
    GET /              → Page d'accueil (info API)
    GET /findings      → Liste tous les findings
    GET /findings/{id} → Détail d'un finding
    GET /stats         → Statistiques globales
    GET /compliance/{framework} → Score de conformité
"""

from fastapi import FastAPI, HTTPException

from src.analyzer.iam_analyzer import (
    compute_compliance_score,
    compute_stats,
    get_high_priority_findings,
)
from src.models.finding import Cloud, Finding, Severity
from src.storage.local_storage import LocalStorage

# --- Initialisation de l'application ---

app = FastAPI(
    title="IAMGuardian Dashboard",
    description="Audit et remédiation IAM multi-cloud",
    version="0.1.0",
)

# Stockage local (fichier JSON)
storage = LocalStorage("./data/findings.json")


# --- Endpoints ---

@app.get("/")
def root():
    """Page d'accueil — informations sur l'API."""
    return {
        "name": "IAMGuardian",
        "version": "0.1.0",
        "description": "Audit et remédiation IAM multi-cloud",
        "endpoints": [
            "GET /findings",
            "GET /findings/{finding_id}",
            "GET /stats",
            "GET /compliance/{framework}",
            "GET /priority",
        ],
    }


@app.get("/findings", response_model=list[Finding])
def list_findings(cloud: Cloud | None = None, severity: Severity | None = None):
    """
    Lister tous les findings.

    Filtres optionnels :
    - cloud : aws, azure, gcp
    - severity : low, medium, high, critical

    FastAPI valide automatiquement les valeurs (422 si invalide).
    """
    findings = storage.get_all_findings()

    if cloud:
        findings = [f for f in findings if f.cloud == cloud]
    if severity:
        findings = [f for f in findings if f.severity == severity]

    return findings


@app.get("/findings/{finding_id}", response_model=Finding)
def get_finding(finding_id: str):
    """Récupérer un finding par son identifiant."""
    finding = storage.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    return finding


@app.get("/stats")
def get_stats():
    """Statistiques globales des findings."""
    findings = storage.get_all_findings()
    return compute_stats(findings)


@app.get("/compliance/{framework}")
def get_compliance(framework: str):
    """
    Score de conformité par framework.

    Frameworks supportés : iso27001, nist_csf, soc2
    """
    if framework not in ("iso27001", "nist_csf", "soc2"):
        raise HTTPException(
            status_code=400,
            detail=f"Framework '{framework}' non supporté. Utilisez : iso27001, nist_csf, soc2",
        )
    findings = storage.get_all_findings()
    return compute_compliance_score(findings, framework)


@app.get("/priority", response_model=list[Finding])
def get_priority_findings():
    """Findings haute priorité (HIGH/CRITICAL) non remédiés."""
    findings = storage.get_all_findings()
    return get_high_priority_findings(findings)
