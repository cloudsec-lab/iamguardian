"""
Dashboard IAMGuardian — Interface web + API JSON.

Interface web (navigateur) :
    GET /              → Dashboard (vue d'ensemble)
    GET /findings      → Liste des findings avec filtres
    GET /findings/{id} → Détail d'un finding
    GET /stats         → Statistiques
    GET /compliance/{framework} → Score de conformité

API JSON (programmation) :
    GET /api/findings      → Liste des findings
    GET /api/findings/{id} → Détail d'un finding
    GET /api/stats         → Statistiques
    GET /api/compliance/{framework} → Score conformité
    GET /api/priority      → Findings prioritaires

Lancer avec :
    cd iamguardian
    uvicorn src.dashboard.app:app --reload
"""

from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.analyzer.iam_analyzer import (
    compute_compliance_score,
    compute_stats,
    get_high_priority_findings,
)
from src.models.finding import Cloud, Finding, Severity
from src.storage.local_storage import LocalStorage


# --- Configuration ---

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="IAMGuardian Dashboard",
    description="Audit et remédiation IAM multi-cloud",
    version="0.2.0",
)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

storage = LocalStorage("./data/findings.json")


# --- Labels pour les templates ---

SEVERITY_LABELS = {
    "low": "Bas",
    "medium": "Moyen",
    "high": "Élevé",
    "critical": "Critique",
}

CATEGORY_LABELS = {
    "excessive_permissions": "Permissions excessives",
    "dormant_account": "Compte dormant",
    "no_mfa": "Pas de MFA",
    "old_access_key": "Clé d'accès ancienne",
    "public_access": "Accès public",
    "privilege_escalation": "Escalade de privilèges",
    "shared_credentials": "Credentials partagés",
}

FRAMEWORK_LABELS = {
    "iso27001": "ISO 27001:2022",
    "nist_csf": "NIST CSF 2.0",
    "soc2": "SOC 2",
}

templates.env.globals["severity_labels"] = SEVERITY_LABELS
templates.env.globals["category_labels"] = CATEGORY_LABELS
templates.env.globals["framework_labels"] = FRAMEWORK_LABELS


def _format_dt(value: datetime | str) -> str:
    """Filtre Jinja2 pour formater les dates."""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    if isinstance(value, str):
        return value[:16].replace("T", " ")
    return str(value)


templates.env.filters["format_dt"] = _format_dt

VALID_FRAMEWORKS = ("iso27001", "nist_csf", "soc2")


# --- Pages HTML (navigateur) ---


@app.get("/", response_class=HTMLResponse)
def page_home(request: Request):
    """Dashboard — vue d'ensemble."""
    findings = storage.get_all_findings()
    stats = compute_stats(findings)
    priority = get_high_priority_findings(findings)
    return templates.TemplateResponse(request, "index.html", {
        "stats": stats,
        "priority": priority[:5],
        "findings_count": len(findings),
    })


@app.get("/findings", response_class=HTMLResponse)
def page_findings(
    request: Request,
    cloud: str | None = None,
    severity: str | None = None,
):
    """Liste des findings avec filtres."""
    findings = storage.get_all_findings()
    if cloud:
        findings = [f for f in findings if f.cloud.value == cloud]
    if severity:
        findings = [f for f in findings if f.severity.value == severity]
    return templates.TemplateResponse(request, "findings.html", {
        "findings": findings,
        "active_cloud": cloud,
        "active_severity": severity,
        "clouds": [c.value for c in Cloud],
        "severities": [s.value for s in Severity],
    })


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
def page_finding_detail(request: Request, finding_id: str):
    """Détail d'un finding."""
    finding = storage.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    return templates.TemplateResponse(request, "finding_detail.html", {
        "finding": finding,
    })


@app.get("/stats", response_class=HTMLResponse)
def page_stats(request: Request):
    """Statistiques."""
    findings = storage.get_all_findings()
    stats = compute_stats(findings)
    return templates.TemplateResponse(request, "stats.html", {
        "stats": stats,
    })


@app.get("/compliance/{framework}", response_class=HTMLResponse)
def page_compliance(request: Request, framework: str):
    """Score de conformité par framework."""
    if framework not in VALID_FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Framework '{framework}' non supporté.",
        )
    findings = storage.get_all_findings()
    compliance = compute_compliance_score(findings, framework)
    return templates.TemplateResponse(request, "compliance.html", {
        "compliance": compliance,
        "framework": framework,
        "frameworks": ["iso27001", "nist_csf", "soc2"],
    })


# --- API JSON (programmation) ---


@app.get("/api/findings", response_model=list[Finding])
def api_list_findings(
    cloud: Cloud | None = None,
    severity: Severity | None = None,
):
    """API : lister les findings avec filtres enum (422 si invalide)."""
    findings = storage.get_all_findings()
    if cloud:
        findings = [f for f in findings if f.cloud == cloud]
    if severity:
        findings = [f for f in findings if f.severity == severity]
    return findings


@app.get("/api/findings/{finding_id}", response_model=Finding)
def api_get_finding(finding_id: str):
    """API : récupérer un finding par ID."""
    finding = storage.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    return finding


@app.get("/api/stats")
def api_get_stats():
    """API : statistiques globales."""
    findings = storage.get_all_findings()
    return compute_stats(findings)


@app.get("/api/compliance/{framework}")
def api_get_compliance(framework: str):
    """API : score de conformité."""
    if framework not in VALID_FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Framework '{framework}' non supporté.",
        )
    findings = storage.get_all_findings()
    return compute_compliance_score(findings, framework)


@app.get("/api/priority", response_model=list[Finding])
def api_get_priority():
    """API : findings haute priorité (HIGH/CRITICAL non remédiés)."""
    findings = storage.get_all_findings()
    return get_high_priority_findings(findings)
