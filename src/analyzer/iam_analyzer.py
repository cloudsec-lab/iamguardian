"""
Analyseur IAM — analyse les findings et génère des statistiques.

Phase actuelle : analyse locale (comptage, filtrage, stats).
Phase 5 : enrichissement via Gemini API pour générer des recommandations IA.

L'analyseur prend les findings bruts des scanners et produit :
- Des statistiques par sévérité, cloud, catégorie
- Un score de conformité par framework
- (Phase 5) Des recommandations de remédiation enrichies par IA
"""

from collections import Counter

from src.models.finding import Cloud, Finding, Severity


def compute_stats(findings: list[Finding]) -> dict:
    """
    Calculer les statistiques à partir d'une liste de findings.

    Args:
        findings: Liste de findings à analyser

    Returns:
        Dictionnaire avec les stats (par sévérité, cloud, catégorie, etc.)
    """
    if not findings:
        return {
            "total": 0,
            "by_severity": {},
            "by_cloud": {},
            "by_category": {},
            "remediated": 0,
            "pending": 0,
        }

    by_severity = Counter(f.severity.value for f in findings)
    by_cloud = Counter(f.cloud.value for f in findings)
    by_category = Counter(f.category.value for f in findings)
    remediated = sum(1 for f in findings if f.remediated)

    return {
        "total": len(findings),
        "by_severity": dict(by_severity),
        "by_cloud": dict(by_cloud),
        "by_category": dict(by_category),
        "remediated": remediated,
        "pending": len(findings) - remediated,
    }


def compute_compliance_score(findings: list[Finding], framework: str) -> dict:
    """
    Calculer un score de conformité pour un framework donné.

    Le score est simple : % de findings remédiés parmi ceux qui
    correspondent au framework demandé.

    Args:
        findings: Liste de findings
        framework: "iso27001", "nist_csf" ou "soc2"

    Returns:
        Dict avec les contrôles couverts et leur statut
    """
    controls: dict[str, dict] = {}

    for finding in findings:
        # Récupérer les contrôles du framework demandé
        mapping = finding.compliance_mapping
        if framework == "iso27001":
            control_list = mapping.iso27001
        elif framework == "nist_csf":
            control_list = mapping.nist_csf
        elif framework == "soc2":
            control_list = mapping.soc2
        else:
            continue

        for control in control_list:
            if control not in controls:
                controls[control] = {"total": 0, "remediated": 0, "findings": []}
            controls[control]["total"] += 1
            if finding.remediated:
                controls[control]["remediated"] += 1
            controls[control]["findings"].append(finding.finding_id)

    # Calculer le score global
    total_issues = sum(c["total"] for c in controls.values())
    total_remediated = sum(c["remediated"] for c in controls.values())
    score = (total_remediated / total_issues * 100) if total_issues > 0 else 100.0

    return {
        "framework": framework,
        "score": round(score, 1),
        "controls": controls,
        "total_issues": total_issues,
        "total_remediated": total_remediated,
    }


def get_high_priority_findings(findings: list[Finding]) -> list[Finding]:
    """
    Retourner les findings haute priorité (HIGH et CRITICAL) non remédiés.

    Ce sont les findings qui nécessitent une action immédiate.
    """
    return [
        f for f in findings
        if f.severity in (Severity.HIGH, Severity.CRITICAL) and not f.remediated
    ]
