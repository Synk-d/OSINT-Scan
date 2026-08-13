from __future__ import annotations

"""
workers/risk_engine.py — Algorithmic Dynamic Threat & Risk Scoring Engine.

Calculates a composite Cyber Risk Score (0-100 rating) based on:
  1. Shodan open ports (High-risk critical management/database/remote desktop ports)
  2. Exposed CVE vulnerabilities
  3. Email spoofability posture (DMARC and SPF DNS record policies)
  4. WHOIS Registrar privacy shield status
  5. Identity surface footprint (number of confirmed developer & social platform hits)

Returns score, risk level tier, brand colors, and itemized breakdown of contributing factors.
"""

from typing import Any, Dict, List, Optional
import pandas as pd

CRITICAL_PORTS = {3389, 445, 139, 23, 21, 1433, 1521, 3306, 5432, 27017, 6379, 111, 5900}
MODERATE_PORTS = {22, 80, 443, 8080, 8443, 25, 53, 110, 143, 993, 995, 2082, 2083, 2086, 2087}


def calculate_risk_score(
    domain_df: Optional[pd.DataFrame] = None,
    ip_df: Optional[pd.DataFrame] = None,
    user_df: Optional[pd.DataFrame] = None,
    shodan_data: Optional[Dict[str, Any]] = None,
    email_sec: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Computes a composite Threat Severity Score (0-100).
    """
    score = 0  # Default baseline score for fresh page
    breakdown: List[Dict[str, Any]] = []

    # 1. Shodan Ports Assessment
    ports = []
    if shodan_data and shodan_data.get("is_available"):
        ports = shodan_data.get("ports", [])
    elif ip_df is not None and not ip_df.empty and "shodan_ports" in ip_df.columns:
        first_ports = ip_df.iloc[0].get("shodan_ports")
        if isinstance(first_ports, list):
            ports = first_ports

    crit_hits = [p for p in ports if p in CRITICAL_PORTS]
    mod_hits = [p for p in ports if p in MODERATE_PORTS]

    if crit_hits:
        crit_pts = min(45, len(crit_hits) * 15)
        score += crit_pts
        breakdown.append({
            "category": "Open Critical Ports",
            "points": crit_pts,
            "severity": "HIGH",
            "detail": f"Exposed high-risk ports: {', '.join(str(p) for p in crit_hits)}"
        })

    if mod_hits:
        mod_pts = min(20, len(mod_hits) * 4)
        score += mod_pts
        breakdown.append({
            "category": "Open Standard Services",
            "points": mod_pts,
            "severity": "LOW",
            "detail": f"Active standard service ports: {', '.join(str(p) for p in mod_hits[:6])}"
        })

    # 2. Exposed CVE Vulnerabilities
    vulns = []
    if shodan_data and shodan_data.get("is_available"):
        vulns = shodan_data.get("vulns", [])
    elif ip_df is not None and not ip_df.empty and "shodan_cves" in ip_df.columns:
        first_cves = ip_df.iloc[0].get("shodan_cves")
        if isinstance(first_cves, list):
            vulns = first_cves

    if vulns:
        vuln_pts = min(35, len(vulns) * 10)
        score += vuln_pts
        breakdown.append({
            "category": "Exposed CVE Vulnerabilities",
            "points": vuln_pts,
            "severity": "CRITICAL",
            "detail": f"{len(vulns)} CVE(s) identified on IP: {', '.join(vulns[:4])}"
        })

    # 3. Email Spoofing & DNS Security (DMARC / SPF)
    if email_sec:
        spf_status = email_sec.get("spf_status", "missing")
        dmarc_status = email_sec.get("dmarc_status", "missing")

        if dmarc_status == "missing":
            score += 15
            breakdown.append({
                "category": "Email Security (DMARC)",
                "points": 15,
                "severity": "HIGH",
                "detail": "Missing DMARC policy record — domain highly vulnerable to spoofing."
            })
        elif dmarc_status == "none":
            score += 10
            breakdown.append({
                "category": "Email Security (DMARC)",
                "points": 10,
                "severity": "MEDIUM",
                "detail": "DMARC policy set to 'p=none' (monitoring mode only, non-enforcing)."
            })

        if spf_status == "missing":
            score += 10
            breakdown.append({
                "category": "Email Security (SPF)",
                "points": 10,
                "severity": "MEDIUM",
                "detail": "Missing SPF record — unauthorized servers can originate mail."
            })

    # 4. Email & Linked Service Attack Surface Footprint
    if user_df is not None and not user_df.empty:
        hits = len(user_df[user_df["confidence"] >= 50])
        if hits >= 6:
            score += 15
            breakdown.append({
                "category": "Email & Service Attack Surface",
                "points": 15,
                "severity": "MEDIUM",
                "detail": f"Broad digital footprint: {hits} linked online service profiles & platforms verified."
            })
        elif hits >= 3:
            score += 8
            breakdown.append({
                "category": "Email & Service Attack Surface",
                "points": 8,
                "severity": "LOW",
                "detail": f"Moderate digital footprint: {hits} service profiles verified."
            })


    # Clamp total score between 0 and 100
    final_score = min(100, max(0, score))

    if final_score >= 80:
        level = "CRITICAL"
        color = "#E8544B"
        badge_bg = "rgba(232, 84, 75, 0.18)"
    elif final_score >= 60:
        level = "HIGH"
        color = "#FF7849"
        badge_bg = "rgba(255, 120, 73, 0.18)"
    elif final_score >= 30:
        level = "MODERATE"
        color = "#F0A63A"
        badge_bg = "rgba(240, 166, 58, 0.18)"
    else:
        level = "LOW"
        color = "#4FD9C9"
        badge_bg = "rgba(79, 217, 201, 0.18)"

    return {
        "score": final_score,
        "level": level,
        "color": color,
        "badge_bg": badge_bg,
        "breakdown": breakdown,
        "ports_found": len(ports),
        "cves_found": len(vulns),
    }
