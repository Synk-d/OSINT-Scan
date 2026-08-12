from __future__ import annotations

"""
workers/shodan_worker.py — Passive Threat Intelligence via Shodan InternetDB.

Queries Shodan's free public unauthenticated API:
    https://internetdb.shodan.io/<IP>

Returns open ports, hostnames, CPEs, tags, and exposed CVE vulnerabilities.
Requires no API key or authentication.
"""

from typing import Any, Dict, List
import requests

from workers.net_utils import get_with_retry

HTTP_TIMEOUT = 6


def query_shodan_internetdb(ip_address: str) -> Dict[str, Any]:
    """
    Queries Shodan InternetDB for open ports, vulnerabilities (CVEs), hostnames, and CPEs.
    Returns a standardized dictionary. Never throws — degrades to empty lists on 404 or error.
    """
    ip_clean = str(ip_address).strip()
    empty_result: Dict[str, Any] = {
        "ip": ip_clean,
        "ports": [],
        "hostnames": [],
        "cpes": [],
        "vulns": [],
        "tags": [],
        "is_available": False,
    }

    if not ip_clean or ip_clean in ("—", "Unresolved", "Unavailable", "Local Network"):
        return empty_result

    url = f"https://internetdb.shodan.io/{ip_clean}"
    try:
        resp = get_with_retry(url, timeout=HTTP_TIMEOUT, retries=1)
        if resp.status_code != 200:
            return empty_result

        data = resp.json()
        ports = [int(p) for p in data.get("ports", []) if isinstance(p, (int, str)) and str(p).isdigit()]
        hostnames = [str(h) for h in data.get("hostnames", []) if h]
        cpes = [str(c) for c in data.get("cpes", []) if c]
        vulns = [str(v) for v in data.get("vulns", []) if v]
        tags = [str(t) for t in data.get("tags", []) if t]

        return {
            "ip": ip_clean,
            "ports": sorted(ports),
            "hostnames": hostnames,
            "cpes": cpes,
            "vulns": vulns,
            "tags": tags,
            "is_available": True,
        }

    except Exception:
        return empty_result
