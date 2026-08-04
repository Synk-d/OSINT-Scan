"""
run_domain_osint(domain_value) — real implementation.

Data sources (all free, no API key required):
  - crt.sh              certificate-transparency subdomain enumeration
  - dnspython           A record + MX record resolution
  - ip-api.com          IP -> country / lat / lon / ISP (45 req/min free tier)
  - python-whois        registrar lookup

Design notes:
  - Every external call is wrapped individually so one flaky source (e.g.
    WHOIS timing out) degrades that field instead of killing the whole sweep.
  - If subdomain enumeration itself fails (no internet, crt.sh down, invalid
    domain) the whole function raises OsintLookupError — the caller
    (app.py) catches this and falls back to mock data, per the spec's
    "self-contained data fallback" requirement.
  - Capped to MAX_SUBDOMAINS to keep sweep time and third-party rate limits
    reasonable; increase if you have more patience / your own DNS resolver.
"""

import re
import socket
import time
from datetime import datetime
from typing import List, Optional

import dns.resolver
import requests
import whois as whois_lib

from workers.net_utils import get_with_retry

MAX_SUBDOMAINS = 12
HTTP_TIMEOUT = 8
CRTSH_TIMEOUT = 25  # crt.sh is a free community service and is frequently slow —
                    # 8s was too aggressive and caused false fallbacks to mock data
DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")


class OsintLookupError(Exception):
    """Raised when live lookup can't proceed at all — caller should fall back to mock."""


def _validate_domain(domain_value: str) -> str:
    domain_value = domain_value.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain_value):
        raise OsintLookupError(f"'{domain_value}' doesn't look like a valid domain")
    return domain_value


def _enumerate_subdomains(domain_value: str) -> List[str]:
    """Certificate-transparency lookup via crt.sh. Returns unique hostnames."""
    try:
        resp = get_with_retry(
            "https://crt.sh/",
            params={"q": f"%.{domain_value}", "output": "json"},
            timeout=CRTSH_TIMEOUT,
            retries=1,
            headers={"User-Agent": "osint-dashboard-recon/1.0"},
        )
        resp.raise_for_status()
        entries = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise OsintLookupError(f"crt.sh lookup failed: {e}") from e

    names = set()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain_value):
                names.add(name)
    names.add(domain_value)
    # Root domain first, then alphabetical, capped
    ordered = [domain_value] + sorted(n for n in names if n != domain_value)
    return ordered[:MAX_SUBDOMAINS]


def _resolve_a_record(hostname: str) -> Optional[str]:
    try:
        answer = dns.resolver.resolve(hostname, "A", lifetime=5)
        return str(answer[0])
    except Exception:
        return None


def _resolve_mx(domain_value: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain_value, "MX", lifetime=5)
        return sorted(str(a.exchange).rstrip(".") for a in answers)
    except Exception:
        return []


def _geo_lookup(ip_address: str) -> dict:
    """ip-api.com free tier: no key, ~45 req/min. Degrades to blanks on failure."""
    try:
        resp = get_with_retry(
            f"http://ip-api.com/json/{ip_address}",
            params={"fields": "status,countryCode,lat,lon,isp,org"},
            timeout=HTTP_TIMEOUT,
        )
        data = resp.json()
        if data.get("status") == "success":
            return {
                "isp": data.get("isp") or data.get("org") or "Unknown",
                "country": data.get("countryCode", "—"),
                "lat": data.get("lat", 0.0),
                "lon": data.get("lon", 0.0),
            }
    except (requests.RequestException, ValueError):
        pass
    return {"isp": "Unknown", "country": "—", "lat": 0.0, "lon": 0.0}


def _whois_lookup(domain_value: str) -> dict:
    """python-whois can hang on some TLD registries — hard-cap via socket timeout."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(6)
    try:
        w = whois_lib.whois(domain_value)
        registrar = w.registrar if isinstance(w.registrar, str) else (
            w.registrar[0] if w.registrar else None
        )
        return {"registrar": registrar or "Unavailable", "raw": {k: str(v) for k, v in (w or {}).items()}}
    except Exception:
        return {"registrar": "Unavailable", "raw": {}}
    finally:
        socket.setdefaulttimeout(old_timeout)


def run_domain_osint(domain_value: str) -> "pd.DataFrame":
    import pandas as pd  # local import keeps this module importable without pandas at load time

    domain_value = _validate_domain(domain_value)
    subdomains = _enumerate_subdomains(domain_value)
    if not subdomains:
        raise OsintLookupError("No subdomains discovered and root domain unreachable")

    whois_info = _whois_lookup(domain_value)
    mx_records = _resolve_mx(domain_value)

    rows = []
    for i, sub in enumerate(subdomains):
        ip = _resolve_a_record(sub)
        geo = _geo_lookup(ip) if ip else {"isp": "Unresolved", "country": "—", "lat": 0.0, "lon": 0.0}
        rows.append({
            "subdomain": sub,
            "ip_address": ip or "—",
            "isp": geo["isp"],
            "country": geo["country"],
            "lat": geo["lat"],
            "lon": geo["lon"],
            "registrar": whois_info["registrar"],
            "mx_records": mx_records if i == 0 else [],
            "raw_whois": whois_info["raw"] if i == 0 else {},
            "discovered_at": datetime.now(),
        })
        time.sleep(0.4)  # be polite to ip-api.com's free-tier rate limit

    return pd.DataFrame(rows)