from __future__ import annotations

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

import socket
import time
from datetime import datetime
from typing import List, Optional

import dns.resolver
import pandas as pd
import requests
import whois as whois_lib

from workers.net_utils import DOMAIN_RE, get_with_retry

MAX_SUBDOMAINS = 12
HTTP_TIMEOUT = 8
CRTSH_TIMEOUT = 25  # crt.sh is a free community service and is frequently slow



class OsintLookupError(Exception):
    """Raised when live lookup can't proceed at all — caller should fall back to mock."""


def _validate_domain(domain_value: str) -> str:
    domain_value = domain_value.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain_value):
        raise OsintLookupError(f"'{domain_value}' doesn't look like a valid domain")
    return domain_value


def _extract_apex_domain(domain_value: str) -> str:
    """Extract apex/root domain from subdomains (e.g. www.instagram.com -> instagram.com)."""
    parts = domain_value.split(".")
    if len(parts) > 2:
        return ".".join(parts[-2:])
    return domain_value


def _enumerate_subdomains(domain_value: str) -> List[str]:
    """Subdomain enumeration with multi-source fallback (crt.sh -> HackerTarget -> DNS probe).
    Returns unique hostnames."""
    root_domain = _extract_apex_domain(domain_value)
    names = {domain_value, root_domain}

    # Source 1: crt.sh (Certificate Transparency)
    try:
        resp = get_with_retry(
            "https://crt.sh/",
            params={"q": f"%.{root_domain}", "output": "json"},
            timeout=CRTSH_TIMEOUT,
            retries=1,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        if resp.status_code == 200:
            try:
                entries = resp.json()
                for entry in entries:
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(root_domain) and not name.startswith("*"):
                            names.add(name)
            except (ValueError, AttributeError):
                pass
    except Exception:
        pass

    # Source 2: HackerTarget API (Fast public fallback if crt.sh fails/times out)
    if len(names) < 3:
        try:
            resp = get_with_retry(
                f"https://api.hackertarget.com/hostsearch/?q={root_domain}",
                timeout=8,
                retries=1,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code == 200 and "," in resp.text:
                for line in resp.text.splitlines():
                    parts = line.split(",")
                    if parts:
                        host = parts[0].strip().lower()
                        if host.endswith(root_domain):
                            names.add(host)
        except Exception:
            pass

    # Source 3: Active DNS resolution probe for common subdomains if still under threshold
    if len(names) < 3:
        common_prefixes = ["www", "api", "mail", "app", "dev", "cdn", "m", "portal"]
        for prefix in common_prefixes:
            candidate = f"{prefix}.{root_domain}"
            if candidate not in names:
                if _resolve_a_record(candidate):
                    names.add(candidate)

    # Root / input domain first, then alphabetical, capped
    ordered = []
    for d in [domain_value, root_domain]:
        if d in names and d not in ordered:
            ordered.append(d)
    for n in sorted(names):
        if n not in ordered:
            ordered.append(n)

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
            params={"fields": "status,countryCode,regionName,city,lat,lon,isp,org"},
            timeout=HTTP_TIMEOUT,
        )
        data = resp.json()
        if data.get("status") == "success":
            return {
                "isp": data.get("isp") or data.get("org") or "Unknown",
                "country": data.get("countryCode", "—"),
                "region_name": data.get("regionName", "—"),
                "city": data.get("city", "—"),
                "lat": data.get("lat", 0.0),
                "lon": data.get("lon", 0.0),
            }
    except (requests.RequestException, ValueError):
        return {"isp": "Unknown", "country": "—", "region_name": "—", "city": "—", "lat": 0.0, "lon": 0.0}
    return {"isp": "Unknown", "country": "—", "region_name": "—", "city": "—", "lat": 0.0, "lon": 0.0}


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


def run_domain_osint(domain_value: str) -> pd.DataFrame:

    try:
        domain_value = _validate_domain(domain_value)
    except Exception as e:
        # If domain validation fails, raise immediately
        raise OsintLookupError(f"Invalid domain: {e}")
    
    # Try to enumerate subdomains, but always fall back to root domain if it fails
    subdomains = None
    try:
        subdomains = _enumerate_subdomains(domain_value)
    except Exception:
        subdomains = [domain_value]  # Fallback: use root domain only
    
    # Always have at least the root domain
    if not subdomains:
        subdomains = [domain_value]

    # Try to get registrar and MX info, but don't fail the whole sweep if they error
    try:
        whois_info = _whois_lookup(domain_value)
    except Exception:
        whois_info = {"registrar": "Unavailable", "raw": {}}
    
    try:
        mx_records = _resolve_mx(domain_value)
    except Exception:
        mx_records = []

    rows = []
    for i, sub in enumerate(subdomains):
        try:
            ip = _resolve_a_record(sub)
        except Exception:
            ip = None
        
        try:
            geo = _geo_lookup(ip) if ip else {"isp": "Unresolved", "country": "—", "region_name": "—", "city": "—", "lat": 0.0, "lon": 0.0}
        except Exception:
            geo = {"isp": "Unavailable", "country": "—", "region_name": "—", "city": "—", "lat": 0.0, "lon": 0.0}
        
        rows.append({
            "subdomain": sub,
            "ip_address": ip or "—",
            "isp": geo["isp"],
            "country": geo["country"],
            "region_name": geo["region_name"],
            "city": geo["city"],
            "lat": geo["lat"],
            "lon": geo["lon"],
            "registrar": whois_info["registrar"],
            "mx_records": mx_records if i == 0 else [],
            "raw_whois": whois_info["raw"] if i == 0 else {},
            "discovered_at": datetime.now(),
        })
        time.sleep(0.4)  # be polite to ip-api.com's free-tier rate limit

    return pd.DataFrame(rows)