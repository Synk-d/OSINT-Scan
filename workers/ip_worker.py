from __future__ import annotations

"""
run_ip_osint(ip_value) — Real live IP Geolocation & Location Region Area lookup worker.

Data sources (free, no API key required):
  - ip-api.com       Real-time IP -> country / region area / city / lat / lon / ISP / ASN / PTR
  - socket           Python standard library socket for reverse DNS PTR lookup

Design notes:
  - Operates strictly on real live network connections.
  - Handles private/local IP ranges (192.168.x.x, 10.x.x.x, 127.0.0.1) gracefully.
  - Supports fetching caller's public WAN IP geolocation via get_public_ip_osint().
"""

import ipaddress
import socket
from datetime import datetime
import pandas as pd
import requests

from workers.net_utils import get_with_retry
from workers.shodan_worker import query_shodan_internetdb

HTTP_TIMEOUT = 8


class OsintLookupError(Exception):
    """Raised when live IP lookup fails or cannot proceed."""


def _validate_and_resolve_ip(ip_input: str) -> str:
    """Validates IPv4/IPv6 address or resolves hostname to IP."""
    ip_str = ip_input.strip()
    if not ip_str:
        raise OsintLookupError("IP address cannot be empty.")
    
    # Try parsing direct IP
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError:
        pass
    
    # Try resolving hostname to IP
    try:
        ip_resolved = socket.gethostbyname(ip_str)
        return ip_resolved
    except socket.gaierror:
        raise OsintLookupError(f"'{ip_str}' is not a valid IPv4/IPv6 address or resolvable hostname.")


def _is_private_ip(ip_str: str) -> bool:
    """Check if IP address is a non-routable private/local range (e.g. 192.168.x.x, 10.x.x.x, 127.0.0.1)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved
    except ValueError:
        return False


def _get_reverse_dns(ip_str: str) -> str:
    """Perform PTR / Reverse DNS lookup."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        return host
    except Exception:
        return "—"


def run_ip_osint(ip_value: str) -> pd.DataFrame:
    """
    Performs real IP geolocation, location region area, city, timezone, network lookup,
    and Shodan InternetDB open ports & CVE vulnerability scanning.
    Returns a single-row pandas DataFrame with live results.
    """
    ip_target = _validate_and_resolve_ip(ip_value)

    # Handle Private / Local LAN IP ranges gracefully
    if _is_private_ip(ip_target):
        reverse_dns = _get_reverse_dns(ip_target)
        row = {
            "ip_address": ip_target,
            "country": "Local Network",
            "country_code": "LAN",
            "region_code": "PRIVATE",
            "region_name": "Private Subnet (RFC 1918)",  # Location Region Area
            "city": "Local Host",
            "zip": "—",
            "lat": 0.0,
            "lon": 0.0,
            "timezone": "Local System Time",
            "isp": "Local Network Interface",
            "org": "Private LAN Subnet",
            "as_number": "Non-Routable Private Range",
            "reverse_dns": reverse_dns,
            "is_private": True,
            "shodan_ports": [],
            "shodan_cves": [],
            "shodan_hostnames": [],
            "shodan_cpes": [],
            "shodan_tags": [],
            "discovered_at": datetime.now(),
        }
        return pd.DataFrame([row])

    try:
        resp = get_with_retry(
            f"http://ip-api.com/json/{ip_target}",
            params={
                "fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse"
            },
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            raise OsintLookupError(f"IP Geolocation API returned HTTP status {resp.status_code}")

        data = resp.json()
        if data.get("status") != "success":
            msg = data.get("message", "Unknown error")
            if msg == "private range":
                return run_ip_osint(ip_target)  # Re-route to private handler
            raise OsintLookupError(f"IP Geolocation lookup failed: {msg}")

        reverse_dns = data.get("reverse") or _get_reverse_dns(ip_target)

        # Passive Shodan InternetDB Threat Intel query
        shodan_info = query_shodan_internetdb(ip_target)

        row = {
            "ip_address": data.get("query") or ip_target,
            "country": data.get("country") or "—",
            "country_code": data.get("countryCode") or "—",
            "region_code": data.get("region") or "—",
            "region_name": data.get("regionName") or "—",  # Location Region Area
            "city": data.get("city") or "—",
            "zip": data.get("zip") or "—",
            "lat": float(data.get("lat") or 0.0),
            "lon": float(data.get("lon") or 0.0),
            "timezone": data.get("timezone") or "—",
            "isp": data.get("isp") or "—",
            "org": data.get("org") or "—",
            "as_number": data.get("as") or "—",
            "reverse_dns": reverse_dns,
            "is_private": False,
            "shodan_ports": shodan_info.get("ports", []),
            "shodan_cves": shodan_info.get("vulns", []),
            "shodan_hostnames": shodan_info.get("hostnames", []),
            "shodan_cpes": shodan_info.get("cpes", []),
            "shodan_tags": shodan_info.get("tags", []),
            "discovered_at": datetime.now(),
        }

        return pd.DataFrame([row])

    except requests.RequestException as exc:
        raise OsintLookupError(f"Network error querying IP Geolocation API: {exc}")
