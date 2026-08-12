"""
Repository layer — all raw SQL lives here, fully parameterized (no string
formatting into queries). Every function returns/accepts plain Python types
or pandas DataFrames shaped exactly like the frontend's mock DataFrames, so
app.py doesn't need to change when it swaps mock data for this.
"""

import json
from typing import Optional

import pandas as pd

from db.connection import get_conn


def get_or_create_target(target_type: str, target_value: str) -> int:
    """Insert the target if new, return its id either way."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO targets (target_type, target_value)
                VALUES (%s, %s)
                ON CONFLICT (target_value) DO UPDATE SET target_value = EXCLUDED.target_value
                RETURNING id
                """,
                (target_type, target_value),
            )
            return cur.fetchone()[0]


def save_domain_intel(target_id: int, rows: list[dict]) -> None:
    """rows: list of dicts matching the domain_intel columns."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            for r in rows:
                cur.execute(
                    """
                    INSERT INTO domain_intel
                        (target_id, subdomain, ip_address, isp, country, region_name, city, lat, lon,
                         registrar, mx_records, raw_whois, discovered_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        target_id, r["subdomain"], r.get("ip_address"), r.get("isp"),
                        r.get("country"), r.get("region_name"), r.get("city"), r.get("lat"), r.get("lon"),
                        r.get("registrar"), r.get("mx_records") or [], json.dumps(r.get("raw_whois") or {}),
                        r.get("discovered_at"),
                    ),
                )


def save_user_intel(target_id: int, rows: list[dict]) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            for r in rows:
                cur.execute(
                    """
                    INSERT INTO user_intel
                        (target_id, platform, profile_url, associated_email,
                         bio_keywords, confidence, discovered_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        target_id, r["platform"], r["profile_url"], r.get("associated_email"),
                        r.get("bio_keywords") or [], r.get("confidence"), r.get("discovered_at"),
                    ),
                )


def save_relationships(domain_target_id: int, user_target_id: int, rows: list[dict]) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            for r in rows:
                cur.execute(
                    """
                    INSERT INTO entity_relationships
                        (source_target_id, destination_target_id, source_label,
                         destination_label, relationship_type, confidence_score)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        domain_target_id, user_target_id, r["source"], r["target"],
                        r["relationship_type"], r["confidence_score"],
                    ),
                )


def fetch_domain_intel(target_value: str) -> Optional[pd.DataFrame]:
    """Most recent sweep for a domain target, shaped like run_domain_osint()'s output."""
    with get_conn() as conn:
        df = pd.read_sql(
            """
            SELECT di.subdomain, di.ip_address, di.isp, di.country, di.lat, di.lon,
                   di.registrar, di.mx_records, di.discovered_at
            FROM domain_intel di
            JOIN targets t ON t.id = di.target_id
            WHERE t.target_value = %(target_value)s
            ORDER BY di.discovered_at DESC
            """,
            conn, params={"target_value": target_value},
        )
    return df if not df.empty else None


def fetch_user_intel(target_value: str) -> Optional[pd.DataFrame]:
    with get_conn() as conn:
        df = pd.read_sql(
            """
            SELECT ui.platform, ui.profile_url, ui.associated_email,
                   ui.bio_keywords, ui.confidence, ui.discovered_at
            FROM user_intel ui
            JOIN targets t ON t.id = ui.target_id
            WHERE t.target_value = %(target_value)s
            ORDER BY ui.discovered_at DESC
            """,
            conn, params={"target_value": target_value},
        )
    return df if not df.empty else None


def fetch_relationships(domain_value: str, user_value: str) -> Optional[pd.DataFrame]:
    with get_conn() as conn:
        df = pd.read_sql(
            """
            SELECT er.source_label AS source, er.destination_label AS target,
                   er.relationship_type, er.confidence_score
            FROM entity_relationships er
            JOIN targets td ON td.id = er.source_target_id
            JOIN targets tu ON tu.id = er.destination_target_id
            WHERE td.target_value = %(domain_value)s AND tu.target_value = %(user_value)s
            ORDER BY er.created_at DESC
            """,
            conn, params={"domain_value": domain_value, "user_value": user_value},
        )
    return df if not df.empty else None


def save_ip_intel(target_id: int, rows: list[dict]) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            for r in rows:
                cur.execute(
                    """
                    INSERT INTO ip_intel
                        (target_id, ip_address, country, country_code, region_code, region_name,
                         city, zip, lat, lon, timezone, isp, org, as_number, reverse_dns, discovered_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        target_id, r["ip_address"], r.get("country"), r.get("country_code"),
                        r.get("region_code"), r.get("region_name"), r.get("city"), r.get("zip"),
                        r.get("lat"), r.get("lon"), r.get("timezone"), r.get("isp"),
                        r.get("org"), r.get("as_number"), r.get("reverse_dns"), r.get("discovered_at"),
                    ),
                )


def fetch_ip_intel(target_value: str) -> Optional[pd.DataFrame]:
    with get_conn() as conn:
        df = pd.read_sql(
            """
            SELECT ii.ip_address, ii.country, ii.country_code, ii.region_code, ii.region_name,
                   ii.city, ii.zip, ii.lat, ii.lon, ii.timezone, ii.isp, ii.org, ii.as_number,
                   ii.reverse_dns, ii.discovered_at
            FROM ip_intel ii
            JOIN targets t ON t.id = ii.target_id
            WHERE t.target_value = %(target_value)s
            ORDER BY ii.discovered_at DESC
            """,
            conn, params={"target_value": target_value},
        )
    return df if not df.empty else None
