"""
Deterministic mock data generators — the "self-contained data fallback"
required by the spec. If live lookups fail, throttle, or the target has no
network access, workers fall back to these so the UI never breaks.

Kept separate from the real workers so there's exactly one source of truth
for the mock shape (this used to live inline in app.py).
"""

from datetime import datetime, timedelta
import pandas as pd
from workers.net_utils import _seed

ISPS = ["Cloudflare", "Amazon AWS", "DigitalOcean", "OVH SAS", "Google Cloud", "Akamai", "Hetzner"]
PLATFORMS = ["GitHub", "Twitter / X", "Keybase", "Reddit", "Instagram", "LinkedIn", "Telegram"]
REL_TYPES = ["shared_registrant_email", "shared_ip_block", "shared_asn", "username_reuse", "linked_bio_url"]
COUNTRIES = [("US", 37.09, -95.71), ("DE", 51.16, 10.45), ("NL", 52.13, 5.29),
             ("SG", 1.35, 103.82), ("FR", 46.6, 2.2), ("JP", 36.2, 138.25)]




def mock_domain_osint(domain_value: str) -> pd.DataFrame:
    rng = _seed(domain_value)
    n = rng.randint(5, 11)
    rows = []
    for i in range(n):
        sub = "root" if i == 0 else rng.choice(
            ["mail", "api", "dev", "staging", "vpn", "cdn", "app", "admin", "portal", "ns1"])
        country = rng.choice(COUNTRIES)
        rows.append({
            "subdomain": f"{sub}.{domain_value}" if sub != "root" else domain_value,
            "ip_address": f"{rng.randint(20,210)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
            "isp": rng.choice(ISPS),
            "country": country[0], "lat": country[1] + rng.uniform(-4, 4), "lon": country[2] + rng.uniform(-4, 4),
            "registrar": rng.choice(["NameCheap Inc.", "GoDaddy.com LLC", "Cloudflare Inc.", "MarkMonitor Inc."]),
            "mx_records": [f"mx{k}.{domain_value}" for k in range(1, rng.randint(2, 4))],
            "discovered_at": datetime.now() - timedelta(hours=rng.randint(0, 96)),
        })
    return pd.DataFrame(rows)


def mock_user_osint(username_value: str) -> pd.DataFrame:
    rng = _seed(username_value + "user")
    hits = rng.sample(PLATFORMS, k=rng.randint(3, len(PLATFORMS)))
    keywords_pool = ["security", "ctf", "python", "infra", "reverse-eng", "privacy", "linux",
                      "photography", "gamedev", "opsource", "networking", "writeups"]
    rows = []
    for p in hits:
        rows.append({
            "platform": p,
            "profile_url": f"https://{p.lower().split(' ')[0]}.example/{username_value}",
            "associated_email": f"{username_value}@{rng.choice(['proton.me','gmail.com','outlook.com'])}" if rng.random() > 0.4 else None,
            "bio_keywords": rng.sample(keywords_pool, k=rng.randint(2, 5)),
            "confidence": rng.randint(52, 99),
            "discovered_at": datetime.now() - timedelta(hours=rng.randint(0, 96)),
        })
    return pd.DataFrame(rows)


def mock_relationships(domain_df, user_df, domain_val, user_val) -> pd.DataFrame:
    rng = _seed(domain_val + user_val + "rel")
    rows = []
    n = rng.randint(3, 6)
    nodes = [domain_val] + list(domain_df["subdomain"].head(3)) + [user_val] + list(user_df["platform"])
    for _ in range(n):
        a, b = rng.sample(nodes, 2)
        rows.append({
            "source": a, "target": b,
            "relationship_type": rng.choice(REL_TYPES),
            "confidence_score": rng.randint(35, 98),
        })
    return pd.DataFrame(rows)
