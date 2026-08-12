"""
generate_auto_relationships(domain_df, user_df, domain_val, user_val)

Real correlation logic — looks for actual shared signals between the two
sweeps rather than random pairing:

  - shared_ip_block:       two subdomains resolve into the same /24
  - username_reuse:        the target username appears literally inside a
                            discovered subdomain label
  - shared_registrant_email: a user profile's associated_email shares a
                            domain with the target domain, or vice versa
  - linked_bio_url:        a bio keyword mentions the domain name

If nothing correlates (common for two unrelated targets picked at random),
this returns an empty DataFrame — that's a correct result, not a bug.
"""

import pandas as pd


def _ip_block(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def generate_auto_relationships(domain_df: pd.DataFrame, user_df: pd.DataFrame,
                                 domain_val: str, user_val: str) -> pd.DataFrame:
    rows = []

    # shared_ip_block: any two resolved subdomains in the same /24
    if "ip_address" in domain_df.columns:
        by_block = {}
        for _, r in domain_df.iterrows():
            ip = r.get("ip_address")
            if not ip or ip == "—":
                continue
            block = _ip_block(ip)
            by_block.setdefault(block, []).append(r["subdomain"])
        for block, subs in by_block.items():
            if len(subs) > 1:
                rows.append({
                    "source": subs[0], "target": subs[1],
                    "relationship_type": "shared_ip_block",
                    "confidence_score": 82,
                })

    # username_reuse: username literally appears in a subdomain label
    if "subdomain" in domain_df.columns and user_val:
        for sub in domain_df["subdomain"]:
            if user_val.lower() in sub.lower():
                rows.append({
                    "source": sub, "target": user_val,
                    "relationship_type": "username_reuse",
                    "confidence_score": 70,
                })

    # shared_registrant_email: user's associated_email domain matches target domain
    if "associated_email" in user_df.columns:
        for _, r in user_df.iterrows():
            email = r.get("associated_email")
            if isinstance(email, str) and "@" in email and email.split("@")[1].lower() == domain_val.lower():
                rows.append({
                    "source": r["platform"], "target": domain_val,
                    "relationship_type": "shared_registrant_email",
                    "confidence_score": 91,
                })

    # linked_bio_url: a bio keyword mentions the domain (crude substring match)
    if "bio_keywords" in user_df.columns:
        domain_root = domain_val.split(".")[0].lower()
        for _, r in user_df.iterrows():
            kws = r.get("bio_keywords")
            if not isinstance(kws, (list, tuple)):
                kws = []
            if any(domain_root in str(kw).lower() for kw in kws):
                rows.append({
                    "source": r["platform"], "target": domain_val,
                    "relationship_type": "linked_bio_url",
                    "confidence_score": 65,
                })

    return pd.DataFrame(rows, columns=["source", "target", "relationship_type", "confidence_score"])
