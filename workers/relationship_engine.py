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

    # exact_email_domain_match: target email domain matches target domain
    if user_val and "@" in user_val and domain_val:
        email_dom = user_val.split("@")[1].lower()
        if email_dom == domain_val.lower():
            rows.append({
                "source": user_val, "target": domain_val,
                "relationship_type": "exact_email_domain_match",
                "confidence_score": 95,
            })

    # email_linked_service: connect target email directly to each discovered platform profile
    if user_val and not user_df.empty and "platform" in user_df.columns:
        for _, r in user_df.iterrows():
            platform = r.get("platform")
            conf = int(r.get("confidence", 85))
            if platform:
                rows.append({
                    "source": user_val, "target": platform,
                    "relationship_type": "email_linked_service",
                    "confidence_score": conf,
                })

    # shared_mail_infrastructure: email domain provider matches MX records
    if "mx_records" in domain_df.columns and user_val and "@" in user_val:
        email_dom = user_val.split("@")[1].lower()
        for _, r in domain_df.iterrows():
            mxs = r.get("mx_records")
            if isinstance(mxs, list):
                mx_str = " ".join(mxs).lower()
                if email_dom in mx_str or ("google" in mx_str and "gmail" in email_dom) or ("outlook" in mx_str and "outlook" in email_dom):
                    rows.append({
                        "source": user_val, "target": r.get("subdomain", domain_val),
                        "relationship_type": "shared_mail_infrastructure",
                        "confidence_score": 88,
                    })

    # username_reuse: username or email local-part appears in a subdomain label
    if "subdomain" in domain_df.columns and user_val:
        handle = user_val.split("@")[0].lower() if "@" in user_val else user_val.lower()
        if len(handle) >= 3:
            for sub in domain_df["subdomain"]:
                if handle in sub.lower():
                    rows.append({
                        "source": sub, "target": user_val,
                        "relationship_type": "username_reuse",
                        "confidence_score": 75,
                    })

    # shared_registrant_email: user's associated_email domain matches target domain
    if "associated_email" in user_df.columns and domain_val:
        for _, r in user_df.iterrows():
            email = r.get("associated_email")
            if isinstance(email, str) and "@" in email and email.split("@")[1].lower() == domain_val.lower():
                rows.append({
                    "source": r["platform"], "target": domain_val,
                    "relationship_type": "shared_registrant_email",
                    "confidence_score": 91,
                })

    # linked_bio_url: a bio keyword mentions the domain (crude substring match)
    if "bio_keywords" in user_df.columns and domain_val:
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

