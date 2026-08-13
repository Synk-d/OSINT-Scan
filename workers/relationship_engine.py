"""
generate_auto_relationships(domain_df, user_df, domain_val, user_val)

Real correlation & relationship logic — links domain infrastructure and identity footprints:

  - investigation_target_pivot: links active Domain target and Identity target in the case workspace
  - platform_target_match: platform profiles (e.g. Instagram profile) match target domain (e.g. instagram.com)
  - shared_ip_block: two subdomains resolve into the same /24 block
  - exact_email_domain_match: target email domain matches target domain
  - username_reuse: target username appears inside a discovered subdomain label
  - shared_registrant_email: user profile's associated_email matches target domain
  - linked_bio_url: bio keyword mentions domain name
"""

import pandas as pd


def _ip_block(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def generate_auto_relationships(domain_df: pd.DataFrame, user_df: pd.DataFrame,
                                 domain_val: str, user_val: str) -> pd.DataFrame:
    rows = []

    # 1. Target Case Pivot: link domain and identity targets in the same investigation case
    if domain_val and user_val:
        if "@" in user_val and user_val.split("@")[1].lower() == domain_val.lower():
            rows.append({
                "source": user_val, "target": domain_val,
                "relationship_type": "exact_email_domain_match",
                "confidence_score": 95,
            })
        else:
            rows.append({
                "source": user_val, "target": domain_val,
                "relationship_type": "investigation_target_pivot",
                "confidence_score": 75,
            })

    # 2. Platform / Target Service Match: link platform profile to target domain if names align
    if domain_val and not user_df.empty and "platform" in user_df.columns:
        domain_root = domain_val.split(".")[0].lower()  # e.g. 'instagram' from 'instagram.com'
        for _, r in user_df.iterrows():
            platform = str(r.get("platform", "")).lower()
            display_name = str(r.get("display_name", "")).lower()
            if domain_root and len(domain_root) >= 3 and (domain_root in platform or domain_root in display_name):
                rows.append({
                    "source": r.get("platform"), "target": domain_val,
                    "relationship_type": "platform_target_match",
                    "confidence_score": 90,
                })

    # 3. shared_ip_block: subdomains in the same /24 block
    if not domain_df.empty and "ip_address" in domain_df.columns:
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

    # 4. email_linked_service: connect email target directly to platform profiles
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

    # 5. shared_mail_infrastructure: MX records match email domain
    if not domain_df.empty and "mx_records" in domain_df.columns and user_val and "@" in user_val:
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

    # 6. username_reuse: handle appears in subdomain label
    if not domain_df.empty and "subdomain" in domain_df.columns and user_val:
        handle = user_val.split("@")[0].lower() if "@" in user_val else user_val.lower()
        if len(handle) >= 3:
            for sub in domain_df["subdomain"]:
                if handle in sub.lower():
                    rows.append({
                        "source": sub, "target": user_val,
                        "relationship_type": "username_reuse",
                        "confidence_score": 75,
                    })

    # 7. shared_registrant_email: associated email domain matches domain target
    if not user_df.empty and "associated_email" in user_df.columns and domain_val:
        for _, r in user_df.iterrows():
            email = r.get("associated_email")
            if isinstance(email, str) and "@" in email and email.split("@")[1].lower() == domain_val.lower():
                rows.append({
                    "source": r["platform"], "target": domain_val,
                    "relationship_type": "shared_registrant_email",
                    "confidence_score": 91,
                })

    # 8. linked_bio_url: bio keyword matches domain
    if not user_df.empty and "bio_keywords" in user_df.columns and domain_val:
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
