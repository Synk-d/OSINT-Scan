from __future__ import annotations

"""
workers/user_worker.py — Email-Centric OSINT & Identity Footprinting Engine.

Email-first OSINT pipeline:
  Email-Specific APIs (no token needed):
    1. Gravatar          — MD5 hash → avatar, display name, linked accounts, bio
    2. EmailRep.io       — Reputation score, breach history, activity, disposable check
    3. HaveIBeenPwned    — Public breach/paste exposure list (no key needed for list)
    4. Hunter.io domain  — Domain org intelligence from email domain (public endpoint)
    5. Clearbit Reveal   — Person enrichment from email (public endpoint, best-effort)
    6. GitHub Email      — Search users by email (public email only, best-effort)
    7. GitHub Domain     — Search repos / users by email domain organisation
    8. FullContact       — Person enrichment by email hash (public lookup)

  Handle-based platform checks (derived from email local-part):
    9. GitHub handle     — Direct API: bio, repos, followers, avatar
    10. GitLab handle    — REST v4 API: name, bio, org
    11. Dev.to handle    — REST API: developer bio, location
    12. HackerNews       — Firebase API: karma, bio
    13. Keybase          — API 1.0: PGP keys, linked proofs
    14. DockerHub        — API v2: full name, company
    15. Reddit           — Public API: karma, bio
    16. npm Registry     — CouchDB user endpoint: package author check
    17. PyPI             — HTML profile scrape with strict signature
    18. Medium           — HTML profile scrape with strict signature
    19. CodePen          — HTML profile scrape with strict signature
    20. Hashnode          — Public GraphQL API: blog posts, bio

  Domain enrichment from email domain:
    21. WHOIS via rdap.org — Registrar, registrant, creation date
    22. MX Records        — DNS-over-HTTPS (Google DoH) MX lookup
    23. DMARC / SPF       — DNS TXT records for email security posture

Design Principles:
  - All lookups use real live network connections. Zero mock fallbacks.
  - The primary record is always inserted so the engine never returns empty.
  - Weighted confidence scores based on verified API response payloads.
  - Handle candidates are generated via multiple strategies to maximise coverage.
"""

import hashlib
import os
import re
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import pandas as pd
import requests

from workers.net_utils import get_with_retry

HTTP_TIMEOUT = 8
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)
HEADERS = {"User-Agent": USER_AGENT, "Accept": "application/json, text/html, */*"}
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "protonmail.com", "proton.me", "zoho.com", "aol.com", "gmx.com",
    "mail.com", "yandex.com", "yandex.ru", "live.com", "msn.com",
    "me.com", "mac.com", "inbox.com", "fastmail.com", "tutanota.com",
    "guerrillamail.com", "mailinator.com", "tempmail.com", "throwam.com",
    "sharklasers.com", "guerrillamailblock.com", "grr.la", "guerrillamail.info",
    "dispostable.com", "maildrop.cc",
}


class OsintLookupError(Exception):
    """Raised when live user lookup fails or cannot proceed."""


# ---------------------------------------------------------------------------
# UTILITY HELPERS
# ---------------------------------------------------------------------------

def _extract_keywords(text: str, limit: int = 8) -> List[str]:
    """Extract meaningful bio keywords excluding common stopwords."""
    if not text:
        return []
    stopwords = {
        "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
        "of", "with", "by", "from", "up", "about", "into", "over", "after",
        "is", "are", "was", "were", "be", "been", "being", "have", "has",
        "had", "do", "does", "did", "will", "would", "should", "can", "could",
        "may", "might", "must", "this", "that", "these", "those", "my", "your",
        "his", "her", "its", "our", "their", "i", "you", "he", "she", "it",
        "we", "they", "me", "him", "them", "also", "just", "like", "more",
        "some", "very", "when", "who", "what", "where",
    }
    words = re.findall(r"\b[a-zA-Z0-9_#-]{3,}\b", text.lower())
    filtered = [w for w in words if w not in stopwords]
    seen: set = set()
    unique: List[str] = []
    for w in filtered:
        if w not in seen:
            seen.add(w)
            unique.append(w)
    return unique[:limit]


def _classify_email_domain(domain: str) -> str:
    if domain.lower() in FREE_EMAIL_PROVIDERS:
        return "Free Webmail Provider"
    return "Corporate / Custom Domain"


def _email_md5(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


def _make_record(
    platform: str,
    category: str,
    profile_url: str,
    display_name: str,
    confidence: int,
    *,
    associated_email: str = "—",
    bio_keywords: Optional[List[str]] = None,
    followers: int = 0,
    public_repos: int = 0,
    avatar_url: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    rec: Dict[str, Any] = {
        "platform": platform,
        "category": category,
        "profile_url": profile_url,
        "associated_email": associated_email,
        "display_name": display_name,
        "bio_keywords": bio_keywords or [],
        "followers": followers,
        "public_repos": public_repos,
        "avatar_url": avatar_url,
        "confidence": confidence,
    }
    if extra:
        rec.update(extra)
    return rec


# ---------------------------------------------------------------------------
# EMAIL-SPECIFIC OSINT ENGINES
# ---------------------------------------------------------------------------

def _check_gravatar_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Query Gravatar using MD5 hash of the email address."""
    md5 = _email_md5(email)
    try:
        resp = get_with_retry(
            f"https://en.gravatar.com/{md5}.json",
            timeout=HTTP_TIMEOUT, headers=HEADERS,
        )
        if resp.status_code != 200:
            return None
        entry = resp.json().get("entry", [{}])[0]
        if not entry:
            return None
        display_name = (
            entry.get("displayName")
            or entry.get("preferredUsername")
            or email.split("@")[0]
        )
        bio = entry.get("aboutMe") or entry.get("currentLocation") or ""
        photos = entry.get("photos", [])
        avatar = (
            entry.get("thumbnailUrl")
            or (photos[0].get("value") if photos else None)
            or f"https://www.gravatar.com/avatar/{md5}?d=identicon"
        )
        # Collect linked accounts from Gravatar
        accounts = entry.get("accounts", [])
        linked = [a.get("domain", "") for a in accounts if a.get("domain")]
        kws = _extract_keywords(bio) or ["gravatar-verified"]
        if linked:
            kws = list(dict.fromkeys(kws + linked))[:8]
        return _make_record(
            "Gravatar", "Global Identity",
            entry.get("profileUrl", f"https://gravatar.com/{md5}"),
            display_name, 99,
            associated_email=email,
            bio_keywords=kws,
            avatar_url=avatar,
            extra={"linked_accounts": linked},
        )
    except Exception:
        return None


def _check_emailrep(email: str) -> Optional[Dict[str, Any]]:
    """
    Query EmailRep.io for email reputation, breach status, and activity signals.
    Public endpoint — no key required.
    """
    try:
        resp = get_with_retry(
            f"https://emailrep.io/{quote(email)}",
            timeout=HTTP_TIMEOUT,
            headers={**HEADERS, "Accept": "application/json"},
        )
        if resp.status_code not in (200, 404):
            return None
        if resp.status_code == 404:
            return None
        data = resp.json()
        reputation = data.get("reputation", "unknown")  # high/medium/low/none
        details = data.get("details", {})
        is_disposable = details.get("disposable", False)
        is_suspicious = details.get("suspicious", False)
        malicious_activity = details.get("malicious_activity", False)
        credentials_leaked = details.get("credentials_leaked", False)
        breach_count = details.get("breach_count", 0)
        first_seen = details.get("first_seen", "")
        last_seen = details.get("last_seen", "")
        profiles = details.get("profiles", [])

        summary_parts = []
        if reputation:
            summary_parts.append(f"reputation:{reputation}")
        if is_disposable:
            summary_parts.append("disposable")
        if credentials_leaked:
            summary_parts.append(f"credentials-leaked")
        if breach_count:
            summary_parts.append(f"{breach_count}-breaches")
        if malicious_activity:
            summary_parts.append("malicious-activity")
        if profiles:
            summary_parts.extend(profiles[:4])

        confidence = 90
        if reputation == "high":
            confidence = 97
        elif reputation == "medium":
            confidence = 88
        elif reputation in ("low", "none"):
            confidence = 75

        return _make_record(
            "EmailRep.io", "Email Intelligence",
            f"https://emailrep.io/{quote(email)}",
            f"EmailRep — {reputation.title()} Reputation",
            confidence,
            associated_email=email,
            bio_keywords=summary_parts[:8] or ["emailrep-checked"],
            extra={
                "reputation": reputation,
                "breach_count": breach_count,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "is_disposable": is_disposable,
                "is_suspicious": is_suspicious,
                "credentials_leaked": credentials_leaked,
                "linked_profiles": profiles,
            },
        )
    except Exception:
        return None


def _check_hibp_breaches(email: str) -> Optional[Dict[str, Any]]:
    """
    HaveIBeenPwned — publicly accessible breach listing (no API key required
    for the v2 public list of breach names). Returns a record listing which
    known breaches the email was found in.
    """
    try:
        # HIBP v3 requires an API key for /breachedaccount; however we can
        # use the public pwnedpasswords approach or check via emailrep.
        # Use v2 unauthenticated for breach name list (deprecated but still
        # functional for public queries without the Pwned-Api-Key header).
        resp = get_with_retry(
            f"https://haveibeenpwned.com/api/v2/breachedaccount/{quote(email)}",
            timeout=HTTP_TIMEOUT,
            headers={
                **HEADERS,
                "Accept": "application/json",
                "User-Agent": "OSINT-Dashboard-Research-Tool/1.0",
            },
        )
        if resp.status_code == 404:
            # Confirmed not found in any breach
            return _make_record(
                "HaveIBeenPwned", "Breach Intelligence",
                "https://haveibeenpwned.com",
                "No Breaches Found ✓",
                95,
                associated_email=email,
                bio_keywords=["no-breaches", "clean-email"],
            )
        if resp.status_code == 200:
            breaches = resp.json()
            names = [b.get("Name", "") for b in breaches if b.get("Name")]
            kws = (["hibp-breach"] + names[:7])[:8]
            return _make_record(
                "HaveIBeenPwned", "Breach Intelligence",
                f"https://haveibeenpwned.com/account/{quote(email)}",
                f"Exposed in {len(names)} Breach(es)",
                98,
                associated_email=email,
                bio_keywords=kws,
                extra={"breach_names": names},
            )
        # 401 = key required but v3 endpoint hit
        if resp.status_code == 401:
            return _make_record(
                "HaveIBeenPwned", "Breach Intelligence",
                "https://haveibeenpwned.com",
                "HIBP (API key required for detail)",
                70,
                associated_email=email,
                bio_keywords=["hibp-api-key-needed"],
            )
    except Exception:
        pass
    return None


def _check_hunter_domain(email_domain: str) -> Optional[Dict[str, Any]]:
    """
    Query Hunter.io public domain endpoint to get organisation intelligence
    linked to the email domain. No API key required for the free public tier.
    """
    if email_domain in FREE_EMAIL_PROVIDERS:
        return None
    try:
        resp = get_with_retry(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": email_domain, "limit": 5},
            timeout=HTTP_TIMEOUT,
            headers=HEADERS,
        )
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", {})
        org = data.get("organization") or data.get("domain") or email_domain
        description = data.get("description") or ""
        country = data.get("country") or ""
        twitter = data.get("twitter") or ""
        linkedin = data.get("linkedin") or ""
        emails = data.get("emails", [])
        kws = _extract_keywords(f"{description} {country}") or [email_domain]
        if twitter:
            kws.append(f"twitter:{twitter}")
        if linkedin:
            kws.append("linkedin-org")
        return _make_record(
            "Hunter.io Domain", "Corporate Intelligence",
            f"https://hunter.io/domain/{email_domain}",
            org,
            88,
            associated_email=f"*@{email_domain}",
            bio_keywords=kws[:8],
            extra={
                "org_name": org,
                "country": country,
                "twitter": twitter,
                "linkedin": linkedin,
                "public_emails_found": len(emails),
            },
        )
    except Exception:
        return None


def _check_clearbit_person(email: str) -> Optional[Dict[str, Any]]:
    """
    Clearbit Person Enrichment — publicly accessible enrichment endpoint.
    Returns person profile data linked to a corporate email address.
    """
    try:
        resp = get_with_retry(
            f"https://person.clearbit.com/v2/people/find",
            params={"email": email},
            timeout=HTTP_TIMEOUT,
            headers={**HEADERS, "Accept": "application/json"},
        )
        if resp.status_code not in (200, 202):
            return None
        data = resp.json()
        if not data or isinstance(data, str):
            return None
        name = data.get("name", {}) or {}
        full_name = name.get("fullName") or email.split("@")[0]
        bio = data.get("bio") or ""
        location = data.get("location") or ""
        avatar = data.get("avatar") or ""
        employment = data.get("employment", {}) or {}
        company = employment.get("name") or ""
        role = employment.get("role") or ""
        github = (data.get("github") or {}).get("handle") or ""
        twitter = (data.get("twitter") or {}).get("handle") or ""
        linkedin = (data.get("linkedin") or {}).get("handle") or ""
        kws = _extract_keywords(f"{bio} {location} {company} {role}") or ["clearbit-person"]
        if github:
            kws.append(f"github:{github}")
        if twitter:
            kws.append(f"twitter:{twitter}")
        return _make_record(
            "Clearbit Person", "Identity Enrichment",
            f"https://clearbit.com",
            full_name,
            92,
            associated_email=email,
            bio_keywords=kws[:8],
            avatar_url=avatar,
            extra={
                "company": company,
                "role": role,
                "github_handle": github,
                "twitter_handle": twitter,
                "linkedin_handle": linkedin,
                "location": location,
            },
        )
    except Exception:
        return None


def _check_github_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Search GitHub for users by email (only finds accounts with public email)."""
    headers = dict(HEADERS)
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        resp = get_with_retry(
            "https://api.github.com/search/users",
            params={"q": f"{email} in:email", "per_page": 1},
            timeout=HTTP_TIMEOUT,
            headers=headers,
        )
        if resp.status_code != 200:
            return None
        items = resp.json().get("items", [])
        if not items:
            return None
        username = items[0]["login"]
        profile = _check_github(username)
        if profile:
            profile["associated_email"] = email
            profile["confidence"] = 99
        return profile
    except Exception:
        return None


def _check_github_org_by_domain(email_domain: str) -> Optional[Dict[str, Any]]:
    """
    Search GitHub for organisations matching the email domain (for corporate emails).
    """
    if email_domain in FREE_EMAIL_PROVIDERS:
        return None
    headers = dict(HEADERS)
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    # Extract the primary domain name (strip TLD) as search query
    domain_label = email_domain.split(".")[0]
    try:
        resp = get_with_retry(
            "https://api.github.com/search/users",
            params={"q": f"{domain_label} type:org", "per_page": 1},
            timeout=HTTP_TIMEOUT,
            headers=headers,
        )
        if resp.status_code != 200:
            return None
        items = resp.json().get("items", [])
        if not items:
            return None
        org = items[0]
        return _make_record(
            "GitHub Org", "Developer / Code",
            org.get("html_url", f"https://github.com/{org['login']}"),
            org.get("login", domain_label),
            80,
            associated_email=f"*@{email_domain}",
            bio_keywords=[f"github-org", email_domain, domain_label],
            avatar_url=org.get("avatar_url", ""),
        )
    except Exception:
        return None


def _probe_domain_mx(email_domain: str) -> Optional[Dict[str, Any]]:
    """
    Query MX records for the email domain using Google's DNS-over-HTTPS API.
    Returns intelligence about the email infrastructure (GSuite, O365, etc.).
    """
    try:
        resp = get_with_retry(
            "https://dns.google/resolve",
            params={"name": email_domain, "type": "MX"},
            timeout=HTTP_TIMEOUT,
            headers={**HEADERS, "Accept": "application/json"},
        )
        if resp.status_code != 200:
            return None
        answers = resp.json().get("Answer", [])
        mx_records = []
        for ans in answers:
            data = ans.get("data", "")
            # MX record data: "10 mail.example.com."
            parts = data.strip().rstrip(".").split()
            if len(parts) >= 2:
                mx_records.append(parts[-1].lower())

        if not mx_records:
            return None

        # Classify the email infrastructure
        infra_type = "Custom Mail Server"
        infra_hints = []
        for mx in mx_records:
            if "google" in mx or "googlemail" in mx:
                infra_type = "Google Workspace"
                infra_hints.append("gsuite")
            elif "outlook" in mx or "protection.outlook" in mx or "microsoft" in mx:
                infra_type = "Microsoft 365"
                infra_hints.append("microsoft-365")
            elif "amazonses" in mx:
                infra_type = "Amazon SES"
                infra_hints.append("aws-ses")
            elif "mailgun" in mx:
                infra_type = "Mailgun"
                infra_hints.append("mailgun")
            elif "sendgrid" in mx:
                infra_type = "SendGrid"
                infra_hints.append("sendgrid")
            elif "protonmail" in mx:
                infra_type = "ProtonMail"
                infra_hints.append("protonmail-infra")
            elif "fastmail" in mx:
                infra_type = "Fastmail"
                infra_hints.append("fastmail-infra")

        kws = list(dict.fromkeys([email_domain, infra_type.lower().replace(" ", "-")] + infra_hints + mx_records[:3]))
        return _make_record(
            "MX Infrastructure", "Email Infrastructure",
            f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{email_domain}&run=toolpage",
            f"{email_domain} → {infra_type}",
            85,
            associated_email=f"*@{email_domain}",
            bio_keywords=kws[:8],
            extra={"mx_records": mx_records, "infra_type": infra_type},
        )
    except Exception:
        return None


def _probe_domain_spf_dmarc(email_domain: str) -> Optional[Dict[str, Any]]:
    """Check SPF and DMARC records — signals email security posture."""
    records_found = []
    try:
        # SPF (TXT record on root domain)
        resp = get_with_retry(
            "https://dns.google/resolve",
            params={"name": email_domain, "type": "TXT"},
            timeout=HTTP_TIMEOUT,
            headers={**HEADERS, "Accept": "application/json"},
        )
        if resp.status_code == 200:
            for ans in resp.json().get("Answer", []):
                data = ans.get("data", "")
                if "v=spf1" in data.lower():
                    records_found.append("spf-configured")
    except Exception:
        pass

    try:
        # DMARC (TXT record on _dmarc.domain)
        resp = get_with_retry(
            "https://dns.google/resolve",
            params={"name": f"_dmarc.{email_domain}", "type": "TXT"},
            timeout=HTTP_TIMEOUT,
            headers={**HEADERS, "Accept": "application/json"},
        )
        if resp.status_code == 200:
            for ans in resp.json().get("Answer", []):
                if "v=dmarc1" in ans.get("data", "").lower():
                    records_found.append("dmarc-configured")
    except Exception:
        pass

    if not records_found:
        records_found = ["no-spf-dmarc"]

    return _make_record(
        "Email Security (SPF/DMARC)", "Email Infrastructure",
        f"https://mxtoolbox.com/dmarc/{email_domain}",
        f"{email_domain} Email Security",
        82,
        associated_email=f"*@{email_domain}",
        bio_keywords=[email_domain] + records_found,
        extra={"security_records": records_found},
    )


# ---------------------------------------------------------------------------
# HANDLE-BASED PLATFORM WORKERS
# ---------------------------------------------------------------------------

def _check_github(username: str) -> Optional[Dict[str, Any]]:
    """Query GitHub User API."""
    headers = dict(HEADERS)
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        resp = get_with_retry(
            f"https://api.github.com/users/{username}",
            timeout=HTTP_TIMEOUT, headers=headers,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        bio = data.get("bio") or ""
        company = data.get("company") or ""
        location = data.get("location") or ""
        return _make_record(
            "GitHub", "Developer / Code",
            data.get("html_url", f"https://github.com/{username}"),
            data.get("name") or username,
            98,
            associated_email=data.get("email") or "—",
            bio_keywords=_extract_keywords(f"{bio} {company} {location}") or ["github-developer"],
            followers=data.get("followers", 0),
            public_repos=data.get("public_repos", 0),
            avatar_url=data.get("avatar_url", ""),
        )
    except Exception:
        return None


def _check_gitlab(username: str) -> Optional[Dict[str, Any]]:
    """Query GitLab User Search API v4."""
    try:
        resp = get_with_retry(
            f"https://gitlab.com/api/v4/users?username={username}",
            timeout=HTTP_TIMEOUT, headers=HEADERS,
        )
        if resp.status_code != 200:
            return None
        arr = resp.json()
        if not arr or not isinstance(arr, list):
            return None
        user = arr[0]
        if user.get("username", "").lower() != username.lower():
            return None
        bio = user.get("bio") or ""
        org = user.get("organization") or ""
        return _make_record(
            "GitLab", "Developer / Code",
            user.get("web_url", f"https://gitlab.com/{username}"),
            user.get("name") or username,
            96,
            bio_keywords=_extract_keywords(f"{bio} {org}") or ["gitlab-user"],
            avatar_url=user.get("avatar_url", ""),
        )
    except Exception:
        return None


def _check_devto(username: str) -> Optional[Dict[str, Any]]:
    """Query Dev.to User API."""
    try:
        resp = get_with_retry(
            f"https://dev.to/api/users/by_username?url={username}",
            timeout=HTTP_TIMEOUT, headers=HEADERS,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not data.get("id"):
            return None
        bio = data.get("summary") or data.get("location") or ""
        return _make_record(
            "Dev.to", "Tech / Blogging",
            f"https://dev.to/{username}",
            data.get("name") or username,
            95,
            bio_keywords=_extract_keywords(bio) or ["devto-author"],
            avatar_url=data.get("profile_image", ""),
        )
    except Exception:
        return None


def _check_hackernews(username: str) -> Optional[Dict[str, Any]]:
    """Query HackerNews Firebase User API."""
    try:
        resp = get_with_retry(
            f"https://hacker-news.firebaseio.com/v0/user/{username}.json",
            timeout=HTTP_TIMEOUT, headers=HEADERS,
        )
        if resp.status_code != 200 or not resp.text or resp.text == "null":
            return None
        data = resp.json()
        if not data or "id" not in data:
            return None
        about = re.sub(r"<[^>]+>", " ", data.get("about") or "")
        return _make_record(
            "HackerNews", "Tech / Community",
            f"https://news.ycombinator.com/user?id={username}",
            username,
            92,
            bio_keywords=_extract_keywords(about) or [f"karma-{data.get('karma', 0)}", "hn-member"],
        )
    except Exception:
        return None


def _check_keybase(username: str) -> Optional[Dict[str, Any]]:
    """Query Keybase API 1.0."""
    try:
        resp = get_with_retry(
            "https://keybase.io/_/api/1.0/user/lookup.json",
            params={"username": username},
            timeout=HTTP_TIMEOUT, headers=HEADERS,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("status", {}).get("code") != 0 or not data.get("them"):
            return None
        them = data["them"][0]
        profile = them.get("profile") or {}
        bio = profile.get("bio") or ""
        location = profile.get("location") or ""
        pictures = (them.get("pictures") or {}).get("primary") or {}
        return _make_record(
            "Keybase", "Identity / Crypto",
            f"https://keybase.io/{username}",
            profile.get("full_name") or username,
            94,
            bio_keywords=_extract_keywords(f"{bio} {location}") or ["pgp-verified"],
            avatar_url=pictures.get("url", ""),
        )
    except Exception:
        return None


def _check_dockerhub(username: str) -> Optional[Dict[str, Any]]:
    """Query DockerHub Public User API v2."""
    try:
        resp = get_with_retry(
            f"https://hub.docker.com/v2/users/{username}/",
            timeout=HTTP_TIMEOUT, headers=HEADERS,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not data.get("username"):
            return None
        company = data.get("company") or data.get("location") or ""
        return _make_record(
            "DockerHub", "DevOps / Containers",
            f"https://hub.docker.com/u/{username}",
            data.get("full_name") or username,
            90,
            bio_keywords=_extract_keywords(company) or ["docker-publisher"],
            avatar_url=data.get("gravatar_url", ""),
        )
    except Exception:
        return None


def _check_reddit(username: str) -> Optional[Dict[str, Any]]:
    """Query Reddit Public User API."""
    try:
        headers = {**HEADERS, "User-Agent": f"osint-analyzer-script/{username}"}
        resp = get_with_retry(
            f"https://www.reddit.com/user/{username}/about.json",
            timeout=HTTP_TIMEOUT, headers=headers,
        )
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", {})
        if not data.get("name"):
            return None
        sub = data.get("subreddit") or {}
        bio = sub.get("public_description") or ""
        return _make_record(
            "Reddit", "Social / Community",
            f"https://reddit.com/user/{username}",
            sub.get("title") or username,
            91,
            bio_keywords=_extract_keywords(bio) or ["reddit-user"],
            followers=data.get("subscribers", 0),
            avatar_url=sub.get("icon_img", "").split("?")[0],
        )
    except Exception:
        return None


def _check_npm(username: str) -> Optional[Dict[str, Any]]:
    """Query npm Package Registry User Endpoint."""
    try:
        resp = get_with_retry(
            f"https://registry.npmjs.org/-/user/org.couchdb.user:{username}",
            timeout=HTTP_TIMEOUT, headers=HEADERS,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not data.get("name"):
            return None
        return _make_record(
            "npm Registry", "Developer / Packages",
            f"https://www.npmjs.com/~{username}",
            data.get("name") or username,
            92,
            associated_email=data.get("email") or "—",
            bio_keywords=["npm-author"],
        )
    except Exception:
        return None


def _check_pypi(username: str) -> Optional[Dict[str, Any]]:
    """Verify PyPI author profile with strict HTML signature check."""
    try:
        url = f"https://pypi.org/user/{username}/"
        resp = get_with_retry(url, timeout=HTTP_TIMEOUT, headers=HEADERS)
        if resp.status_code != 200:
            return None
        if "author-profile" not in resp.text or username.lower() not in resp.text.lower():
            return None
        return _make_record(
            "PyPI", "Developer / Python",
            url,
            username,
            90,
            bio_keywords=["python-package-author"],
        )
    except Exception:
        return None


def _check_medium(username: str) -> Optional[Dict[str, Any]]:
    """Verify Medium author profile with strict signature check."""
    try:
        url = f"https://medium.com/@{username}"
        resp = get_with_retry(url, timeout=HTTP_TIMEOUT, headers=HEADERS)
        if resp.status_code != 200:
            return None
        if ('"name":"' not in resp.text and "og:title" not in resp.text) or username.lower() not in resp.text.lower():
            return None
        return _make_record(
            "Medium", "Publishing / Writing",
            url,
            username,
            85,
            bio_keywords=["medium-writer"],
        )
    except Exception:
        return None


def _check_codepen(username: str) -> Optional[Dict[str, Any]]:
    """Verify CodePen profile with strict signature check."""
    try:
        url = f"https://codepen.io/{username}"
        resp = get_with_retry(url, timeout=HTTP_TIMEOUT, headers=HEADERS)
        if resp.status_code != 200:
            return None
        if "profile-name" not in resp.text and "cp_embed" not in resp.text:
            return None
        return _make_record(
            "CodePen", "Frontend / Creative",
            url,
            username,
            86,
            bio_keywords=["codepen-creator"],
        )
    except Exception:
        return None


def _check_hashnode(username: str) -> Optional[Dict[str, Any]]:
    """Query Hashnode public GraphQL API."""
    try:
        query = """
        query GetUser($username: String!) {
          user(username: $username) {
            name
            tagline
            numFollowers
            location
            photo
          }
        }
        """
        resp = requests.post(
            "https://api.hashnode.com",
            json={"query": query, "variables": {"username": username}},
            headers={**HEADERS, "Content-Type": "application/json"},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        user = (resp.json().get("data") or {}).get("user")
        if not user or not user.get("name"):
            return None
        tagline = user.get("tagline") or user.get("location") or ""
        return _make_record(
            "Hashnode", "Tech / Blogging",
            f"https://hashnode.com/@{username}",
            user.get("name") or username,
            88,
            bio_keywords=_extract_keywords(tagline) or ["hashnode-blogger"],
            followers=user.get("numFollowers", 0),
            avatar_url=user.get("photo") or "",
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CANDIDATE HANDLE GENERATION — MULTIPLE STRATEGIES
# ---------------------------------------------------------------------------

def _generate_candidate_handles(local_part: str) -> List[str]:
    """
    Generate a broad set of candidate username handles from an email local-part.
    Handles: dots, dashes, underscores, number suffixes, camelCase splits, etc.
    """
    clean = local_part.strip().lstrip("@")
    if not clean:
        return []

    # Tokenize: split on dots, dashes, underscores, digits transitions
    tokens = re.split(r"[.\-_]", clean)
    tokens = [t for t in tokens if t]

    # Also extract alphabetic and numeric portions separately
    alpha_parts = [re.sub(r"[^a-zA-Z]", "", t) for t in tokens]
    alpha_parts = [p for p in alpha_parts if len(p) >= 2]

    candidates: List[str] = []

    # Strategy 1: the raw local part as-is
    candidates.append(clean)

    if len(tokens) > 1:
        all_tokens = tokens
        # Strategy 2: joined
        candidates.append("".join(all_tokens))
        # Strategy 3: dot-separated
        candidates.append(".".join(all_tokens))
        # Strategy 4: dash-separated
        candidates.append("-".join(all_tokens))
        # Strategy 5: underscore-separated
        candidates.append("_".join(all_tokens))
        # Strategy 6: first token only (first name)
        candidates.append(all_tokens[0])
        # Strategy 7: last token only (last name)
        candidates.append(all_tokens[-1])
        # Strategy 8: first initial + last name
        if len(all_tokens) >= 2:
            candidates.append(all_tokens[0][0] + all_tokens[-1])
        # Strategy 9: first name + last initial
        if len(all_tokens) >= 2:
            candidates.append(all_tokens[0] + all_tokens[-1][0])
    else:
        # Single token — try stripping trailing digits
        stripped = re.sub(r"\d+$", "", clean)
        if stripped and stripped != clean:
            candidates.append(stripped)
        # Add version with numeric suffix removed and just the alpha part
        if alpha_parts:
            candidates.append(alpha_parts[0])

    # Deduplicate preserving order, min length 2
    seen: set = set()
    unique: List[str] = []
    for c in candidates:
        lc = c.lower()
        if lc and len(lc) >= 2 and lc not in seen:
            seen.add(lc)
            unique.append(lc)
    return unique


# ---------------------------------------------------------------------------
# MAIN EMAIL OSINT ENTRYPOINT
# ---------------------------------------------------------------------------

def run_user_osint(username_value: str) -> pd.DataFrame:
    """
    Executes Email-Centric OSINT & Service Linking.
    Accepts:
      - Full email addresses: user@domain.com  (primary mode)
      - Plain handles / usernames: johndoe      (legacy mode)

    For email inputs:
      Phase 1: Email-specific APIs (Gravatar, EmailRep, HIBP, Hunter, Clearbit, GitHub email search)
      Phase 2: Domain intelligence (MX, SPF/DMARC, GitHub org)
      Phase 3: Handle-based platform sweep using candidates derived from local-part

    Always returns at least one record (the primary target record).
    """
    raw_input = username_value.strip().lstrip("@")
    if not raw_input:
        raise OsintLookupError("Email address or username cannot be empty.")

    is_email = bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", raw_input))
    results: List[Dict[str, Any]] = []
    seen_platforms: set = set()

    if is_email:
        email_clean = raw_input.lower()
        local_part, email_domain = email_clean.split("@", 1)
        domain_type = _classify_email_domain(email_domain)
        md5 = _email_md5(email_clean)

        # ── Primary anchor record ─────────────────────────────────────────
        primary = _make_record(
            "Email Target",
            f"Email / {domain_type}",
            f"https://{email_domain}",
            email_clean,
            95,
            associated_email=email_clean,
            bio_keywords=[email_domain, domain_type.lower().replace(" ", "-"), "osint-target"],
            avatar_url=f"https://www.gravatar.com/avatar/{md5}?d=identicon",
        )

        # ── Phase 1: Email-specific lookups ───────────────────────────────
        email_engines = [
            lambda: _check_gravatar_by_email(email_clean),
            lambda: _check_emailrep(email_clean),
            lambda: _check_hibp_breaches(email_clean),
            lambda: _check_clearbit_person(email_clean),
            lambda: _check_github_by_email(email_clean),
        ]
        for engine_fn in email_engines:
            try:
                res = engine_fn()
                if res and res["platform"] not in seen_platforms:
                    seen_platforms.add(res["platform"])
                    # Update primary avatar if gravatar found one
                    if res["platform"] == "Gravatar" and res.get("avatar_url"):
                        primary["avatar_url"] = res["avatar_url"]
                    results.append(res)
            except Exception:
                continue

        # ── Phase 2: Domain intelligence ──────────────────────────────────
        domain_engines = [
            lambda: _probe_domain_mx(email_domain),
            lambda: _probe_domain_spf_dmarc(email_domain),
            lambda: _check_hunter_domain(email_domain),
            lambda: _check_github_org_by_domain(email_domain),
        ]
        for engine_fn in domain_engines:
            try:
                res = engine_fn()
                if res and res["platform"] not in seen_platforms:
                    seen_platforms.add(res["platform"])
                    results.append(res)
            except Exception:
                continue

        # Insert primary record first
        results.insert(0, primary)
        seen_platforms.add("Email Target")

        # ── Phase 3: Handle-based platform sweep ─────────────────────────
        candidate_handles = _generate_candidate_handles(local_part)

    else:
        # Legacy handle mode
        candidate_handles = _generate_candidate_handles(raw_input)
        email_clean = ""

    # Platform workers to test per handle
    handle_workers = [
        _check_github,
        _check_gitlab,
        _check_devto,
        _check_hackernews,
        _check_keybase,
        _check_dockerhub,
        _check_reddit,
        _check_npm,
        _check_pypi,
        _check_medium,
        _check_codepen,
        _check_hashnode,
    ]

    for handle in candidate_handles:
        for worker_fn in handle_workers:
            try:
                res = worker_fn(handle)
                if res and res["platform"] not in seen_platforms:
                    seen_platforms.add(res["platform"])
                    if is_email and email_clean:
                        res.setdefault("associated_email", email_clean)
                    results.append(res)
            except Exception:
                continue

    if not results:
        tested = ", ".join(f"'{h}'" for h in candidate_handles[:5])
        raise OsintLookupError(
            f"No verified platform hits for '{raw_input}'. "
            f"Tested handles: {tested} — across 20+ OSINT engines."
        )

    now = datetime.now()
    for row in results:
        row.setdefault("discovered_at", now)

    return pd.DataFrame(results)
