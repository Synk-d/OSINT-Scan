from __future__ import annotations

"""
run_user_osint(username_value) — real implementation.

Two tiers of signal, by design:

1. Platforms with a clean public JSON API (GitHub, Reddit, Keybase) — we get
   real bio text, confirmed existence, and (for GitHub) a public email if the
   user has one set. This is genuine OSINT signal.

2. Platforms without an unauthenticated public API (Twitter/X, Instagram,
   LinkedIn, Telegram) — we only do an existence check (HTTP status of the
   profile URL). We do NOT scrape these pages: they're auth-walled / anti-bot
   protected by design, and reliably extracting bio text would mean working
   around that. Bio keywords for these rows come back empty and confidence
   reflects "profile exists" rather than "bio content confirmed" — this is
   flagged in the `bio_keywords` field itself so it's not silently faked.

If every single check fails (e.g. no internet from this environment), the
caller falls back to mock data.
"""

import os
from datetime import datetime
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import pandas as pd

import requests

from workers.net_utils import get_with_retry

HTTP_TIMEOUT = 6
HEADERS = {"User-Agent": "osint-dashboard-recon/1.0"}
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()


class OsintLookupError(Exception):
    """Raised when live user lookup cannot proceed."""


def _extract_keywords(text: str, limit: int = 6) -> list[str]:
    keywords = [w.strip("#.,!").lower() for w in (text or "").split() if len(w) > 3]
    return keywords[:limit] or ["no-bio-set"]


def _check_github(username: str) -> Optional[dict]:
    headers = dict(HEADERS)
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        resp = get_with_retry(
            f"https://api.github.com/users/{username}", timeout=HTTP_TIMEOUT, headers=headers,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        return {
            "platform": "GitHub",
            "profile_url": data.get("html_url", f"https://github.com/{username}"),
            "associated_email": data.get("email"),
            "bio_keywords": _extract_keywords(data.get("bio") or ""),
            "confidence": 97,
        }
    except requests.RequestException:
        return None


def _check_reddit(username: str) -> Optional[dict]:
    try:
        resp = get_with_retry(
            f"https://www.reddit.com/user/{username}/about.json",
            timeout=HTTP_TIMEOUT, headers=HEADERS,
        )
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", {})
        bio = data.get("subreddit", {}).get("public_description", "") or ""
        return {
            "platform": "Reddit",
            "profile_url": f"https://reddit.com/user/{username}",
            "associated_email": None,
            "bio_keywords": _extract_keywords(bio),
            "confidence": 90,
        }
    except requests.RequestException:
        return None


def _check_keybase(username: str) -> Optional[dict]:
    try:
        resp = get_with_retry(
            "https://keybase.io/_/api/1.0/user/lookup.json",
            params={"username": username}, timeout=HTTP_TIMEOUT, headers=HEADERS,
        )
        data = resp.json()
        if data.get("status", {}).get("code") != 0 or not data.get("them"):
            return None
        them = data["them"][0]
        bio = (them.get("profile", {}) or {}).get("bio", "") or ""
        return {
            "platform": "Keybase",
            "profile_url": f"https://keybase.io/{username}",
            "associated_email": None,
            "bio_keywords": _extract_keywords(bio),
            "confidence": 93,
        }
    except (requests.RequestException, ValueError, KeyError, IndexError):
        return None


# platform name -> profile URL template, for existence-only checks
EXISTENCE_ONLY = {
    "Twitter / X": "https://x.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "LinkedIn": "https://www.linkedin.com/in/{u}",
    "Telegram": "https://t.me/{u}",
}


def _check_existence_only(platform: str, url_template: str, username: str) -> Optional[dict]:
    url = url_template.format(u=username)
    try:
        resp = get_with_retry(url, timeout=HTTP_TIMEOUT, headers=HEADERS, allow_redirects=True)
        # Many of these platforms return 200 for both real and "not found" pages
        # (client-side rendered 404s), so treat this as a weak existence signal only.
        if resp.status_code >= 400:
            return None
        return {
            "platform": platform,
            "profile_url": url,
            "associated_email": None,
            "bio_keywords": ["existence-check-only"],
            "confidence": 55,
        }
    except requests.RequestException:
        return None


def run_user_osint(username_value: str) -> "pd.DataFrame":
    import pandas as pd

    username_value = username_value.strip().lstrip("@")
    if not username_value:
        raise OsintLookupError("Empty username")

    checks = [
        _check_github(username_value),
        _check_reddit(username_value),
        _check_keybase(username_value),
    ]
    for platform, template in EXISTENCE_ONLY.items():
        checks.append(_check_existence_only(platform, template, username_value))

    hits = [c for c in checks if c]
    if not hits:
        raise OsintLookupError(f"No platform hits and no connectivity for '{username_value}'")

    now = datetime.now()
    for h in hits:
        h["discovered_at"] = now

    return pd.DataFrame(hits)
