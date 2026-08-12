"""
Shared HTTP helper with basic retry/backoff for transient failures.

Retries on: connection errors, timeouts, 429 (rate limited), 5xx.
Does NOT retry on 4xx (other than 429) — a 404 means "not found", not
"try again", and retrying it just wastes time and hammers the target.
"""

import hashlib
import random
import re
import time
import requests

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def _seed(value: str) -> random.Random:
    """Used for deterministic layout and mock generation randomness."""
    h = hashlib.sha256(value.encode()).hexdigest()
    return random.Random(int(h[:12], 16))



def get_with_retry(url: str, retries: int = 2, backoff: float = 0.6, **kwargs) -> requests.Response:
    """
    Thin wrapper around requests.get with exponential backoff.
    Raises the underlying requests exception (or returns the last response)
    if all attempts are exhausted — callers already catch requests.RequestException.
    """
    last_exc = None
    last_resp = None

    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, **kwargs)
        except requests.RequestException as e:
            last_exc = e
        else:
            if resp.status_code not in RETRYABLE_STATUS:
                return resp
            last_resp = resp

        if attempt < retries:
            time.sleep(backoff * (2 ** attempt))

    if last_resp is not None:
        return last_resp
    raise last_exc
