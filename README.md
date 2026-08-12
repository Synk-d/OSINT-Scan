# OSINT-Scan — Frontend + Backend (v0.4.0)

## What's real vs mock now

| Piece | Status |
|---|---|
| Domain subdomain enumeration | **Real** — certificate transparency via crt.sh |
| DNS A / MX resolution | **Real** — dnspython |
| IP → country / ISP / lat-lon | **Real** — ip-api.com (free tier, no key) |
| WHOIS registrar | **Real** — python-whois |
| GitHub / Reddit / Keybase profile + bio | **Real** — public JSON APIs, no key |
| Twitter/X, Instagram, LinkedIn, Telegram | **Existence-check only** (HTTP status), no bio scraping — see note below |
| Entity relationships | **Real** — correlates shared IP blocks, username reuse, matching emails, bio mentions |
| PostgreSQL persistence | **Real**, optional — silently skipped if no DB is reachable |

If any live lookup fails (no internet, rate-limited, invalid target), that
specific piece transparently falls back to deterministic mock data so the UI
never breaks — you'll see `domain mock` / `user mock` in the small tag next
to the timestamp in the header when that happens.

### Why some platforms are existence-only
Twitter/X, Instagram, LinkedIn, and Telegram don't offer a public,
unauthenticated API for profile data, and their web pages are behind
anti-bot/auth walls. Rather than scrape around that, these platforms only
get a genuine HTTP-reachability check (does the profile URL 404 or not) —
real signal, honestly labeled, no fabricated bio content.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env        # optional — only needed for DB persistence
streamlit run app.py
```

Runs fully without a database — persistence is opt-in.

### Optional: enable PostgreSQL persistence

```bash
docker compose up -d          # starts Postgres + applies db/schema.sql automatically
python -m db.init_db          # re-applies schema if you point at an existing DB instead
```

Then fill in `.env` with your DB credentials (defaults match `docker-compose.yml`).
Every successful **live** sweep gets written to `targets`, `domain_intel`,
`user_intel`, and `entity_relationships`. Mock-fallback data is never
persisted, so your DB only ever fills up with real findings.

### Force mock mode
Set `FORCE_MOCK_DATA=true` in `.env` to skip live lookups entirely — useful
for demos or working offline.

## Project layout

```
app.py                        # Streamlit frontend (unchanged UI, now backend-wired)
workers/
  domain_worker.py            # real: crt.sh + DNS + WHOIS + ip-api
  user_worker.py               # real: GitHub/Reddit/Keybase APIs + existence checks
  relationship_engine.py      # real: correlation logic (shared IP/email/username/bio)
  mock_fallback.py            # deterministic mock generators (the fallback layer)
db/
  schema.sql                   # CREATE TABLE statements (idempotent)
  connection.py                # psycopg2 connection handling + DatabaseUnavailable
  repository.py                # all parameterized SQL — inserts + reads
  init_db.py                   # `python -m db.init_db` to apply schema.sql manually
docker-compose.yml             # local Postgres for dev
.env.example                   # copy to .env
```

## Rate limits / politeness to third parties
- crt.sh: no documented hard limit, but the code caps subdomain enumeration
  to 12 hosts (`MAX_SUBDOMAINS` in `domain_worker.py`) to keep sweeps fast
  and avoid hammering it.
- ip-api.com free tier: ~45 requests/minute. A 0.4s delay between subdomain
  lookups keeps a full sweep well under that.
- GitHub unauthenticated API: 60 requests/hour per IP. Set `GITHUB_TOKEN` in
  `.env` (a personal access token, no scopes required) to bump that to
  5000/hour — see `.env.example` for the link to generate one.
- All HTTP calls now retry on transient failures (connection errors,
  timeouts, 429, 5xx) with exponential backoff via `workers/net_utils.py`,
  but do NOT retry on 404 — a "not found" is a real answer, not a glitch.

## Known limitations to be aware of
- WHOIS responses vary wildly by registrar/TLD and sometimes get rate
  limited or blocked outright — registrar field falls back to
  `"Unavailable"` rather than guessing.
- Existence-only platform checks (Twitter/X etc.) can false-positive if a
  platform serves a 200 status for a client-side-rendered "not found" page.
  Confidence score for these rows is capped at 55 to reflect that weaker
  signal, versus 90+ for API-confirmed hits.
