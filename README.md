<div align="center">

# ◉ OSINT-SCAN

### Open Source Intelligence Aggregation & Threat Analysis Dashboard

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.38%2B-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![Gemini AI](https://img.shields.io/badge/Gemini_AI-2.5_Flash-4285F4?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=for-the-badge&logo=postgresql&logoColor=white)](https://postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**Real-time, multi-engine intelligence gathering on domains, IP addresses, and digital identities — powered by 23+ live data sources and a Gemini AI analysis layer.**

![OSINT-Scan Dashboard Preview](https://raw.githubusercontent.com/yourusername/OSINT-Dashboard/main/docs/preview.png)

</div>

---

## ⚡ What Is OSINT-Scan?

OSINT-Scan is a **cybersecurity intelligence dashboard** built for security researchers, penetration testers, and digital forensics analysts. It aggregates open-source intelligence from 23+ live APIs and data sources into a single, dark-themed, real-time interface — no paid API keys required to get started.

Point it at a **domain**, **IP address**, or **email address** and it will automatically:

- Enumerate subdomains via certificate transparency logs
- Geolocate and fingerprint all resolved infrastructure
- Map the full digital identity footprint of an email or username
- Check for data breach exposures and infostealer logs
- Correlate relationships between all discovered assets
- Generate a Gemini AI-powered threat intelligence brief

> **Zero mock data. Zero fabrication. Real network calls only.**

---

## 🎯 Real-World Use Cases

| Use Case | How OSINT-Scan Helps |
|---|---|
| **Red Team Reconnaissance** | Enumerate domain attack surface, exposed ports, and ISP before an engagement |
| **Employee Phishing Risk Assessment** | Map an employee email's platform footprint and breach history |
| **Third-Party Vendor Due Diligence** | Analyze a vendor's domain and IP infrastructure posture before onboarding |
| **Incident Response** | Quickly correlate an indicator of compromise (domain/IP/email) to known threat data |
| **Bug Bounty Recon** | Discover subdomains, CDN edges, and infrastructure before scoping a target |
| **OSINT Investigations** | Link identities across platforms, detect username reuse, and map digital relationships |

---

## ✨ Features

### 🌐 Domain & Infrastructure Intelligence
- **Certificate Transparency Subdomain Enumeration** — Real-time crt.sh queries to surface all public subdomains
- **DNS A & MX Record Resolution** — Live dnspython lookups with IP resolution for every discovered host
- **IP Geolocation & ISP Fingerprinting** — Country, city, region, ISP, latitude/longitude via ip-api.com
- **WHOIS Registrar Lookup** — Registrar, registration date, and registrant privacy shield status
- **Shodan Port Intelligence** — Open port exposure mapping with critical port risk detection
- **Interactive Geolocation Map** — Plotly-rendered world map with all resolved infrastructure plotted

### 👤 Identity & Email Intelligence (23 Sources)
- **Gravatar** — MD5 email hash → avatar, display name, linked accounts, bio
- **EmailRep.io** — Reputation score, breach history, disposable email check, suspicious activity flags
- **HaveIBeenPwned** — Real breach and paste exposure list
- **GitHub** — Developer profile, repositories, followers, public email search
- **GitLab / Dev.to / HackerNews / Keybase** — Developer ecosystem presence mapping
- **DockerHub / npm / PyPI / Medium / CodePen / Hashnode** — Platform presence across developer ecosystems
- **Reddit** — Karma, account age, bio intelligence
- **HudsonRock Cavalier** — Infostealer & stealer log database check (credential leak intelligence)
- **LeakCheck.io** — Multi-source breach database correlation
- **Hunter.io** — Email domain organization intelligence
- **WHOIS / MX / DMARC / SPF** — Full email infrastructure and security posture analysis

### 🔗 Relationship & Correlation Engine
Automatically discovers and maps asset relationships including:
- `exact_email_domain_match` — Email domain ↔ target domain correlation
- `shared_ip_block` — Subdomains sharing the same /24 IP block
- `username_reuse` — Target username appearing inside discovered subdomains
- `platform_target_match` — Platform profiles linking to the target domain
- `linked_bio_url` — Bio keyword mentions referencing the target domain
- `shared_registrant_email` — User profiles linked to domain registrant

Visual network graph (via PyVis) shows all entity relationships interactively.

### 🤖 Gemini AI Intelligence Briefs
- **Domain Brief** — Tactical overview of infrastructure posture
- **Identity Brief** — Platform footprint and breach exposure summary
- **Executive Brief** — Full correlation analysis with remediation steps
- **PDF Export** — One-click downloadable intelligence report

### 📊 Threat Risk Scoring
Composite 0–100 Cyber Risk Score calculated from:
- Critical open port exposure (RDP 3389, SMB 445, MongoDB 27017, Redis 6379 ...)
- CVE/vulnerability count from Shodan
- DMARC & SPF email spoofability posture
- WHOIS registrar privacy shield status
- Identity surface area (developer & social platform confirmed hits)

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | Streamlit, Plotly, PyVis, HTML/CSS |
| **AI Analysis** | Google Gemini 2.5 Flash via `google-genai` SDK |
| **OSINT Engines** | 23+ public APIs — zero paid keys required |
| **DNS Resolution** | `dnspython` with DNS-over-HTTPS fallback (Google DoH) |
| **IP Intelligence** | ip-api.com free tier + Shodan (optional) |
| **Subdomain Enumeration** | crt.sh Certificate Transparency |
| **WHOIS** | `python-whois` |
| **Database** | PostgreSQL 16 (optional — runs fully without it) |
| **ORM / DB Layer** | Raw `psycopg2` with parameterized SQL |
| **Containerization** | Docker Compose (Postgres + schema auto-apply) |
| **HTTP Client** | `requests` with exponential backoff retry logic |
| **Language** | Python 3.9+ |

---

## 🚀 Installation

### Prerequisites
- Python 3.9+
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/OSINT-Dashboard.git
cd OSINT-Dashboard
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your credentials. Only `GEMINI_API_KEY` is required for AI briefs — everything else works without any keys:

```env
# Required for AI Intelligence Briefs
GEMINI_API_KEY=your_gemini_api_key_here

# Optional: GitHub token bumps rate limit from 60 to 5000 req/hour
GITHUB_TOKEN=your_github_pat_here

# Optional: PostgreSQL persistence (runs fine without this)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=osint_intel
DB_USER=postgres
DB_PASSWORD=changeme
```

**Get your free Gemini API key** → [aistudio.google.com](https://aistudio.google.com/apikey)

### 5. Run the Dashboard

```bash
streamlit run app.py
```

Open **http://localhost:8501** in your browser.

---

## 🐳 Optional: PostgreSQL Persistence

Run the full stack with Docker to enable sweep persistence:

```bash
docker compose up -d
```

This starts a PostgreSQL 16 container and auto-applies the schema. Every successful live sweep is persisted to:
- `targets` — unique target records
- `domain_intel` — subdomain, IP, ISP, WHOIS data
- `user_intel` — platform hits, breach data, confidence scores
- `entity_relationships` — correlated asset relationships

> Sweeps run perfectly fine without a database — persistence is completely opt-in.

---

## 📁 Project Structure

```
OSINT-Dashboard/
├── app.py                        # Main Streamlit app — UI, routing, sweep orchestration
│
├── workers/
│   ├── domain_worker.py          # crt.sh + DNS + WHOIS + ip-api.com subdomain sweep
│   ├── user_worker.py            # 23-source email/identity OSINT pipeline
│   ├── ip_worker.py              # IP geolocation, reverse PTR, region area lookup
│   ├── relationship_engine.py    # Cross-asset correlation & relationship mapping
│   ├── risk_engine.py            # Composite 0–100 Cyber Threat Risk Scorer
│   ├── shodan_worker.py          # Shodan open port & CVE integration
│   └── net_utils.py              # Retry logic, domain regex, HTTP utilities
│
├── lib/
│   ├── ai_analyzer.py            # Gemini AI brief generation (domain, user, executive)
│   └── pdf_generator.py          # FPDF2-based PDF intelligence report builder
│
├── db/
│   ├── schema.sql                # Idempotent CREATE TABLE statements
│   ├── connection.py             # psycopg2 connection + DatabaseUnavailable guard
│   ├── repository.py             # All parameterized SQL — inserts & reads
│   └── init_db.py                # `python -m db.init_db` to manually apply schema
│
├── docker-compose.yml            # Local Postgres dev stack
├── requirements.txt              # Python dependencies
└── .env.example                  # Environment variable template
```

---

## 🔑 Optional API Keys

All core OSINT features work **without any API keys**. These optional keys unlock higher rate limits or premium data sources:

| Key | What It Unlocks | Get It |
|---|---|---|
| `GEMINI_API_KEY` | AI Intelligence Briefs (Domain, Identity, Executive) | [aistudio.google.com](https://aistudio.google.com/apikey) |
| `GITHUB_TOKEN` | GitHub rate limit 60 → 5,000 req/hour | [github.com/settings/tokens](https://github.com/settings/tokens) |
| `SHODAN_API_KEY` | Open port scanning & CVE data | [account.shodan.io](https://account.shodan.io) |

---

## ⚙️ Platform Coverage & Methodology

| Platform | Method | Confidence |
|---|---|---|
| Gravatar | MD5 hash → JSON API | 90+ |
| HaveIBeenPwned | REST API | 90+ |
| GitHub (by email) | Public search API | 85+ |
| GitHub (by handle) | REST API | 90+ |
| GitLab | REST v4 API | 90+ |
| Dev.to | REST API | 90+ |
| HackerNews | Firebase API | 85+ |
| Keybase | API 1.0 (PGP proofs) | 90+ |
| DockerHub | API v2 | 85+ |
| Reddit | Public JSON API | 85+ |
| npm / PyPI | Registry API / HTML scrape | 80+ |
| Medium / CodePen / Hashnode | HTML scrape / GraphQL | 75+ |
| HudsonRock Cavalier | Infostealer DB API | 95+ |
| LeakCheck.io | Breach DB API | 90+ |
| Twitter/X, Instagram, LinkedIn | HTTP reachability check | ≤55 (existence only) |

> **Note on social platforms**: Twitter/X, Instagram, and LinkedIn do not provide public unauthenticated APIs. OSINT-Scan performs an honest HTTP reachability check — no fabricated bio data. Confidence scores are capped at 55 to reflect this weaker signal.

---

## 📡 Rate Limits & Responsible Use

OSINT-Scan is designed to be polite to free third-party services:

- **crt.sh**: Capped to 12 subdomains (`MAX_SUBDOMAINS`) to avoid hammering the free community service
- **ip-api.com**: 0.4s delay between subdomain IP lookups stays comfortably under the 45 req/min free tier limit
- **GitHub (unauthenticated)**: 60 req/hour per IP — set `GITHUB_TOKEN` to raise to 5,000/hour
- **All HTTP calls**: Exponential backoff retry on connection errors, timeouts, 429, and 5xx. 404 responses are treated as authoritative "not found" — never retried

> **Legal & Ethical Notice**: OSINT-Scan queries only publicly available data sources. Always ensure you have authorization to perform intelligence gathering on your targets. Do not use this tool against targets without explicit permission.

---

## 🤝 Contributing

Contributions are welcome! If you want to add a new data source, fix a bug, or improve the UI:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-data-source`
3. Commit your changes: `git commit -m 'Add XYZ data source'`
4. Push and open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built for the security community. **Use responsibly.**

</div>
