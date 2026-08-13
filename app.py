"""
OSINT Aggregation & Visualization Dashboard — Multi-Engine Intelligence (v0.7.0)
-----------------------------------------------------------------------------
Calls real ingestion workers in workers/ (crt.sh, DNS, WHOIS, IP Geolocation,
Region Area tracking, Reverse PTR DNS, Multi-Engine Username OSINT across 12+ platforms).
Live lookups only — real data only.

Successful live sweeps are persisted to PostgreSQL if DB_* env vars point at a
reachable database (see .env.example) — optional, silently skipped otherwise.

Run with:
    pip install -r requirements.txt
    cp .env.example .env   # optional — only needed for DB persistence
    streamlit run app.py
"""

import ipaddress
import os
import re
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd
# pyrefly: ignore [missing-import]
import plotly.express as px
# pyrefly: ignore [missing-import]
import streamlit as st
# pyrefly: ignore [missing-import]
import streamlit.components.v1 as components
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
# pyrefly: ignore [missing-import]
from pyvis.network import Network

from db import repository as repo
from db.connection import DatabaseUnavailable
from workers.domain_worker import OsintLookupError as DomainLookupError, run_domain_osint as _live_domain_osint
from workers.ip_worker import OsintLookupError as IpLookupError, run_ip_osint as _live_ip_osint
from workers.net_utils import DOMAIN_RE, _seed
from lib.ai_analyzer import generate_osint_brief, generate_domain_brief, generate_user_brief
from lib.pdf_generator import build_pdf_report
from workers.relationship_engine import generate_auto_relationships
from workers.risk_engine import calculate_risk_score
from workers.user_worker import OsintLookupError as UserLookupError, _email_md5, run_user_osint as _live_user_osint

load_dotenv()



# ----------------------------------------------------------------------------
# PAGE CONFIG
# ----------------------------------------------------------------------------
st.set_page_config(
    page_title="OSINT-Scan",
    page_icon="◉",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ----------------------------------------------------------------------------
# DESIGN TOKENS & CSS STYLING
# ----------------------------------------------------------------------------
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;800;900&family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root {
    --void: #0A0D10;
    --panel: #12171C;
    --panel-raised: #161C22;
    --line: #223038;
    --text: #C9D3D6;
    --text-dim: #6E7C82;
    --amber: #F0A63A;
    --cyan: #4FD9C9;
    --red: #E8544B;
}

html, body, [class*="css"]  { font-family: 'IBM Plex Mono', monospace; }
.stApp { background-color: var(--void); color: var(--text); }

#MainMenu, footer { visibility: hidden; }
[data-testid="stMainMenu"], [data-testid="stToolbarActions"] { visibility: hidden; }
header[data-testid="stHeader"] { background-color: transparent; }
[data-testid="stStatusWidget"] { visibility: hidden; }
[data-testid="stExpandSidebarButton"] {
    visibility: visible !important; opacity: 1 !important;
    background-color: var(--panel) !important; border: 1px solid var(--amber);
}
[data-testid="stExpandSidebarButton"] svg { color: var(--amber) !important; }
.block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1400px; }

/* Sidebar Logo Styling */
.sidebar-logo-container {
    border-bottom: 1px solid var(--line); padding-bottom: 16px; margin-bottom: 16px; margin-top: -20px;
}
.console-title {
    font-family: 'Orbitron', sans-serif; font-weight: 800; font-size: 2.2rem;
    letter-spacing: 0.06em; color: #F2F5F5; margin: 0; text-transform: uppercase;
}
.console-title span { color: var(--amber); }

/* Main Page Header Styling */
.main-header {
    display: flex; justify-content: space-between; align-items: flex-end;
    border-bottom: 1px solid var(--line); padding-bottom: 14px; margin-bottom: 22px;
}
.console-sub {
    font-size: 0.85rem; color: var(--text-dim); letter-spacing: 0.12em;
    text-transform: uppercase; margin: 0; font-weight: 600;
}
.console-clock {
    font-size: 0.75rem; color: var(--cyan); text-align: right; letter-spacing: 0.04em; margin: 0;
}
.console-clock .dim { color: var(--text-dim); display:block; font-size: 0.68rem; margin-top: 4px;}

.metric-card {
    background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--amber);
    padding: 14px 16px; height: 100%;
}
.metric-card.alt { border-left-color: var(--cyan); }
.metric-card.danger { border-left-color: var(--red); }
.metric-card.purple { border-left-color: #A855F7; }
.metric-label {
    font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.14em; color: var(--text-dim);
}
.metric-value {
    font-family: 'Space Grotesk', sans-serif; font-size: 1.8rem; font-weight: 700; color: #F2F5F5;
    margin-top: 4px;
}
.metric-delta { font-size: 0.7rem; color: var(--cyan); margin-top: 4px; }

.section-eyebrow {
    font-size: 0.68rem; letter-spacing: 0.16em; text-transform: uppercase; color: var(--amber);
    border-bottom: 1px dashed var(--line); padding-bottom: 8px; margin: 26px 0 14px 0;
}

section[data-testid="stSidebar"] { background-color: var(--panel); border-right: 1px solid var(--line); }
section[data-testid="stSidebar"] .stMarkdown p { color: var(--text-dim); font-size: 0.75rem; }

/* STREAMLIT TAB CENTERING */
.stTabs, [data-testid="stTabs"] {
    width: 100% !important;
}
.stTabs > div:first-child,
[data-testid="stTabs"] > div:first-child,
[data-testid="stTabsHeader"],
.stTabs [data-baseweb="tab-highlight-container"],
.stTabs [data-baseweb="tab-list"],
.stTabs [role="tablist"] {
    display: flex !important;
    justify-content: center !important;
    align-items: center !important;
    width: 100% !important;
    margin: 0 auto !important;
    gap: 16px !important;
    border-bottom: 1px solid var(--line) !important;
}
.stTabs [data-baseweb="tab"], .stTabs button[role="tab"], [data-testid="stTab"] {
    background-color: transparent !important;
    color: var(--text-dim) !important;
    border: none !important;
    font-size: 0.78rem !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
    padding: 10px 16px !important;
}
.stTabs [aria-selected="true"], .stTabs button[role="tab"][aria-selected="true"] {
    color: var(--amber) !important;
    border-bottom: 2px solid var(--amber) !important;
}

/* SIDEBAR TACTICAL BUTTON STYLING */
section[data-testid="stSidebar"] .stButton > button {
    background-color: var(--amber) !important; 
    color: var(--void) !important; 
    border: 2px solid var(--amber) !important;
    border-radius: 0px !important;
    font-size: 1.05rem !important; 
    font-weight: 800 !important; 
    letter-spacing: 0.25em !important; 
    text-transform: uppercase !important;
    padding: 16px 20px !important;
    display: flex !important; 
    justify-content: center !important; 
    align-items: center !important;
    box-shadow: 0 4px 12px rgba(240, 166, 58, 0.15) !important;
    transition: all 0.2s ease-in-out !important;
}
section[data-testid="stSidebar"] .stButton > button p { 
    text-align: center !important; 
    margin: 0 !important;
    flex: 1 !important; 
    display: flex !important;
    justify-content: center !important;
}
section[data-testid="stSidebar"] .stButton > button:hover { 
    background-color: #FFC069 !important; 
    border-color: #FFC069 !important; 
    color: var(--void) !important;
    box-shadow: 0 6px 20px rgba(240, 166, 58, 0.3) !important;
    transform: translateY(-2px) !important;
}
section[data-testid="stSidebar"] .stButton > button:active { 
    background-color: #D48F2E !important; 
    border-color: #D48F2E !important;
    transform: translateY(1px) !important;
}

/* MAIN CONTENT BUTTON STYLING (MATCHING ST.BUTTON & ST.DOWNLOAD_BUTTON) */
.stButton > button, .stDownloadButton > button {
    background-color: var(--panel-raised) !important;
    color: var(--text) !important;
    border: 1px solid var(--line) !important;
    border-radius: 4px !important;
    font-size: 0.88rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.04em !important;
    padding: 10px 16px !important;
    display: flex !important;
    justify-content: center !important;
    align-items: center !important;
    transition: all 0.2s ease-in-out !important;
}
.stButton > button p, .stDownloadButton > button p {
    text-align: center !important;
    margin: 0 !important;
    color: var(--text) !important;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    background-color: var(--line) !important;
    border-color: var(--amber) !important;
    color: var(--amber) !important;
}
.stButton > button:hover p, .stDownloadButton > button:hover p {
    color: var(--amber) !important;
}

[data-testid="stDataFrame"] { border: 1px solid var(--line); }

.chip {
    display:inline-block; padding: 2px 8px; font-size: 0.68rem; border: 1px solid var(--line);
    letter-spacing: 0.06em;
}
.chip.high { color: var(--red); border-color: var(--red); }
.chip.med { color: var(--amber); border-color: var(--amber); }
.chip.low { color: var(--cyan); border-color: var(--cyan); }

.history-item {
    font-size: 0.72rem; margin-bottom: 6px; padding: 8px; 
    border: 1px solid var(--line); background: var(--void); border-radius: 2px;
    display: flex; justify-content: space-between; align-items: center;
}
.history-item .target { color: var(--text); font-weight: 500; }
.history-item .time { color: var(--cyan); font-size: 0.65rem; }

hr { border-color: var(--line); }
[data-testid="InputInstructions"] { display: none !important; }
.mapboxgl-ctrl-attrib { display: none !important; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

# ----------------------------------------------------------------------------
# SESSION STATE INIT
# ----------------------------------------------------------------------------
def init_session_state():
    defaults = {
        "history": [],
        "domain_val": "",
        "user_val": "",
        "ip_val": "",
        "domain_df": pd.DataFrame(columns=[
            "subdomain", "ip_address", "isp", "country", "region_name", "city", "lat", "lon",
            "registrar", "mx_records", "discovered_at",
        ]),
        "user_df": pd.DataFrame(columns=[
            "platform", "category", "display_name", "profile_url", "associated_email",
            "bio_keywords", "followers", "public_repos", "avatar_url", "confidence", "discovered_at",
        ]),
        "ip_df": pd.DataFrame(columns=[
            "ip_address", "country", "country_code", "region_code", "region_name",
            "city", "zip", "lat", "lon", "timezone", "isp", "org", "as_number",
            "reverse_dns", "discovered_at",
        ]),
        "rel_df": pd.DataFrame(columns=["source", "target", "relationship_type", "confidence_score"]),
        "domain_swept": False,
        "user_swept": False,
        "ip_swept": False,
        "data_source": {"domain": "live", "user": "live", "ip": "live"},
        "failures": {},
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val

    # Defensive backfill for any existing user_df in session state
    if "user_df" in st.session_state and isinstance(st.session_state.user_df, pd.DataFrame):
        for col in ["category", "display_name", "associated_email", "followers", "public_repos", "avatar_url"]:
            if col not in st.session_state.user_df.columns:
                st.session_state.user_df[col] = "—"

init_session_state()

# ----------------------------------------------------------------------------
# BACKEND INTEGRATION & VALIDATION
# ----------------------------------------------------------------------------

def clean_domain_input(domain_value: str) -> str:
    """Extract clean domain hostname from full URLs or raw input strings."""
    domain_value = domain_value.strip()
    if domain_value.startswith(("http://", "https://")) or "://" in domain_value:
        try:
            parsed = urlparse(domain_value)
            netloc = parsed.netloc or parsed.path.split("/")[0]
            domain_value = netloc.split(":")[0]
        except Exception:
            pass
    elif "/" in domain_value:
        domain_value = domain_value.split("/")[0]
    return domain_value.lower().strip().rstrip(".")


def clean_user_input(username_value: str) -> str:
    """Extract clean email or username from profile URLs or raw input strings."""
    val = username_value.strip()
    if "@" in val and "." in val.split("@")[-1]:
        return val.lower()
    val = val.lstrip("@")
    if val.startswith(("http://", "https://")) or "://" in val:
        try:
            parsed = urlparse(val)
            path_parts = [p for p in parsed.path.split("/") if p]
            if path_parts:
                val = path_parts[-1] if path_parts[0] in ("in", "user", "users", "u", "profile") and len(path_parts) > 1 else path_parts[0]
        except Exception:
            pass
    elif "/" in val:
        parts = [p for p in val.split("/") if p]
        if parts:
            val = parts[-1] if len(parts) > 1 else parts[0]
    return val.strip().lstrip("@")


def validate_domain(domain_value: str) -> tuple[bool, str, str]:
    """Validate domain input. Returns (is_valid, error_message, cleaned_domain)."""
    cleaned = clean_domain_input(domain_value)
    if not cleaned:
        return False, "Domain cannot be empty.", ""
    if not DOMAIN_RE.match(cleaned):
        return False, f"'{domain_value}' is not a valid domain. Use format: example.com", ""
    return True, "", cleaned


def validate_username(username_value: str) -> tuple[bool, str, str]:
    """Validate email address or username input. Returns (is_valid, error_message, cleaned_val)."""
    cleaned = clean_user_input(username_value)
    if not cleaned:
        return False, "Email address or username cannot be empty.", ""
    if len(cleaned) < 2:
        return False, "Input must be at least 2 characters.", ""
    if "@" in cleaned:
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", cleaned):
            return False, f"'{username_value}' is not a valid email address.", ""
        return True, "", cleaned
    if not re.match(r"^[a-zA-Z0-9_.\- ]+$", cleaned):
        return False, f"'{username_value}' contains invalid characters.", ""
    return True, "", cleaned


def validate_ip_address(ip_value: str) -> tuple[bool, str, str]:
    """Validate IP address or hostname input. Returns (is_valid, error_message, cleaned_ip)."""
    cleaned = ip_value.strip()
    if not cleaned:
        return False, "IP address / Hostname cannot be empty.", ""
    try:
        ipaddress.ip_address(cleaned)
        return True, "", cleaned
    except ValueError:
        pass
    if DOMAIN_RE.match(cleaned):
        return True, "", cleaned
    return False, f"'{ip_value}' is not a valid IPv4/IPv6 address or hostname.", ""


def run_domain_osint(domain_value: str) -> tuple[pd.DataFrame, str]:
    """Runs real live domain sweep."""
    return _live_domain_osint(domain_value), "live"


def run_user_osint(username_value: str) -> tuple[pd.DataFrame, str]:
    """Runs real live Email-Centric & Service OSINT across 12+ engines."""
    return _live_user_osint(username_value), "live"


def run_ip_osint(ip_value: str) -> tuple[pd.DataFrame, str]:
    """Runs real live IP Geolocation & Location Region Area lookup."""
    return _live_ip_osint(ip_value), "live"


def persist_sweep(domain_val, user_val, ip_val, domain_df, user_df, ip_df, rel_df):
    """Best-effort persistence — silently no-ops if the DB isn't reachable."""
    try:
        if domain_val and not domain_df.empty:
            domain_target_id = repo.get_or_create_target("domain", domain_val)
            repo.save_domain_intel(domain_target_id, domain_df.to_dict("records"))
        if user_val and not user_df.empty:
            target_type = "email" if "@" in user_val else "user"
            user_target_id = repo.get_or_create_target(target_type, user_val)
            repo.save_user_intel(user_target_id, user_df.to_dict("records"))
        if ip_val and not ip_df.empty:
            ip_target_id = repo.get_or_create_target("ip", ip_val)
            repo.save_ip_intel(ip_target_id, ip_df.to_dict("records"))
        if domain_val and user_val and not rel_df.empty:
            domain_target_id = repo.get_or_create_target("domain", domain_val)
            target_type = "email" if "@" in user_val else "user"
            user_target_id = repo.get_or_create_target(target_type, user_val)
            repo.save_relationships(domain_target_id, user_target_id, rel_df.to_dict("records"))
    except DatabaseUnavailable:
        pass


# ----------------------------------------------------------------------------
# SIDEBAR — TARGET INGESTION
# ----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div class="sidebar-logo-container">
        <p class="console-title">OSINT<span>-</span>Scan</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<div class='section-eyebrow'>Target Ingestion</div>", unsafe_allow_html=True)
    target_type = st.radio("Target type", ["Domain / IP", "Email / Identity"], horizontal=True, label_visibility="collapsed")

    if target_type == "Domain / IP":
        target_value = st.text_input(
            "Target Domain or IP Address", value="", placeholder="e.g. example.com",
            key="domain_ip_input", label_visibility="collapsed",
        )
    else:
        target_value = st.text_input(
            "Target Email Address or Handle", value="", placeholder="e.g. user@domain.com",
            key="user_input", label_visibility="collapsed",
        )

    sweep = st.button("START", use_container_width=True)


    st.markdown("<div class='section-eyebrow'>DB Connection</div>", unsafe_allow_html=True)
    with st.expander("Settings", expanded=False):
        st.text_input("Host", value="localhost", key="db_host")
        st.text_input("Port", value="5432", key="db_port")
        st.text_input("Database", value="osint_intel", key="db_name")
        st.text_input("User", value="postgres", key="db_user")
        st.text_input("Password", value="", type="password", key="db_pass")

    st.markdown("<div class='section-eyebrow'>Sweep History</div>", unsafe_allow_html=True)
    
    if sweep and target_value.strip():
        st.session_state.history.insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": target_type,
            "target": target_value.strip()
        })
        st.session_state.history = st.session_state.history[:10]

    if not st.session_state.history:
        st.markdown("<p style='color:var(--text-dim); font-size:0.75rem; font-style:italic;'>No recent sweeps found.</p>", unsafe_allow_html=True)
    else:
        for item in st.session_state.history:
            icon = ""
            st.markdown(f"""
            <div class="history-item">
                <span class="target">{item['target']}</span>
                <span class="time">{item['time']}</span>
            </div>
            """, unsafe_allow_html=True)


# ----------------------------------------------------------------------------
# CORE LOGIC & SWEEP EXECUTION
# ----------------------------------------------------------------------------
if sweep and target_value.strip():
    st.session_state.failures = {}
    raw_val = target_value.strip()

    if target_type == "Domain / IP":
        is_ip = False
        try:
            ipaddress.ip_address(raw_val)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            is_valid, error_msg, cleaned_val = validate_ip_address(raw_val)
            if not is_valid:
                st.error(f"{error_msg}")
            else:
                st.session_state.ip_val = cleaned_val
                try:
                    with st.spinner(f"Geolocating {cleaned_val}"):
                        df, src = run_ip_osint(st.session_state.ip_val)
                        st.session_state.ip_df = df
                        st.session_state.data_source["ip"] = src
                    st.session_state.ip_swept = True
                except Exception as e:
                    st.error(f"IP Geolocation failed: {e}")
        else:
            is_valid, error_msg, cleaned_val = validate_domain(raw_val)
            if not is_valid:
                st.error(f"{error_msg}")
            else:
                st.session_state.domain_val = cleaned_val
                try:
                    with st.spinner(f"Sweeping {cleaned_val}"):
                        df, src = run_domain_osint(st.session_state.domain_val)
                        st.session_state.domain_df = df
                        st.session_state.data_source["domain"] = src
                    st.session_state.domain_swept = True
                except Exception as e:
                    st.error(f"Domain lookup failed: {e}")

    else:  # Email / Identity
        is_valid, error_msg, cleaned_val = validate_username(raw_val)
        if not is_valid:
            st.error(f"{error_msg}")
        else:
            st.session_state.user_val = cleaned_val
            try:
                with st.spinner(f"Sweeping {cleaned_val}"):
                    df, src = run_user_osint(st.session_state.user_val)
                    st.session_state.user_df = df
                    st.session_state.data_source["user"] = src
                st.session_state.user_swept = True
            except Exception as e:
                st.error(f"Email & identity footprinting failed: {e}")


    if st.session_state.domain_val and st.session_state.user_val:
        try:
            st.session_state.rel_df = generate_auto_relationships(
                st.session_state.domain_df, st.session_state.user_df,
                st.session_state.domain_val, st.session_state.user_val,
            )
        except Exception as e:
            st.session_state.failures["relationships"] = str(e)

    persist_sweep(
        st.session_state.domain_val, st.session_state.user_val, st.session_state.ip_val,
        st.session_state.domain_df, st.session_state.user_df, st.session_state.ip_df,
        st.session_state.rel_df,
    )
    
    # Automatically generate specific briefs after a sweep
    if st.session_state.domain_swept or st.session_state.ip_swept:
        with st.spinner("Analyzing Domain"):
            st.session_state.domain_brief = generate_domain_brief(st.session_state.domain_val, st.session_state.domain_df, st.session_state.ip_df)
    if st.session_state.user_swept:
        with st.spinner("Analyzing Email"):
            st.session_state.user_brief = generate_user_brief(st.session_state.user_val, st.session_state.user_df)


domain_val = st.session_state.domain_val
user_val = st.session_state.user_val
ip_val = st.session_state.ip_val
domain_df = st.session_state.domain_df
user_df = st.session_state.user_df
ip_df = st.session_state.ip_df
rel_df = st.session_state.rel_df
domain_swept = st.session_state.domain_swept
user_swept = st.session_state.user_swept
ip_swept = st.session_state.ip_swept

source_label = " · live network"

case_label = " &nbsp;/&nbsp; ".join(
    filter(None, [
        domain_val if domain_swept else None,
        f"@{user_val}" if user_swept else None,
        f"IP: {ip_val}" if ip_swept else None,
    ])
) or "No sweep yet"

st.markdown(f"""
<div class="main-header">
    <div class="console-sub">Active case · {case_label}</div>
    <div class="console-clock">
        <span id="live-clock">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
        <span class="dim">{source_label}</span>
    </div>
</div>
<script>
(function() {{
    function updateLiveClock() {{
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');
        const clockEl = document.getElementById('live-clock');
        if (clockEl) {{
            clockEl.textContent = `${{year}}-${{month}}-${{day}} ${{hours}}:${{minutes}}:${{seconds}}`;
        }}
    }}
    updateLiveClock();
    if (window.liveClockTimer) {{
        clearInterval(window.liveClockTimer);
    }}
    window.liveClockTimer = setInterval(updateLiveClock, 1000);
}})();
</script>
""", unsafe_allow_html=True)


# ----------------------------------------------------------------------------
# COMBINED INFRASTRUCTURE & IP DATA AGGREGATION
# ----------------------------------------------------------------------------
infra_records = []
if not domain_df.empty:
    for _, r in domain_df.iterrows():
        infra_records.append({
            "target_label": r["subdomain"],
            "ip_address": r["ip_address"],
            "isp": r.get("isp", "—"),
            "country": r.get("country", "—"),
            "region_name": r.get("region_name", "—"),
            "city": r.get("city", "—"),
            "lat": float(r.get("lat", 0.0)),
            "lon": float(r.get("lon", 0.0)),
            "timezone": "—",
            "as_number": "—",
            "reverse_dns": "—",
            "registrar": r.get("registrar", "—"),
            "mx_records": ", ".join(r["mx_records"]) if isinstance(r.get("mx_records"), list) else str(r.get("mx_records", "")),
            "discovered_at": r.get("discovered_at"),
        })

if not ip_df.empty:
    for _, r in ip_df.iterrows():
        infra_records.append({
            "target_label": f"IP Target: {r['ip_address']}",
            "ip_address": r["ip_address"],
            "isp": r.get("isp", "—"),
            "country": r.get("country", "—"),
            "region_name": r.get("region_name", "—"),
            "city": r.get("city", "—"),
            "lat": float(r.get("lat", 0.0)),
            "lon": float(r.get("lon", 0.0)),
            "timezone": r.get("timezone", "—"),
            "as_number": r.get("as_number", "—"),
            "reverse_dns": r.get("reverse_dns", "—"),
            "registrar": r.get("as_number", "—"),
            "mx_records": f"PTR: {r.get('reverse_dns', '—')}",
            "discovered_at": r.get("discovered_at"),
        })

combined_infra_df = pd.DataFrame(infra_records)


# ----------------------------------------------------------------------------
# TOP METRICS & DYNAMIC RISK SCORE
# ----------------------------------------------------------------------------
domain_ips = domain_df[domain_df["ip_address"] != "—"]["ip_address"].tolist() if not domain_df.empty else []
direct_ips = ip_df["ip_address"].tolist() if not ip_df.empty else []
total_unique_ips = len(set(domain_ips + direct_ips))
unique_isps = len(set(combined_infra_df["isp"])) if not combined_infra_df.empty else 0

email_sec_info = None
if not domain_df.empty and "spf_status" in domain_df.columns:
    first_d = domain_df.iloc[0]
    email_sec_info = {
        "spf_status": first_d.get("spf_status", "missing"),
        "dmarc_status": first_d.get("dmarc_status", "missing"),
    }

shodan_info = None
if not ip_df.empty and "shodan_ports" in ip_df.columns:
    r0 = ip_df.iloc[0]
    shodan_info = {
        "is_available": True,
        "ports": r0.get("shodan_ports", []),
        "vulns": r0.get("shodan_cves", []),
    }

risk_result = calculate_risk_score(domain_df, ip_df, user_df, shodan_info, email_sec_info)

c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Subdomains Found</div>
        <div class="metric-value">{len(domain_df)}</div>
    </div>
    """, unsafe_allow_html=True)
with c2:
    st.markdown(f"""
    <div class="metric-card alt">
        <div class="metric-label">Tracked IP Locations</div>
        <div class="metric-value">{total_unique_ips}</div>
    </div>
    """, unsafe_allow_html=True)
with c3:
    st.markdown(f"""
    <div class="metric-card purple">
        <div class="metric-label">ISPs & Networks</div>
        <div class="metric-value">{unique_isps}</div>
    </div>
    """, unsafe_allow_html=True)
with c4:
    st.markdown(f"""
    <div class="metric-card alt">
        <div class="metric-label">Verified Profile Hits</div>
        <div class="metric-value">{len(user_df)}</div>
    </div>
    """, unsafe_allow_html=True)
with c5:
    badge_html = f'<span style="font-size:0.65rem; background:{risk_result["badge_bg"]}; color:{risk_result["color"]}; padding:2px 6px; border-radius:2px; vertical-align:middle; margin-left:4px; font-weight:700;">{risk_result["level"]}</span>' if risk_result['level'] != "LOW" else ""
    st.markdown(
        f'<div class="metric-card" style="border-left-color: {risk_result["color"]};">'
        f'<div class="metric-label">Threat Severity Score</div>'
        f'<div class="metric-value" style="color: {risk_result["color"]}; font-size:1.5rem;">'
        f'{risk_result["score"]} <span style="font-size:0.8rem; color:var(--text-dim);">/100</span> {badge_html}'
        f'</div></div>',
        unsafe_allow_html=True
    )

if risk_result["breakdown"]:
    with st.expander(f"Cyber Risk & Vulnerability Breakdown ({risk_result['score']}/100 — {risk_result['level']})", expanded=False):
        for item in risk_result["breakdown"]:
            bd_color = "#E8544B" if item["severity"] == "CRITICAL" else "#FF7849" if item["severity"] == "HIGH" else "#F0A63A"
            chip_cls = "high" if item["severity"] in ("CRITICAL", "HIGH") else "med"
            st.markdown(f"""
            <div style="padding:8px 12px; margin-bottom:6px; background:var(--panel-raised); border-left:3px solid {bd_color}; font-size:0.78rem;">
                <strong style="color:var(--text);">{item['category']} (+{item['points']} pts)</strong> &nbsp;
                <span class="chip {chip_cls}">{item['severity']}</span>
                <div style="color:var(--text-dim); margin-top:2px; font-size:0.72rem;">{item['detail']}</div>
            </div>
            """, unsafe_allow_html=True)


def style_fig(fig, height=380):
    fig.update_layout(
        paper_bgcolor="#12171C", plot_bgcolor="#12171C",
        font=dict(family="IBM Plex Mono", color="#C9D3D6", size=12),
        margin=dict(l=10, r=10, t=30, b=10), height=height,
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    fig.update_xaxes(gridcolor="#223038", zerolinecolor="#223038")
    fig.update_yaxes(gridcolor="#223038", zerolinecolor="#223038")
    return fig


# ----------------------------------------------------------------------------
# TABS
# ----------------------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Domain",
    "Email",
    "Relation",
    "Geolocation",
    "Final Report"
])


# ---- TAB 1: Infrastructure & IP Geolocation ------------------------------
with tab1:
    if "domain" in st.session_state.failures:
        st.warning(f"Domain lookup warning: {st.session_state.failures['domain']}")
    if "ip" in st.session_state.failures:
        st.warning(f"IP lookup warning: {st.session_state.failures['ip']}")

    if st.session_state.get('domain_brief') and not st.session_state['domain_brief'].startswith("⚠️"):
        with st.expander("🤖 Domain AI Analysis", expanded=True):
            st.markdown(st.session_state['domain_brief'])

    # Render location highlight cards if data is available
    if not combined_infra_df.empty:
        primary_row = combined_infra_df.iloc[0]
        k1, k2, k3, k4, k5 = st.columns(5)
        with k1:
            st.markdown(f"""
            <div class="metric-card alt">
                <div class="metric-label">Target IP / Host</div>
                <div class="metric-value" style="font-size:1.1rem; overflow:hidden; text-overflow:ellipsis;">{primary_row['ip_address']}</div>
            </div>
            """, unsafe_allow_html=True)
        with k2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Location Region Area</div>
                <div class="metric-value" style="font-size:1.1rem;">{primary_row['region_name']}</div>
            </div>
            """, unsafe_allow_html=True)
        with k3:
            st.markdown(f"""
            <div class="metric-card alt">
                <div class="metric-label">City / Country</div>
                <div class="metric-value" style="font-size:1.1rem;">{primary_row['city']}, {primary_row['country']}</div>
            </div>
            """, unsafe_allow_html=True)
        with k4:
            st.markdown(f"""
            <div class="metric-card purple">
                <div class="metric-label">ISP / Network</div>
                <div class="metric-value" style="font-size:1.0rem; overflow:hidden; text-overflow:ellipsis;">{primary_row['isp']}</div>
            </div>
            """, unsafe_allow_html=True)
        with k5:
            st.markdown(f"""
            <div class="metric-card alt">
                <div class="metric-label">Timezone</div>
                <div class="metric-value" style="font-size:1.1rem;">{primary_row.get('timezone', '—')}</div>
            </div>
            """, unsafe_allow_html=True)

    # Shodan Passive Intelligence & Email Security
    if not ip_df.empty and "shodan_ports" in ip_df.columns:
        shodan_row = ip_df.iloc[0]
        s_ports = shodan_row.get("shodan_ports", [])
        s_cves = shodan_row.get("shodan_cves", [])
        s_hosts = shodan_row.get("shodan_hostnames", [])

        st.markdown("<div class='section-eyebrow'>Shodan Passive Intelligence (Ports & Vulnerabilities)</div>", unsafe_allow_html=True)
        p1, p2, p3 = st.columns([1.2, 1.2, 1])
        with p1:
            st.markdown("**Open Ports Detected**")
            if s_ports:
                port_chips = " ".join([
                    f"<span class='chip { 'high' if p in (3389,445,139,23,21,1433,5432,3306,27017) else 'low' }'>Port {p}</span>"
                    for p in s_ports
                ])
                st.markdown(port_chips, unsafe_allow_html=True)
            else:
                st.markdown("<p style='color:var(--text-dim); font-size:0.75rem;'>No open ports indexed on Shodan InternetDB.</p>", unsafe_allow_html=True)
        with p2:
            st.markdown("**Exposed Vulnerabilities (CVEs)**")
            if s_cves:
                cve_chips = " ".join([f"<span class='chip high'>{cve}</span>" for cve in s_cves[:8]])
                st.markdown(cve_chips, unsafe_allow_html=True)
            else:
                st.markdown("<p style='color:var(--cyan); font-size:0.75rem;'>Zero exposed CVE vulnerabilities indexed.</p>", unsafe_allow_html=True)
        with p3:
            st.markdown("**Indexed Hostnames**")
            if s_hosts:
                st.markdown("<br>".join([f"<code style='color:var(--text); font-size:0.72rem;'>{h}</code>" for h in s_hosts[:4]]), unsafe_allow_html=True)
            else:
                st.markdown("<p style='color:var(--text-dim); font-size:0.75rem;'>—</p>", unsafe_allow_html=True)

    if not domain_df.empty and "dmarc_status" in domain_df.columns:
        d0 = domain_df.iloc[0]
        dmarc_st = str(d0.get("dmarc_status", "missing"))
        spf_st = str(d0.get("spf_status", "missing"))
        st.markdown("<div class='section-eyebrow'>Email Security & Spoofing Defense Posture</div>", unsafe_allow_html=True)
        e1, e2 = st.columns(2)
        with e1:
            d_cls = "low" if dmarc_st in ("enforced", "present") else "med" if dmarc_st == "none" else "high"
            st.markdown(f"**DMARC Policy**: <span class='chip {d_cls}'>{dmarc_st.upper()}</span>", unsafe_allow_html=True)
            if d0.get("dmarc_record"):
                st.caption(f"Record: `{d0['dmarc_record']}`")
        with e2:
            s_cls = "low" if spf_st == "present" else "high"
            st.markdown(f"**SPF Policy**: <span class='chip {s_cls}'>{spf_st.upper()}</span>", unsafe_allow_html=True)
            if d0.get("spf_record"):
                st.caption(f"Record: `{d0['spf_record']}`")

    left, right = st.columns([1, 1.3])

    with left:
        st.markdown("<div class='section-eyebrow'>Hosting / ISP Breakdown</div>", unsafe_allow_html=True)
        resolved_df = combined_infra_df[~combined_infra_df["isp"].isin(["Unresolved", "Unavailable", "—"])] if not combined_infra_df.empty else pd.DataFrame()
        if not resolved_df.empty:
            isp_counts = resolved_df["isp"].value_counts().reset_index()
            isp_counts.columns = ["isp", "count"]
        else:
            isp_counts = pd.DataFrame({"isp": [], "count": []})
        
        fig_bar = px.bar(isp_counts, x="count", y="isp", orientation="h",
                          color_discrete_sequence=["#F0A63A"])
        fig_bar.update_traces(marker_line_width=0)
        st.plotly_chart(style_fig(fig_bar, height=210))

        st.markdown("<div class='section-eyebrow'>Location Region Area Breakdown</div>", unsafe_allow_html=True)
        if not combined_infra_df.empty:
            region_counts = combined_infra_df["region_name"].value_counts().reset_index()
            region_counts.columns = ["region_name", "count"]
        else:
            region_counts = pd.DataFrame({"region_name": [], "count": []})

        fig_reg = px.bar(
            region_counts, x="count", y="region_name", orientation="h",
            color="count", color_continuous_scale=["#223038", "#A855F7", "#4FD9C9"]
        )
        fig_reg.update_coloraxes(showscale=False)
        fig_reg.update_layout(xaxis_title="Count", yaxis_title="")
        st.plotly_chart(style_fig(fig_reg, height=210))

    with right:
        st.markdown("<div class='section-eyebrow'>Map</div>", unsafe_allow_html=True)
        geo_df = combined_infra_df[(combined_infra_df["lat"] != 0.0) | (combined_infra_df["lon"] != 0.0)] if not combined_infra_df.empty else pd.DataFrame()
        if geo_df.empty:
            geo_df = pd.DataFrame({"lat": [], "lon": [], "target_label": [], "ip_address": [], "isp": [], "region_name": [], "city": [], "country": []})
        
        fig_map = px.scatter_map(
            geo_df, lat="lat", lon="lon", hover_name="target_label",
            hover_data={"ip_address": True, "isp": True, "region_name": True, "city": True, "country": True, "lat": False, "lon": False},
            color_discrete_sequence=["#4FD9C9"], zoom=1,
        )
        fig_map.update_traces(marker=dict(size=14))
        fig_map.update_layout(map_style="carto-darkmatter")
        st.plotly_chart(style_fig(fig_map, height=480))

    st.markdown("<div class='section-eyebrow'>Subdomain, IP Location & Region Register</div>", unsafe_allow_html=True)
    if not combined_infra_df.empty:
        cols = [c for c in ["target_label", "ip_address", "city", "region_name", "country", "isp", "registrar", "mx_records", "discovered_at"] if c in combined_infra_df.columns]
        st.dataframe(combined_infra_df[cols], width='stretch', hide_index=True)
    else:
        st.markdown("<p style='color:var(--text-dim); font-size:0.8rem; font-style:italic;'>No infrastructure or IP sweep data yet. Enter a Domain or IP in the left sidebar and click START.</p>", unsafe_allow_html=True)


# ---- TAB 2: Email & Identity Intelligence OSINT --------------------------
with tab2:
    if "user" in st.session_state.failures:
        st.warning(f"Email/Identity lookup warning: {st.session_state.failures['user']}")

    if st.session_state.get('user_brief') and not st.session_state['user_brief'].startswith("⚠️"):
        with st.expander("🤖 Identity AI Analysis", expanded=True):
            st.markdown(st.session_state['user_brief'])

    if not user_df.empty:
        # ── Metric cards ─────────────────────────────────────────────────────
        u1, u2, u3, u4, u5 = st.columns(5)
        total_hits = len(user_df)
        is_email_target = "@" in user_val
        email_dom = user_val.split("@")[1] if is_email_target else "—"
        dom_match = "CONNECTED" if (domain_val and is_email_target and email_dom.lower() == domain_val.lower()) else email_dom

        # Extract threat intel from HudsonRock (infostealer) + LeakCheck (breach DB)
        hr_rows = user_df[user_df["platform"] == "HudsonRock Cavalier"]
        lc_rows = user_df[user_df["platform"] == "LeakCheck.io"]
        breach_count_display = "—"
        breach_color = "var(--text-dim)"
        # Priority: HudsonRock compromise > LeakCheck exposed > clean
        if not hr_rows.empty:
            hr_r = hr_rows.iloc[0]
            hr_name = str(hr_r.get("display_name", ""))
            if "Compromised" in hr_name:
                breach_count_display = "⚠ Compromised"
                breach_color = "#E8544B"
            else:
                breach_count_display = "✓ Clean"
                breach_color = "var(--cyan)"
        elif not lc_rows.empty:
            lc_r = lc_rows.iloc[0]
            lc_name = str(lc_r.get("display_name", ""))
            if "Exposed" in lc_name:
                bc = lc_r.get("breach_count", 0)
                breach_count_display = f"{bc:,} records"
                breach_color = "#E8544B"
            elif "Not Found" in lc_name:
                breach_count_display = "✓ Clean"
                breach_color = "var(--cyan)"

        # Extract EmailRep reputation if present
        emailrep_rows = user_df[user_df["platform"] == "EmailRep.io"]
        reputation_display = "—"
        if not emailrep_rows.empty:
            rep = emailrep_rows.iloc[0]
            reputation_display = str(rep.get("reputation", rep.get("display_name", "—"))).title()

        all_kws = []
        for _, r in user_df.iterrows():
            if isinstance(r.get("bio_keywords"), list):
                all_kws.extend(r["bio_keywords"])
        high_conf = len(user_df[user_df["confidence"] >= 90])

        with u1:
            st.markdown(f"""
            <div class="metric-card alt">
                <div class="metric-label">Target Email</div>
                <div class="metric-value" style="font-size:0.95rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{user_val}</div>
            </div>
            """, unsafe_allow_html=True)
        with u2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Services Found</div>
                <div class="metric-value" style="font-size:1.3rem;">{total_hits}</div>
            </div>
            """, unsafe_allow_html=True)
        with u3:
            st.markdown(f"""
            <div class="metric-card purple">
                <div class="metric-label">Email Reputation</div>
                <div class="metric-value" style="font-size:1.1rem;">{reputation_display}</div>
            </div>
            """, unsafe_allow_html=True)
        with u4:
            st.markdown(f"""
            <div class="metric-card danger">
                <div class="metric-label">Breach Exposure</div>
                <div class="metric-value" style="font-size:1.1rem; color:{breach_color};">{breach_count_display}</div>
            </div>
            """, unsafe_allow_html=True)
        with u5:
            st.markdown(f"""
            <div class="metric-card alt">
                <div class="metric-label">Domain Link</div>
                <div class="metric-value" style="font-size:0.95rem; color:{'var(--cyan)' if dom_match == 'CONNECTED' else 'var(--text-dim)'}; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">{dom_match}</div>
            </div>
            """, unsafe_allow_html=True)

        # ── Gravatar / Identity Banner ────────────────────────────────────
        gravatar_rows = user_df[user_df["platform"] == "Gravatar"]
        # Fall back to Clearbit for avatar/name if no Gravatar
        clearbit_rows = user_df[user_df["platform"] == "Clearbit Person"]
        profile_row = gravatar_rows.iloc[0] if not gravatar_rows.empty else (clearbit_rows.iloc[0] if not clearbit_rows.empty else None)
        if profile_row is not None:
            avatar_src = str(profile_row.get("avatar_url", "") or f"https://www.gravatar.com/avatar/{_email_md5(user_val)}?d=identicon")
            d_name = str(profile_row.get("display_name", user_val))
            p_url = str(profile_row.get("profile_url", ""))
            source_badge = "Gravatar" if not gravatar_rows.empty else "Clearbit"
            st.markdown(f"""
            <div style="background:var(--panel-raised); border:1px solid var(--line); border-left:4px solid var(--cyan); padding:14px 20px; margin-bottom:16px; border-radius:6px; display:flex; align-items:center; gap:18px;">
                <img src="{avatar_src}" style="width:58px; height:58px; border-radius:50%; border:2px solid var(--cyan); object-fit:cover;" alt="Avatar"/>
                <div style="flex:1; min-width:0;">
                    <div style="font-size:1.1rem; font-weight:700; color:var(--text);">{d_name} <span class="chip low">{source_badge}</span></div>
                    <div style="font-size:0.8rem; color:var(--text-dim); margin-top:4px;">
                        Email: <strong style="color:var(--cyan);">{user_val}</strong>
                        {'&nbsp;&middot;&nbsp; Profile: <a href="' + p_url + '" target="_blank" style="color:var(--purple);">' + p_url[:60] + ('…' if len(p_url) > 60 else '') + '</a>' if p_url else ''}
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # ── Breach & Reputation Detail Cards ─────────────────────────────
        intel_cols = st.columns(2)
        with intel_cols[0]:
            # ── HudsonRock Cavalier — infostealer card ────────────────────
            if not hr_rows.empty:
                hr_r = hr_rows.iloc[0]
                is_compromised = "Compromised" in str(hr_r.get("display_name", ""))
                border_clr = "#E8544B" if is_compromised else "var(--cyan)"
                malware_list = hr_r.get("malware_families", []) or []
                countries_list = hr_r.get("countries", []) or []
                comp_count = hr_r.get("compromised_computers", 0)

                # Pre-build all HTML fragments as variables
                mf_chips = "".join(
                    f"<span style='background:rgba(232,84,75,0.15); color:#E8544B; border:1px solid rgba(232,84,75,0.4); border-radius:4px; padding:2px 8px; font-size:0.75rem; margin:2px; display:inline-block;'>{m}</span>"
                    for m in malware_list[:6]
                )
                if is_compromised:
                    countries_str = ", ".join(countries_list[:3]) if countries_list else "—"
                    detail_line = f"<div style='font-size:0.8rem; color:var(--text-dim); margin-bottom:6px;'>Stealer logs: <strong style='color:#E8544B;'>{comp_count}</strong> &nbsp;·&nbsp; Countries: {countries_str}</div>"
                    body_content = detail_line + (mf_chips if mf_chips else "")
                else:
                    body_content = "<span style='color:#4ECDC4; font-size:0.85rem;'>&#10003; No infostealer compromise detected</span>"

                hr_display = hr_r.get("display_name", "—")
                st.markdown(
                    f"<div style='background:var(--panel-raised); border:1px solid var(--line); border-left:4px solid {border_clr}; padding:14px; border-radius:6px; margin-bottom:12px;'>"
                    f"<div style='font-size:0.7rem; text-transform:uppercase; letter-spacing:.08em; color:var(--text-dim); margin-bottom:6px;'>HudsonRock — Infostealer Intelligence</div>"
                    f"<div style='font-size:1rem; font-weight:700; color:var(--text); margin-bottom:8px;'>{hr_display}</div>"
                    f"{body_content}"
                    f"</div>",
                    unsafe_allow_html=True,
                )

            # ── LeakCheck.io — breach database card ───────────────────────
            if not lc_rows.empty:
                lc_r = lc_rows.iloc[0]
                lc_name = str(lc_r.get("display_name", "—"))
                is_lc_exposed = "Exposed" in lc_name
                lc_border = "#E8544B" if is_lc_exposed else "var(--cyan)"
                sources = lc_r.get("sources", []) or []
                fields = lc_r.get("exposed_fields", []) or []

                # Pre-build HTML fragments
                src_chips = "".join(
                    f"<span style='background:rgba(232,84,75,0.15); color:#E8544B; border:1px solid rgba(232,84,75,0.4); border-radius:4px; padding:2px 8px; font-size:0.75rem; margin:2px; display:inline-block;'>{s}</span>"
                    for s in sources[:8]
                ) if is_lc_exposed else ""
                field_chips = "".join(
                    f"<span style='background:rgba(155,89,182,0.15); color:#9B59B6; border:1px solid rgba(155,89,182,0.4); border-radius:4px; padding:2px 8px; font-size:0.75rem; margin:2px; display:inline-block;'>{f}</span>"
                    for f in fields[:6]
                ) if is_lc_exposed else ""
                fields_line = f"<div style='margin-top:6px; font-size:0.75rem; color:var(--text-dim);'>Exposed data types: {field_chips}</div>" if field_chips else ""
                clean_msg = "" if is_lc_exposed else "<span style='color:#4ECDC4; font-size:0.85rem;'>&#10003; Not found in public breach records</span>"

                st.markdown(
                    f"<div style='background:var(--panel-raised); border:1px solid var(--line); border-left:4px solid {lc_border}; padding:14px; border-radius:6px; margin-bottom:12px;'>"
                    f"<div style='font-size:0.7rem; text-transform:uppercase; letter-spacing:.08em; color:var(--text-dim); margin-bottom:6px;'>LeakCheck.io — Breach Database</div>"
                    f"<div style='font-size:1rem; font-weight:700; color:var(--text); margin-bottom:8px;'>{lc_name}</div>"
                    f"{src_chips}{fields_line}{clean_msg}"
                    f"</div>",
                    unsafe_allow_html=True,
                )

        with intel_cols[1]:
            if not emailrep_rows.empty:
                rep_r = emailrep_rows.iloc[0]
                rep_val = str(rep_r.get("reputation", "unknown")).lower()
                rep_color = {"high": "var(--cyan)", "medium": "#F0A63A", "low": "#E8544B", "none": "#E8544B"}.get(rep_val, "var(--text-dim)")
                profiles = rep_r.get("linked_profiles", [])
                profiles_html = ""
                if isinstance(profiles, list) and profiles:
                    profiles_html = "".join(f"<span class='chip low' style='margin:2px;display:inline-block;'>{p}</span>" for p in profiles[:8])
                cred_leaked = rep_r.get("credentials_leaked", False)
                first_seen = rep_r.get("first_seen", "")
                st.markdown(f"""
                <div style="background:var(--panel-raised); border:1px solid var(--line); border-left:4px solid {rep_color}; padding:14px; border-radius:6px; margin-bottom:12px;">
                    <div style="font-size:0.7rem; text-transform:uppercase; letter-spacing:.08em; color:var(--text-dim); margin-bottom:6px;">EmailRep.io Intelligence</div>
                    <div style="font-size:1rem; font-weight:700; color:{rep_color}; margin-bottom:4px;">Reputation: {rep_val.title()}</div>
                    <div style="font-size:0.8rem; color:var(--text-dim); margin-bottom:8px;">
                        {'🔐 Credentials leaked &nbsp;·&nbsp; ' if cred_leaked else ''}
                        {'First seen: ' + first_seen if first_seen else ''}
                    </div>
                    {profiles_html}
                </div>
                """, unsafe_allow_html=True)

        # ── MX / Infrastructure inline card ──────────────────────────────
        mx_rows = user_df[user_df["platform"] == "MX Infrastructure"]
        if not mx_rows.empty:
            mx_r = mx_rows.iloc[0]
            infra_type = mx_r.get("infra_type", str(mx_r.get("display_name", "")))
            mx_list = mx_r.get("mx_records", [])
            mx_str = " · ".join(mx_list[:4]) if isinstance(mx_list, list) else ""
            st.markdown(f"""
            <div style="background:var(--panel-raised); border:1px solid var(--line); border-left:4px solid var(--purple); padding:12px 16px; border-radius:6px; margin-bottom:12px;">
                <div style="font-size:0.7rem; text-transform:uppercase; letter-spacing:.08em; color:var(--text-dim); margin-bottom:4px;">Email Infrastructure (MX Records)</div>
                <div style="font-size:0.95rem; font-weight:700; color:var(--text);">{infra_type}</div>
                <div style="font-size:0.78rem; color:var(--text-dim); margin-top:4px;">{mx_str}</div>
            </div>
            """, unsafe_allow_html=True)

    # ── Charts row ───────────────────────────────────────────────────────
    left, right = st.columns([1, 1])

    with left:
        st.markdown("<div class='section-eyebrow'>Platform Detection & Confidence Matrix</div>", unsafe_allow_html=True)
        if not user_df.empty:
            pf = user_df.copy()
            for c in ["display_name", "category", "confidence"]:
                if c not in pf.columns:
                    pf[c] = "—" if c != "confidence" else 80
            pf = pf.sort_values("confidence", ascending=True)
            fig_pf = px.bar(
                pf, x="confidence", y="platform", orientation="h",
                color="confidence", color_continuous_scale=["#223038", "#4FD9C9", "#F0A63A"],
                hover_data={"display_name": True, "category": True, "confidence": True},
            )
            fig_pf.update_coloraxes(showscale=False)
            fig_pf.update_layout(xaxis_title="Confidence Rating (%)", yaxis_title="")
            st.plotly_chart(style_fig(fig_pf, height=360))
        else:
            st.markdown("<p style='color:var(--text-dim); font-size:0.8rem; font-style:italic;'>No identity footprint data yet. Select Email / Identity in the left sidebar and click START.</p>", unsafe_allow_html=True)

    with right:
        st.markdown("<div class='section-eyebrow'>Bio Keyword & Interest Cloud</div>", unsafe_allow_html=True)
        kw_rows = []
        if not user_df.empty:
            for _, r in user_df.iterrows():
                if isinstance(r.get("bio_keywords"), list):
                    for kw in r["bio_keywords"]:
                        kw_rows.append(kw)
        kw_df = pd.Series(kw_rows).value_counts().reset_index() if kw_rows else pd.DataFrame()
        if not kw_df.empty:
            kw_df.columns = ["keyword", "count"]
            rng = _seed(user_val + "bubble")
            kw_df["x"] = [rng.uniform(0, 10) for _ in range(len(kw_df))]
            kw_df["y"] = [rng.uniform(0, 10) for _ in range(len(kw_df))]
            fig_bubble = px.scatter(
                kw_df, x="x", y="y", size="count", text="keyword", size_max=55,
                color="count", color_continuous_scale=["#223038", "#A855F7", "#F0A63A"],
            )
            fig_bubble.update_traces(textposition="middle center", textfont=dict(color="#F2F5F5", size=11, family="Space Grotesk"))
            fig_bubble.update_coloraxes(showscale=False)
            fig_bubble.update_xaxes(visible=False)
            fig_bubble.update_yaxes(visible=False)
            st.plotly_chart(style_fig(fig_bubble, height=360))
        else:
            st.markdown("<p style='color:var(--text-dim); font-size:0.8rem; font-style:italic;'>No bio keywords extracted.</p>", unsafe_allow_html=True)

    st.markdown("<div class='section-eyebrow'>Verified Platform Hits & Linked Services Register</div>", unsafe_allow_html=True)
    if not user_df.empty:
        show_u = user_df.copy()
        show_u["bio_keywords"] = show_u["bio_keywords"].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
        show_u["associated_email"] = show_u["associated_email"].fillna("—")
        display_cols = [c for c in ["platform", "category", "display_name", "profile_url", "associated_email", "confidence", "bio_keywords"] if c in show_u.columns]
        st.dataframe(show_u[display_cols], width='stretch', hide_index=True)
    else:
        st.markdown("<p style='color:var(--text-dim); font-size:0.8rem; font-style:italic;'>No email sweep data available. Ingest an email address from the sidebar.</p>", unsafe_allow_html=True)


# ---- TAB 3: Topology & Link Graph ----------------------------------------
with tab3:
    if "relationships" in st.session_state.failures:
        st.warning(f"Relationship analysis warning: {st.session_state.failures['relationships']}")

    if rel_df.empty and domain_val and user_val:
        rel_df = generate_auto_relationships(domain_df, user_df, domain_val, user_val)
        st.session_state.rel_df = rel_df

    st.markdown("<div class='section-eyebrow'>Infrastructure & Identity Topology Correlation</div>", unsafe_allow_html=True)
    physics_on = st.toggle("Enable physics engine", value=True)

    net = Network(height="540px", width="100%", bgcolor="#0A0D10", font_color="#C9D3D6", directed=False)
    if domain_val:
        net.add_node(domain_val, label=domain_val, color="#4FD9C9", shape="dot", size=28, title="Domain (root)")
    if user_val:
        user_node_label = user_val if "@" in user_val else f"@{user_val}"
        net.add_node(user_val, label=user_node_label, color="#3AD65B", shape="dot", size=28, title="Target Email / Identity (root)")
    if ip_val:
        net.add_node(ip_val, label=f"IP: {ip_val}", color="#A855F7", shape="dot", size=28, title="IP Target (root)")

    for _, r in domain_df.head(10).iterrows():
        net.add_node(r["subdomain"], color="#4FD9C9", shape="dot", size=14, title=r["ip_address"])
        net.add_node(r["ip_address"], color="#E8544B", shape="dot", size=10, title="Resolved IP")
        if domain_val:
            net.add_edge(domain_val, r["subdomain"])
        net.add_edge(r["subdomain"], r["ip_address"])

    if not ip_df.empty:
        for _, r in ip_df.iterrows():
            if ip_val:
                net.add_node(r["isp"], color="#A855F7", shape="dot", size=16, title=r.get("as_number", "ISP"))
                net.add_edge(ip_val, r["isp"])

    if not user_df.empty:
        for _, r in user_df.iterrows():
            net.add_node(r["platform"], color="#3AD65B", shape="dot", size=14, title=r["profile_url"])
            if user_val:
                net.add_edge(user_val, r["platform"], title="email_linked_service")

    if not rel_df.empty:
        for _, r in rel_df.iterrows():
            if r["source"] in net.get_nodes() and r["target"] in net.get_nodes():
                net.add_edge(r["source"], r["target"], color="#F0A63A", title=f"{r['relationship_type']} ({r['confidence_score']}%)", dashes=True)

    net.toggle_physics(physics_on)
    net.set_edge_smooth("dynamic")
    html_path = "/tmp/entity_graph.html"
    net.write_html(html_path)
    with open(html_path, "r", encoding="utf-8") as f:
        graph_html = f.read()
    components.html(graph_html, height=560, scrolling=False)


    st.markdown("<div class='section-eyebrow'>Relationship Register</div>", unsafe_allow_html=True)
    if rel_df.empty:
        st.markdown("<p style='color:var(--text-dim); font-size:0.8rem;'>No correlating signals found between active targets.</p>", unsafe_allow_html=True)
    else:
        for _, r in rel_df.iterrows():
            conf = r["confidence_score"]
            cls = "high" if conf >= 80 else "med" if conf >= 55 else "low"
            st.markdown(
                f"`{r['source']}`  →  `{r['target']}`  &nbsp; "
                f"<span class='chip {cls}'>{r['relationship_type']} · {conf}%</span>",
                unsafe_allow_html=True,
            )


# ---- TAB 4: Tactical GeoINT Map ------------------------------------------
with tab4:
    st.markdown("<div class='section-eyebrow'>Tactical GeoINT & Geographic Threat Map</div>", unsafe_allow_html=True)

    map_nodes = []

    # 1. Primary IP Target
    if not ip_df.empty:
        for _, r in ip_df.iterrows():
            if float(r.get("lat", 0.0)) != 0.0 or float(r.get("lon", 0.0)) != 0.0:
                s_ports_str = ", ".join(str(p) for p in r.get("shodan_ports", [])) or "None"
                map_nodes.append({
                    "node_type": "Primary IP Target",
                    "label": f"{r['ip_address']}",
                    "ip_address": r["ip_address"],
                    "lat": float(r["lat"]),
                    "lon": float(r["lon"]),
                    "location": f"{r.get('city', '—')}, {r.get('country', '—')}",
                    "isp": r.get("isp", "—"),
                    "ports": s_ports_str,
                    "marker_size": 18,
                    "color": "#E8544B"
                })

    # 2. Subdomains & Resolved IPs
    if not domain_df.empty:
        for _, r in domain_df.iterrows():
            if float(r.get("lat", 0.0)) != 0.0 or float(r.get("lon", 0.0)) != 0.0:
                map_nodes.append({
                    "node_type": "Subdomain / Infra Node",
                    "label": f"{r['subdomain']}",
                    "ip_address": r.get("ip_address", "—"),
                    "lat": float(r["lat"]),
                    "lon": float(r["lon"]),
                    "location": f"{r.get('city', '—')}, {r.get('country', '—')}",
                    "isp": r.get("isp", "—"),
                    "ports": "—",
                    "marker_size": 12,
                    "color": "#4FD9C9"
                })

    map_df = pd.DataFrame(map_nodes)

    if not map_df.empty:
        g1, g2, g3, g4 = st.columns(4)
        with g1:
            st.markdown(f"""
            <div class="metric-card alt">
                <div class="metric-label">Mapped Nodes</div>
                <div class="metric-value">{len(map_df)}</div>
            </div>
            """, unsafe_allow_html=True)
        with g2:
            unique_countries = len(map_df["location"].apply(lambda x: x.split(",")[-1].strip()).unique())
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Geographic Countries</div>
                <div class="metric-value">{unique_countries}</div>
            </div>
            """, unsafe_allow_html=True)
        with g3:
            st.markdown(f"""
            <div class="metric-card purple">
                <div class="metric-label">Primary Region</div>
                <div class="metric-value" style="font-size:1.1rem;">{map_df.iloc[0]['location']}</div>
            </div>
            """, unsafe_allow_html=True)
        with g4:
            st.markdown(f"""
            <div class="metric-card alt">
                <div class="metric-label">Map Engine</div>
                <div class="metric-value" style="font-size:1.1rem;">Dark Vector Map</div>
            </div>
            """, unsafe_allow_html=True)

        fig_geoint = px.scatter_geo(
            map_df,
            lat="lat",
            lon="lon",
            color="node_type",
            size="marker_size",
            hover_name="label",
            hover_data={
                "ip_address": True,
                "location": True,
                "isp": True,
                "ports": True,
                "node_type": False,
                "marker_size": False,
                "lat": False,
                "lon": False
            },
            color_discrete_map={
                "Primary IP Target": "#E8544B",
                "Subdomain / Infra Node": "#4FD9C9",
            },
            projection="natural earth",
        )

        # Add visual flight connection lines if multiple nodes exist
        if len(map_df) > 1:
            target_node = map_df.iloc[0]
            for i in range(1, len(map_df)):
                row_node = map_df.iloc[i]
                fig_geoint.add_trace(
                    px.line_geo(
                        lat=[target_node["lat"], row_node["lat"]],
                        lon=[target_node["lon"], row_node["lon"]],
                    ).data[0]
                )
                fig_geoint.data[-1].line.color = "rgba(240, 166, 58, 0.4)"
                fig_geoint.data[-1].line.width = 1

        fig_geoint.update_geos(
            bgcolor="#0A0D10",
            showland=True, landcolor="#12171C",
            showocean=True, oceancolor="#0A0D10",
            showlakes=True, lakecolor="#0A0D10",
            showcountries=True, countrycolor="#223038",
            showcoastlines=True, coastlinecolor="#223038",
        )
        st.plotly_chart(style_fig(fig_geoint, height=540))
    else:
        st.markdown("<p style='color:var(--text-dim); font-size:0.85rem; font-style:italic;'>No geographic coordinates available to render tactical map. Ingest a Domain or IP address in the sidebar.</p>", unsafe_allow_html=True)

with tab5:
    st.markdown("<h3 style='color:var(--cyan); margin-bottom: 0;'>Gemini AI Executive Brief & Reporting</h3>", unsafe_allow_html=True)
    st.markdown("<p style='color:var(--text-dim); font-size:0.85rem; margin-bottom: 20px;'>Generate a synthesized intelligence brief and download a PDF report of all findings.</p>", unsafe_allow_html=True)
    
    colA, colB = st.columns([1, 1])
    
    with colA:
        if st.button("Generate AI Executive Brief", use_container_width=True):
            with st.spinner("Analyzing OSINT data with Gemini..."):
                summary = generate_osint_brief(
                    domain_val, user_val, ip_val,
                    domain_df, user_df, ip_df,
                    risk_result
                )
                st.session_state['ai_summary'] = summary
    
    with colB:
        if 'ai_summary' not in st.session_state:
            st.session_state['ai_summary'] = ""
            
        # We allow downloading the PDF even if AI summary wasn't generated yet (it will just be blank)
        pdf_bytes = build_pdf_report(
            domain_val, user_val, ip_val,
            domain_df, user_df, ip_df,
            risk_result,
            st.session_state['ai_summary']
        )
        st.download_button(
            label="Download PDF Report",
            data=pdf_bytes,
            file_name=f"OSINT_Report_{domain_val or user_val or ip_val or 'Target'}.pdf",
            mime="application/pdf",
            use_container_width=True
        )

    if st.session_state.get('ai_summary'):
        st.markdown("---")
        st.markdown("### Executive Brief")
        st.markdown(f"<div style='background:var(--panel-bg); padding:20px; border-radius:8px; border:1px solid var(--border-color);'>{st.session_state['ai_summary']}</div>", unsafe_allow_html=True)# Force reload
