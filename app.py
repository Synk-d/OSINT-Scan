"""
OSINT Aggregation & Visualization Dashboard — Frontend + Backend (v0.5.1)
--------------------------------------------------------------------
Calls real ingestion workers in workers/ (crt.sh, DNS, WHOIS, IP Geolocation,
Region Area tracking, GitHub/Reddit/Keybase APIs). Live lookups only — real data only.
If a lookup fails (no internet, rate-limited, invalid target), the dashboard
shows an error message and empty results instead of faked data.

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
import plotly.express as px
import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv
from pyvis.network import Network

from db import repository as repo
from db.connection import DatabaseUnavailable
from workers.domain_worker import OsintLookupError as DomainLookupError, run_domain_osint as _live_domain_osint
from workers.ip_worker import OsintLookupError as IpLookupError, run_ip_osint as _live_ip_osint
from workers.net_utils import DOMAIN_RE, _seed
from workers.relationship_engine import generate_auto_relationships
from workers.user_worker import OsintLookupError as UserLookupError, run_user_osint as _live_user_osint

load_dotenv()
FORCE_MOCK_DATA = os.getenv("FORCE_MOCK_DATA", "false").lower() == "true"


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
# DESIGN TOKENS
# ----------------------------------------------------------------------------
CSS = """
<style>
/* Imported Orbitron for a high-tech cybersecurity/logo aesthetic */
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

.stTabs [data-baseweb="tab-list"] { gap: 4px; border-bottom: 1px solid var(--line); }
.stTabs [data-baseweb="tab"] {
    background-color: transparent; color: var(--text-dim); border: none;
    font-size: 0.78rem; letter-spacing: 0.08em; text-transform: uppercase; padding: 10px 4px;
}
.stTabs [aria-selected="true"] { color: var(--amber) !important; border-bottom: 2px solid var(--amber) !important; }

/* TACTICAL BUTTON STYLING */
.stButton > button {
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
.stButton > button p { 
    text-align: center !important; 
    margin: 0 !important;
    flex: 1 !important; 
    display: flex !important;
    justify-content: center !important;
}
.stButton > button:hover { 
    background-color: #FFC069 !important; 
    border-color: #FFC069 !important; 
    color: var(--void) !important;
    box-shadow: 0 6px 20px rgba(240, 166, 58, 0.3) !important;
    transform: translateY(-2px) !important;
}
.stButton > button:active { 
    background-color: #D48F2E !important; 
    border-color: #D48F2E !important;
    transform: translateY(1px) !important;
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
            "platform", "profile_url", "associated_email", "bio_keywords", "confidence", "discovered_at",
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
    """Extract clean username from profile URLs or raw input strings."""
    username_value = username_value.strip().lstrip("@")
    if username_value.startswith(("http://", "https://")) or "://" in username_value:
        try:
            parsed = urlparse(username_value)
            path_parts = [p for p in parsed.path.split("/") if p]
            if path_parts:
                username_value = path_parts[-1] if path_parts[0] in ("in", "user", "users", "u", "profile") and len(path_parts) > 1 else path_parts[0]
        except Exception:
            pass
    elif "/" in username_value:
        parts = [p for p in username_value.split("/") if p]
        if parts:
            username_value = parts[-1] if len(parts) > 1 else parts[0]
    return username_value.strip().lstrip("@")


def validate_domain(domain_value: str) -> tuple[bool, str, str]:
    """Validate domain input. Returns (is_valid, error_message, cleaned_domain)."""
    cleaned = clean_domain_input(domain_value)
    if not cleaned:
        return False, "Domain cannot be empty.", ""
    if not DOMAIN_RE.match(cleaned):
        return False, f"'{domain_value}' is not a valid domain. Use format: example.com", ""
    return True, "", cleaned


def validate_username(username_value: str) -> tuple[bool, str, str]:
    """Validate username input. Returns (is_valid, error_message, cleaned_username)."""
    cleaned = clean_user_input(username_value)
    if not cleaned:
        return False, "Username cannot be empty.", ""
    if len(cleaned) < 2:
        return False, "Username must be at least 2 characters.", ""
    if not re.match(r"^[a-zA-Z0-9_.-]+$", cleaned):
        return False, f"'{username_value}' contains invalid characters. Use only letters, numbers, dots, underscores, and hyphens.", ""
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
    """Runs real live user sweep."""
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
            user_target_id = repo.get_or_create_target("user", user_val)
            repo.save_user_intel(user_target_id, user_df.to_dict("records"))
        if ip_val and not ip_df.empty:
            ip_target_id = repo.get_or_create_target("ip", ip_val)
            repo.save_ip_intel(ip_target_id, ip_df.to_dict("records"))
        if domain_val and user_val and not rel_df.empty:
            domain_target_id = repo.get_or_create_target("domain", domain_val)
            user_target_id = repo.get_or_create_target("user", user_val)
            repo.save_relationships(domain_target_id, user_target_id, rel_df.to_dict("records"))
    except DatabaseUnavailable:
        pass


# ----------------------------------------------------------------------------
# SIDEBAR
# ----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div class="sidebar-logo-container">
        <p class="console-title">OSINT<span>-</span>Scan</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<div class='section-eyebrow'>Target Ingestion</div>", unsafe_allow_html=True)
    target_type = st.radio("Target type", ["domain", "user", "ip"], horizontal=True, label_visibility="collapsed")

    if target_type == "domain":
        target_value = st.text_input(
            "Domain", value="", placeholder="example.com",
            key="domain_input", label_visibility="collapsed",
        )
    elif target_type == "user":
        target_value = st.text_input(
            "Username", value="", placeholder="username",
            key="user_input", label_visibility="collapsed",
        )
    else:
        target_value = st.text_input(
            "IP Address", value="", placeholder="8.8.8.8",
            key="ip_input", label_visibility="collapsed",
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
            "target": target_value
        })
        st.session_state.history = st.session_state.history[:10]

    if not st.session_state.history:
        st.markdown("<p style='color:var(--text-dim); font-size:0.75rem; font-style:italic;'>No recent sweeps found.</p>", unsafe_allow_html=True)
    else:
        for item in st.session_state.history:
            icon = "🌐" if item["type"] == "domain" else ("👤" if item["type"] == "user" else "📍")
            st.markdown(f"""
            <div class="history-item">
                <span class="target">{icon} &nbsp; {item['target']}</span>
                <span class="time">{item['time']}</span>
            </div>
            """, unsafe_allow_html=True)


# ----------------------------------------------------------------------------
# CORE LOGIC & SWEEP EXECUTION
# ----------------------------------------------------------------------------
if sweep and target_value.strip():
    st.session_state.failures = {}
    
    if target_type == "domain":
        is_valid, error_msg, cleaned_val = validate_domain(target_value)
        if not is_valid:
            st.error(f"❌ {error_msg}")
        else:
            st.session_state.domain_val = cleaned_val
            try:
                with st.spinner(f"Sweeping {cleaned_val} — live lookups in progress…"):
                    df, src = run_domain_osint(st.session_state.domain_val)
                    st.session_state.domain_df = df
                    st.session_state.data_source["domain"] = src
                st.session_state.domain_swept = True
            except Exception as e:
                st.error(f"❌ Domain lookup failed: {e}")

    elif target_type == "user":
        is_valid, error_msg, cleaned_val = validate_username(target_value)
        if not is_valid:
            st.error(f"❌ {error_msg}")
        else:
            st.session_state.user_val = cleaned_val
            try:
                with st.spinner(f"Sweeping @{cleaned_val} — checking live sources…"):
                    df, src = run_user_osint(st.session_state.user_val)
                    st.session_state.user_df = df
                    st.session_state.data_source["user"] = src
                st.session_state.user_swept = True
            except Exception as e:
                st.error(f"❌ User lookup failed: {e}")

    else:  # ip
        is_valid, error_msg, cleaned_val = validate_ip_address(target_value)
        if not is_valid:
            st.error(f"❌ {error_msg}")
        else:
            st.session_state.ip_val = cleaned_val
            try:
                with st.spinner(f"Geolocating {cleaned_val} — fetching live region area & network data…"):
                    df, src = run_ip_osint(st.session_state.ip_val)
                    st.session_state.ip_df = df
                    st.session_state.data_source["ip"] = src
                st.session_state.ip_swept = True
            except Exception as e:
                st.error(f"❌ IP Geolocation failed: {e}")

    if st.session_state.domain_swept and st.session_state.user_swept:
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
        f"📍 {ip_val}" if ip_swept else None,
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
# TOP METRICS
# ----------------------------------------------------------------------------
domain_ips = domain_df[domain_df["ip_address"] != "—"]["ip_address"].tolist() if not domain_df.empty else []
direct_ips = ip_df["ip_address"].tolist() if not ip_df.empty else []
total_unique_ips = len(set(domain_ips + direct_ips))

c1, c2, c3, c4, c5 = st.columns(5)
metrics = [
    (c1, "Subdomains Found", len(domain_df), "", ""),
    (c2, "Platform Hits", len(user_df), "alt", ""),
    (c3, "Tracked IP Locations", total_unique_ips, "purple", ""),
    (c4, "Entity Links", len(rel_df), "alt", ""),
    (c5, "High-Confidence Links", int((rel_df["confidence_score"] >= 80).sum()) if not rel_df.empty else 0, "danger", ""),
]
for col, label, value, cls, delta in metrics:
    with col:
        st.markdown(f"""
        <div class="metric-card {cls}">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
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
            "registrar": r.get("as_number", "—"),
            "mx_records": f"PTR: {r.get('reverse_dns', '—')}",
            "discovered_at": r.get("discovered_at"),
        })

combined_infra_df = pd.DataFrame(infra_records)


# ----------------------------------------------------------------------------
# TABS
# ----------------------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs([
    "Infrastructure & IP Analytics",
    "Identity Footprinting",
    "IP Geolocation & Region",
    "Entity Link Graph"
])

# ---- TAB 1: Infrastructure & IP Analytics --------------------------------
with tab1:
    if "domain" in st.session_state.failures:
        st.warning(f"⚠️ Domain lookup warning: {st.session_state.failures['domain']}")
    if "ip" in st.session_state.failures:
        st.warning(f"⚠️ IP lookup warning: {st.session_state.failures['ip']}")

    # If IP scan was run, show prominent summary alert
    if ip_swept and not ip_df.empty:
        r0 = ip_df.iloc[0]
        st.success(
            f"📍 **IP Target Scanned**: `{r0['ip_address']}` | "
            f"**Location Region Area**: {r0['region_name']}, {r0['city']} ({r0['country']}) | "
            f"**ISP**: {r0['isp']} | **ASN**: {r0['as_number']} | **Reverse DNS**: {r0['reverse_dns']}"
        )
    
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
        st.plotly_chart(style_fig(fig_bar))

    with right:
        st.markdown("<div class='section-eyebrow'>Resolved IP Geolocation</div>", unsafe_allow_html=True)
        geo_df = combined_infra_df[(combined_infra_df["lat"] != 0.0) | (combined_infra_df["lon"] != 0.0)] if not combined_infra_df.empty else pd.DataFrame()
        if geo_df.empty:
            geo_df = pd.DataFrame({"lat": [], "lon": [], "target_label": [], "ip_address": [], "isp": [], "region_name": [], "city": [], "country": []})
        
        fig_map = px.scatter_map(
            geo_df, lat="lat", lon="lon", hover_name="target_label",
            hover_data={"ip_address": True, "isp": True, "region_name": True, "city": True, "lat": False, "lon": False},
            color_discrete_sequence=["#4FD9C9"], zoom=1,
        )
        fig_map.update_traces(marker=dict(size=14))
        fig_map.update_layout(map_style="carto-darkmatter")
        st.plotly_chart(style_fig(fig_map, height=380))

    st.markdown("<div class='section-eyebrow'>Subdomain & IP Region Register</div>", unsafe_allow_html=True)
    if not combined_infra_df.empty:
        cols = [c for c in ["target_label", "ip_address", "city", "region_name", "country", "isp", "registrar", "mx_records", "discovered_at"] if c in combined_infra_df.columns]
        st.dataframe(combined_infra_df[cols], width='stretch', hide_index=True)
    else:
        st.markdown("<p style='color:var(--text-dim); font-size:0.8rem; font-style:italic;'>No infrastructure or IP sweep data yet. Select Domain or IP in the sidebar and click START.</p>", unsafe_allow_html=True)


# ---- TAB 2: Identity Footprinting ---------------------------------------
with tab2:
    if "user" in st.session_state.failures:
        st.warning(f"⚠️ User lookup warning: {st.session_state.failures['user']}")
    
    left, right = st.columns([1, 1])

    with left:
        st.markdown("<div class='section-eyebrow'>Platform Detection Matrix</div>", unsafe_allow_html=True)
        if not user_df.empty:
            pf = user_df.sort_values("confidence", ascending=True)
            fig_pf = px.bar(pf, x="confidence", y="platform", orientation="h",
                             color="confidence", color_continuous_scale=["#223038", "#4FD9C9", "#F0A63A"])
            fig_pf.update_coloraxes(showscale=False)
            fig_pf.update_layout(xaxis_title="confidence score", yaxis_title="")
            st.plotly_chart(style_fig(fig_pf))
        else:
            st.markdown("<p style='color:var(--text-dim); font-size:0.8rem; font-style:italic;'>No identity footprint data yet.</p>", unsafe_allow_html=True)

    with right:
        st.markdown("<div class='section-eyebrow'>Bio Keyword Trends</div>", unsafe_allow_html=True)
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
                kw_df, x="x", y="y", size="count", text="keyword", size_max=60,
                color="count", color_continuous_scale=["#223038", "#F0A63A"],
            )
            fig_bubble.update_traces(textposition="middle center", textfont=dict(color="#0A0D10", size=10))
            fig_bubble.update_coloraxes(showscale=False)
            fig_bubble.update_xaxes(visible=False)
            fig_bubble.update_yaxes(visible=False)
            st.plotly_chart(style_fig(fig_bubble))
        else:
            st.markdown("<p style='color:var(--text-dim); font-size:0.8rem; font-style:italic;'>No bio keywords found.</p>", unsafe_allow_html=True)

    st.markdown("<div class='section-eyebrow'>Verified Profile Hits</div>", unsafe_allow_html=True)
    if not user_df.empty:
        show_u = user_df.copy()
        show_u["bio_keywords"] = show_u["bio_keywords"].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
        show_u["associated_email"] = show_u["associated_email"].fillna("— masked / not found —")
        st.dataframe(
            show_u[["platform", "profile_url", "associated_email", "confidence", "bio_keywords"]],
            width='stretch', hide_index=True,
        )
    else:
        st.markdown("<p style='color:var(--text-dim); font-size:0.8rem; font-style:italic;'>No user sweep data yet. Enter a username in the sidebar and click START.</p>", unsafe_allow_html=True)


# ---- TAB 3: IP Geolocation & Location Region Area Tracker --------------
with tab3:
    st.markdown("<div class='section-eyebrow'>Interactive Direct IP Lookup</div>", unsafe_allow_html=True)
    quick_col1, quick_col2 = st.columns([3, 1])
    with quick_col1:
        quick_ip = st.text_input("Enter IP Address / Hostname", value="", placeholder="e.g. 8.8.8.8 or 1.1.1.1", key="tab_ip_search", label_visibility="collapsed")
    with quick_col2:
        quick_btn = st.button("GEOLOCATE IP", use_container_width=True, key="btn_quick_ip")
    
    if quick_btn and quick_ip.strip():
        is_valid, err, cleaned_ip = validate_ip_address(quick_ip)
        if not is_valid:
            st.error(f"❌ {err}")
        else:
            try:
                with st.spinner(f"Geolocating {cleaned_ip} live…"):
                    df_q, _ = run_ip_osint(cleaned_ip)
                    st.session_state.ip_val = cleaned_ip
                    st.session_state.ip_df = df_q
                    st.session_state.ip_swept = True
                    st.rerun()
            except Exception as exc:
                st.error(f"❌ IP Lookup failed: {exc}")

    # Gather all available IP records from both direct IP sweeps and domain subdomains
    all_ip_records = []
    if not ip_df.empty:
        for _, r in ip_df.iterrows():
            all_ip_records.append({
                "target_or_host": f"IP: {r['ip_address']}",
                "ip_address": r["ip_address"],
                "city": r.get("city", "—"),
                "region_name": r.get("region_name", "—"),
                "country": r.get("country", "—"),
                "lat": float(r.get("lat", 0.0)),
                "lon": float(r.get("lon", 0.0)),
                "isp": r.get("isp", "—"),
                "as_number": r.get("as_number", "—"),
                "timezone": r.get("timezone", "—"),
                "reverse_dns": r.get("reverse_dns", "—"),
                "discovered_at": r.get("discovered_at"),
            })
    
    if not domain_df.empty:
        for _, r in domain_df.iterrows():
            if r["ip_address"] not in ["—", "Unresolved", "Unavailable"] and (r["lat"] != 0.0 or r["lon"] != 0.0):
                all_ip_records.append({
                    "target_or_host": r["subdomain"],
                    "ip_address": r["ip_address"],
                    "city": r.get("city", "—"),
                    "region_name": r.get("region_name", "—"),
                    "country": r.get("country", "—"),
                    "lat": float(r.get("lat", 0.0)),
                    "lon": float(r.get("lon", 0.0)),
                    "isp": r.get("isp", "—"),
                    "as_number": "—",
                    "timezone": "—",
                    "reverse_dns": "—",
                    "discovered_at": r.get("discovered_at"),
                })
    
    combined_ip_df = pd.DataFrame(all_ip_records)

    if combined_ip_df.empty:
        st.info("ℹ️ No IP location data available yet. Enter an IP address above or run a Domain/IP sweep in the sidebar.")
    else:
        # Display Location & Region Key Highlights Cards
        primary_row = combined_ip_df.iloc[0]
        k1, k2, k3, k4, k5 = st.columns(5)
        with k1:
            st.markdown(f"""
            <div class="metric-card alt">
                <div class="metric-label">Target IP</div>
                <div class="metric-value" style="font-size:1.3rem;">{primary_row['ip_address']}</div>
            </div>
            """, unsafe_allow_html=True)
        with k2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Location Region Area</div>
                <div class="metric-value" style="font-size:1.3rem;">{primary_row['region_name']}</div>
            </div>
            """, unsafe_allow_html=True)
        with k3:
            st.markdown(f"""
            <div class="metric-card alt">
                <div class="metric-label">City / Country</div>
                <div class="metric-value" style="font-size:1.3rem;">{primary_row['city']}, {primary_row['country']}</div>
            </div>
            """, unsafe_allow_html=True)
        with k4:
            st.markdown(f"""
            <div class="metric-card purple">
                <div class="metric-label">ISP / Network</div>
                <div class="metric-value" style="font-size:1.1rem; overflow:hidden; text-overflow:ellipsis;">{primary_row['isp']}</div>
            </div>
            """, unsafe_allow_html=True)
        with k5:
            st.markdown(f"""
            <div class="metric-card alt">
                <div class="metric-label">Timezone</div>
                <div class="metric-value" style="font-size:1.1rem;">{primary_row['timezone']}</div>
            </div>
            """, unsafe_allow_html=True)

        map_col, chart_col = st.columns([1.3, 1])

        with map_col:
            st.markdown("<div class='section-eyebrow'>Interactive Regional Location Map</div>", unsafe_allow_html=True)
            fig_ip_map = px.scatter_map(
                combined_ip_df, lat="lat", lon="lon", hover_name="target_or_host",
                hover_data={"ip_address": True, "region_name": True, "city": True, "country": True, "isp": True, "lat": False, "lon": False},
                color_discrete_sequence=["#F0A63A"], zoom=2,
            )
            fig_ip_map.update_traces(marker=dict(size=14))
            fig_ip_map.update_layout(map_style="carto-darkmatter")
            st.plotly_chart(style_fig(fig_ip_map, height=390))

        with chart_col:
            st.markdown("<div class='section-eyebrow'>Location Region Area Breakdown</div>", unsafe_allow_html=True)
            region_counts = combined_ip_df["region_name"].value_counts().reset_index()
            region_counts.columns = ["region_name", "count"]
            fig_reg = px.bar(
                region_counts, x="count", y="region_name", orientation="h",
                color="count", color_continuous_scale=["#223038", "#A855F7", "#4FD9C9"]
            )
            fig_reg.update_coloraxes(showscale=False)
            fig_reg.update_layout(xaxis_title="Tracked IPs", yaxis_title="Region Area")
            st.plotly_chart(style_fig(fig_reg, height=390))

        st.markdown("<div class='section-eyebrow'>Detailed IP Location & Region Register</div>", unsafe_allow_html=True)
        st.dataframe(
            combined_ip_df[["target_or_host", "ip_address", "city", "region_name", "country", "isp", "as_number", "timezone", "reverse_dns", "discovered_at"]],
            width='stretch', hide_index=True,
        )


# ---- TAB 4: Entity Link Graph --------------------------------------------
with tab4:
    if "relationships" in st.session_state.failures:
        st.warning(f"⚠️ Relationship analysis warning: {st.session_state.failures['relationships']}")
    
    st.markdown("<div class='section-eyebrow'>Cross-Entity Correlation Topology</div>", unsafe_allow_html=True)
    physics_on = st.toggle("Enable physics engine", value=True)

    net = Network(height="520px", width="100%", bgcolor="#0A0D10", font_color="#C9D3D6", directed=False)
    if domain_val:
        net.add_node(domain_val, label=domain_val, color="#4FD9C9", shape="dot", size=26, title="Domain (root)")
    if user_val:
        net.add_node(user_val, label=f"@{user_val}", color="#3AD65B", shape="dot", size=26, title="Username (root)")
    if ip_val:
        net.add_node(ip_val, label=f"📍 {ip_val}", color="#A855F7", shape="dot", size=26, title="IP Target (root)")

    for _, r in domain_df.head(6).iterrows():
        net.add_node(r["subdomain"], color="#4FD9C9", shape="dot", size=14, title=r["ip_address"])
        net.add_node(r["ip_address"], color="#E8544B", shape="dot", size=10, title="Resolved IP")
        if domain_val:
            net.add_edge(domain_val, r["subdomain"])
        net.add_edge(r["subdomain"], r["ip_address"])

    if not ip_df.empty:
        for _, r in ip_df.iterrows():
            if ip_val:
                net.add_node(r["isp"], color="#A855F7", shape="dot", size=14, title=r["as_number"])
                net.add_edge(ip_val, r["isp"])

    for _, r in user_df.iterrows():
        net.add_node(r["platform"], color="#3AD65B", shape="dot", size=14, title=r["profile_url"])
        if user_val:
            net.add_edge(user_val, r["platform"])

    for _, r in rel_df.iterrows():
        if r["source"] in net.get_nodes() and r["target"] in net.get_nodes():
            net.add_edge(r["source"], r["target"], color="#F0A63A", title=f"{r['relationship_type']} ({r['confidence_score']}%)", dashes=True)

    net.toggle_physics(physics_on)
    net.set_edge_smooth("dynamic")
    html_path = "/tmp/entity_graph.html"
    net.write_html(html_path)
    with open(html_path, "r", encoding="utf-8") as f:
        graph_html = f.read()
    components.html(graph_html, height=540, scrolling=False)

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