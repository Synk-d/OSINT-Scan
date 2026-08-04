"""
OSINT Aggregation & Visualization Dashboard — Frontend + Backend (v0.4.1)
--------------------------------------------------------------------
Calls the real ingestion workers in workers/ (crt.sh, DNS, WHOIS, IP-geo,
GitHub/Reddit/Keybase APIs). If a live lookup fails (no internet,
rate-limited, invalid target), it falls back to the deterministic mock
generators in workers/mock_fallback.py so the UI never breaks. Successful
live sweeps are persisted to PostgreSQL if DB_* env vars point at a
reachable database (see .env.example) — optional, silently skipped
otherwise.

Run with:
    pip install -r requirements.txt
    cp .env.example .env   # optional — only needed for DB persistence
    streamlit run app.py
"""

import os
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv
from pyvis.network import Network

from workers.domain_worker import run_domain_osint as _live_domain_osint, OsintLookupError as DomainLookupError
from workers.user_worker import run_user_osint as _live_user_osint, OsintLookupError as UserLookupError
from workers.relationship_engine import generate_auto_relationships as _live_relationships
from workers.mock_fallback import mock_domain_osint, mock_user_osint, mock_relationships
from db.connection import DatabaseUnavailable
from db import repository as repo

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
.metric-label {
    font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.14em; color: var(--text-dim);
}
.metric-value {
    font-family: 'Space Grotesk', sans-serif; font-size: 1.9rem; font-weight: 700; color: #F2F5F5;
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

/* =========================================
TACTICAL START BUTTON STYLING 
=========================================
*/
.stButton > button {
    background-color: var(--amber) !important; 
    color: var(--void) !important; 
    border: 2px solid var(--amber) !important;
    border-radius: 0px !important; /* Sharp corners */
    font-size: 1.05rem !important; 
    font-weight: 800 !important; 
    letter-spacing: 0.25em !important; 
    text-transform: uppercase !important;
    padding: 16px 20px !important; /* Chunky stretched box */
    display: flex !important; 
    justify-content: center !important; 
    align-items: center !important;
    box-shadow: 0 4px 12px rgba(240, 166, 58, 0.15) !important;
    transition: all 0.2s ease-in-out !important;
}
/* Force the text inside the button to center perfectly */
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

/* Remove default Streamlit input action string instruction overlays */
[data-testid="InputInstructions"] {
    display: none !important;
}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

# ----------------------------------------------------------------------------
# SESSION STATE INIT
# ----------------------------------------------------------------------------
if "history" not in st.session_state:
    st.session_state.history = []

# ----------------------------------------------------------------------------
# BACKEND INTEGRATION — live lookups with automatic mock fallback
# ----------------------------------------------------------------------------
import hashlib
import random


def _seed(value: str) -> random.Random:
    """Used for deterministic layout randomness (e.g. bubble chart positions),
    not for data generation — that lives in workers/mock_fallback.py now."""
    h = hashlib.sha256(value.encode()).hexdigest()
    return random.Random(int(h[:12], 16))


# Tracks whether the most recent sweep used live data or fell back to mock,
# shown as a small tag in the header rather than a warning banner.
data_source = {"domain": "mock", "user": "mock"}


def run_domain_osint(domain_value: str) -> pd.DataFrame:
    if not FORCE_MOCK_DATA:
        try:
            df = _live_domain_osint(domain_value)
            data_source["domain"] = "live"
            return df
        except DomainLookupError as e:
            print(f"[OSINT-Scan] domain lookup fell back to mock for '{domain_value}': {e}")
    data_source["domain"] = "mock"
    return mock_domain_osint(domain_value)


def run_user_osint(username_value: str) -> pd.DataFrame:
    if not FORCE_MOCK_DATA:
        try:
            df = _live_user_osint(username_value)
            data_source["user"] = "live"
            return df
        except UserLookupError as e:
            print(f"[OSINT-Scan] user lookup fell back to mock for '{username_value}': {e}")
    data_source["user"] = "mock"
    return mock_user_osint(username_value)


def generate_auto_relationships(domain_df, user_df, domain_val, user_val):
    if data_source["domain"] == "live" and data_source["user"] == "live":
        rel = _live_relationships(domain_df, user_df, domain_val, user_val)
        if not rel.empty:
            return rel
    return mock_relationships(domain_df, user_df, domain_val, user_val)


def persist_sweep(domain_val, user_val, domain_df, user_df, rel_df):
    """Best-effort persistence — silently no-ops if the DB isn't reachable."""
    try:
        domain_target_id = repo.get_or_create_target("domain", domain_val)
        user_target_id = repo.get_or_create_target("user", user_val)
        if data_source["domain"] == "live":
            repo.save_domain_intel(domain_target_id, domain_df.to_dict("records"))
        if data_source["user"] == "live":
            repo.save_user_intel(user_target_id, user_df.to_dict("records"))
        if not rel_df.empty:
            repo.save_relationships(domain_target_id, user_target_id, rel_df.to_dict("records"))
    except DatabaseUnavailable:
        pass


# ----------------------------------------------------------------------------
# SIDEBAR
# ----------------------------------------------------------------------------
with st.sidebar:
    # Sidebar Logo
    st.markdown("""
    <div class="sidebar-logo-container">
        <p class="console-title">OSINT<span>-</span>Scan</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<div class='section-eyebrow'>Target Ingestion</div>", unsafe_allow_html=True)
    target_type = st.radio("Target type", ["domain", "user"], horizontal=True, label_visibility="collapsed")

    # Separate, independently-keyed inputs per mode (instead of one shared field
    # whose default value swapped based on target_type). Streamlit ties a
    # widget's identity to its full call signature when no key is given, so a
    # value= that changes with target_type was silently resetting whatever
    # you'd typed. Explicit keys fix that and let domain/user remember their
    # own last-typed value independently.
    if target_type == "domain":
        target_value = st.text_input(
            "Domain", value="", placeholder="example.com",
            key="domain_input", label_visibility="collapsed",
        )
    else:
        target_value = st.text_input(
            "Username", value="", placeholder="username",
            key="user_input", label_visibility="collapsed",
        )

    sweep = st.button("START", use_container_width=True)

    # DB Connection Details
    st.markdown("<div class='section-eyebrow'>DB Connection</div>", unsafe_allow_html=True)
    with st.expander("Settings", expanded=False):
        st.text_input("Host", value="localhost", key="db_host")
        st.text_input("Port", value="5432", key="db_port")
        st.text_input("Database", value="osint_intel", key="db_name")
        st.text_input("User", value="postgres", key="db_user")
        st.text_input("Password", value="", type="password", key="db_pass")

    # History Section
    st.markdown("<div class='section-eyebrow'>Sweep History</div>", unsafe_allow_html=True)
    
    if sweep and target_value.strip():
        # Append the new target to history
        st.session_state.history.insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": target_type,
            "target": target_value
        })
        # Keep only the latest 10
        st.session_state.history = st.session_state.history[:10]

    if not st.session_state.history:
        st.markdown("<p style='color:var(--text-dim); font-size:0.75rem; font-style:italic;'>No recent sweeps found.</p>", unsafe_allow_html=True)
    else:
        for item in st.session_state.history:
            icon = "🌐" if item["type"] == "domain" else "👤"
            st.markdown(f"""
            <div class="history-item">
                <span class="target">{icon} &nbsp; {item['target']}</span>
                <span class="time">{item['time']}</span>
            </div>
            """, unsafe_allow_html=True)

# ----------------------------------------------------------------------------
# CORE LOGIC & HEADER INJECTION
# ----------------------------------------------------------------------------
# Each mode only ever updates its OWN target on sweep — the other mode's last
# real value is left untouched instead of being reset to a placeholder.
#
# IMPORTANT: run_domain_osint/run_user_osint now hit real network APIs
# (crt.sh, WHOIS, DNS, ip-api, GitHub) with retries/backoff, which can take
# 10-60+ seconds. Streamlit reruns this whole script on almost any
# interaction (toggling the DB expander, switching tabs, etc.) — so these
# must NOT be called unconditionally on every rerun, only when a sweep is
# actually triggered. Results are cached in session_state in between.
if "domain_val" not in st.session_state:
    st.session_state.domain_val = "example.com"
if "user_val" not in st.session_state:
    st.session_state.user_val = "octocat"
if "domain_df" not in st.session_state:
    st.session_state.domain_df = mock_domain_osint(st.session_state.domain_val)
    data_source["domain"] = "mock"
if "user_df" not in st.session_state:
    st.session_state.user_df = mock_user_osint(st.session_state.user_val)
    data_source["user"] = "mock"
if "rel_df" not in st.session_state:
    st.session_state.rel_df = mock_relationships(
        st.session_state.domain_df, st.session_state.user_df,
        st.session_state.domain_val, st.session_state.user_val,
    )
if "data_source" not in st.session_state:
    st.session_state.data_source = dict(data_source)

if sweep and target_value.strip():
    if target_type == "domain":
        st.session_state.domain_val = target_value.strip()
        with st.spinner(f"Sweeping {target_value.strip()} — live lookups can take up to a minute…"):
            st.session_state.domain_df = run_domain_osint(st.session_state.domain_val)
    else:
        st.session_state.user_val = target_value.strip()
        with st.spinner(f"Sweeping @{target_value.strip()} — checking live sources…"):
            st.session_state.user_df = run_user_osint(st.session_state.user_val)

    st.session_state.rel_df = generate_auto_relationships(
        st.session_state.domain_df, st.session_state.user_df,
        st.session_state.domain_val, st.session_state.user_val,
    )
    st.session_state.data_source = dict(data_source)
    persist_sweep(
        st.session_state.domain_val, st.session_state.user_val,
        st.session_state.domain_df, st.session_state.user_df, st.session_state.rel_df,
    )

domain_val = st.session_state.domain_val
user_val = st.session_state.user_val
domain_df = st.session_state.domain_df
user_df = st.session_state.user_df
rel_df = st.session_state.rel_df

source_label = " · ".join(
    f"{k} {'live' if v == 'live' else 'mock'}" for k, v in st.session_state.data_source.items()
)

# Render the dynamic header on the main page
st.markdown(f"""
<div class="main-header">
    <div class="console-sub">Active case · {domain_val} &nbsp;/&nbsp; @{user_val}</div>
    <div class="console-clock">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        <span class="dim">{source_label}</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ----------------------------------------------------------------------------
# TOP METRICS
# ----------------------------------------------------------------------------
c1, c2, c3, c4 = st.columns(4)
metrics = [
    (c1, "Subdomains Found", len(domain_df), "", ""),
    (c2, "Platform Hits", len(user_df), "alt", ""),
    (c3, "Entity Links", len(rel_df), "alt", ""),
    (c4, "High-Confidence Links", int((rel_df["confidence_score"] >= 80).sum()), "danger", ""),
]
for col, label, value, cls, delta in metrics:
    with col:
        st.markdown(f"""
        <div class="metric-card {cls}">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """, unsafe_allow_html=True)

# ----------------------------------------------------------------------------
# PLOTLY THEME HELPER
# ----------------------------------------------------------------------------
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
tab1, tab2, tab3 = st.tabs(["Infrastructure Analytics", "Identity Footprinting", "Entity Link Graph"])

# ---- TAB 1: Infrastructure Analytics -----------------------------------
with tab1:
    left, right = st.columns([1, 1.3])

    with left:
        st.markdown("<div class='section-eyebrow'>Hosting / ISP Breakdown</div>", unsafe_allow_html=True)
        isp_counts = domain_df["isp"].value_counts().reset_index()
        isp_counts.columns = ["isp", "count"]
        fig_bar = px.bar(isp_counts, x="count", y="isp", orientation="h",
                          color_discrete_sequence=["#F0A63A"])
        fig_bar.update_traces(marker_line_width=0)
        st.plotly_chart(style_fig(fig_bar), width='stretch')

    with right:
        st.markdown("<div class='section-eyebrow'>Resolved IP Geolocation</div>", unsafe_allow_html=True)
        fig_map = px.scatter_map(
            domain_df, lat="lat", lon="lon", hover_name="subdomain",
            hover_data={"ip_address": True, "isp": True, "lat": False, "lon": False},
            color_discrete_sequence=["#4FD9C9"], zoom=1,
        )
        fig_map.update_traces(marker=dict(size=12))
        fig_map.update_layout(map_style="carto-darkmatter")
        st.plotly_chart(style_fig(fig_map, height=380), width='stretch')

    st.markdown("<div class='section-eyebrow'>Subdomain Register</div>", unsafe_allow_html=True)
    show_df = domain_df.copy()
    show_df["mx_records"] = show_df["mx_records"].apply(lambda x: ", ".join(x))
    st.dataframe(
        show_df[["subdomain", "ip_address", "isp", "registrar", "mx_records", "discovered_at"]],
        width='stretch', hide_index=True,
    )

# ---- TAB 2: Identity Footprinting ---------------------------------------
with tab2:
    left, right = st.columns([1, 1])

    with left:
        st.markdown("<div class='section-eyebrow'>Platform Detection Matrix</div>", unsafe_allow_html=True)
        pf = user_df.sort_values("confidence", ascending=True)
        fig_pf = px.bar(pf, x="confidence", y="platform", orientation="h",
                         color="confidence", color_continuous_scale=["#223038", "#4FD9C9", "#F0A63A"])
        fig_pf.update_coloraxes(showscale=False)
        fig_pf.update_layout(xaxis_title="confidence score", yaxis_title="")
        st.plotly_chart(style_fig(fig_pf), width='stretch')

    with right:
        st.markdown("<div class='section-eyebrow'>Bio Keyword Trends</div>", unsafe_allow_html=True)
        kw_rows = []
        for _, r in user_df.iterrows():
            for kw in r["bio_keywords"]:
                kw_rows.append(kw)
        kw_df = pd.Series(kw_rows).value_counts().reset_index()
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
        st.plotly_chart(style_fig(fig_bubble), width='stretch')

    st.markdown("<div class='section-eyebrow'>Verified Profile Hits</div>", unsafe_allow_html=True)
    show_u = user_df.copy()
    show_u["bio_keywords"] = show_u["bio_keywords"].apply(lambda x: ", ".join(x))
    show_u["associated_email"] = show_u["associated_email"].fillna("— masked / not found —")
    st.dataframe(
        show_u[["platform", "profile_url", "associated_email", "confidence", "bio_keywords"]],
        width='stretch', hide_index=True,
    )

# ---- TAB 3: Entity Link Graph --------------------------------------------
with tab3:
    st.markdown("<div class='section-eyebrow'>Cross-Entity Correlation Topology</div>", unsafe_allow_html=True)
    physics_on = st.toggle("Enable physics engine", value=True)

    net = Network(height="520px", width="100%", bgcolor="#0A0D10", font_color="#C9D3D6", directed=False)
    net.add_node(domain_val, label=domain_val, color="#4FD9C9", shape="dot", size=26, title="Domain (root)")
    net.add_node(user_val, label=f"@{user_val}", color="#3AD65B", shape="dot", size=26, title="Username (root)")

    for _, r in domain_df.head(6).iterrows():
        net.add_node(r["subdomain"], color="#4FD9C9", shape="dot", size=14, title=r["ip_address"])
        net.add_node(r["ip_address"], color="#E8544B", shape="dot", size=10, title="Resolved IP")
        net.add_edge(domain_val, r["subdomain"])
        net.add_edge(r["subdomain"], r["ip_address"])

    for _, r in user_df.iterrows():
        net.add_node(r["platform"], color="#3AD65B", shape="dot", size=14, title=r["profile_url"])
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
    for _, r in rel_df.iterrows():
        conf = r["confidence_score"]
        cls = "high" if conf >= 80 else "med" if conf >= 55 else "low"
        st.markdown(
            f"`{r['source']}`  →  `{r['target']}`  &nbsp; "
            f"<span class='chip {cls}'>{r['relationship_type']} · {conf}%</span>",
            unsafe_allow_html=True,
        )