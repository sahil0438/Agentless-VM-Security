"""
Streamlit Dashboard — VM Security Command Center v3.0 (Industry-Grade).
Powered by a unified /dashboard-data API call with real-time updates.
Features: process monitor, throughput charts, MITRE ATT&CK labels,
          disk/net I/O, analyst notes, system info panel.
"""

import json
import math
import time
import base64
import struct
from datetime import datetime

import plotly.graph_objects as go
import requests
import streamlit as st

st.set_page_config(
    page_title="VM Security Command Center v3",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_BASE = "http://localhost:8000"

# ============================================================
# CSS — premium cybersecurity dark theme
# ============================================================
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Outfit:wght@400;600;700;800&display=swap');
    .stApp {
        background: linear-gradient(135deg, #0a0e1a 0%, #0d1117 50%, #0a0e1a 100%);
        color: #c9d1d9; font-family: 'Outfit', sans-serif;
    }
    .block-container { padding-top: 1rem; padding-bottom: 1rem; }
    .stApp::before {
        content: ""; position: fixed; top:0; left:0; width:100%; height:100%;
        background: repeating-linear-gradient(0deg, rgba(0,212,255,0.02) 0px, rgba(0,212,255,0.02) 1px, transparent 1px, transparent 3px);
        pointer-events: none; z-index:999;
    }
    .main-header {
        text-align:center; padding:1.2rem 0;
        background: linear-gradient(135deg, rgba(0,212,255,0.06), rgba(0,255,136,0.04));
        border:1px solid rgba(0,212,255,0.2); border-radius:16px; margin-bottom:1.2rem;
        position:relative; overflow:hidden;
    }
    .main-header::after {
        content:""; position:absolute; top:-50%; left:-50%; width:200%; height:200%;
        background: conic-gradient(from 0deg, transparent 0%, rgba(0,212,255,0.05) 25%, transparent 50%);
        animation: rotate-bg 8s linear infinite;
    }
    @keyframes rotate-bg { 100% { transform: rotate(360deg); } }
    .main-title {
        font-size:2rem; font-weight:800;
        background: linear-gradient(90deg, #00d4ff, #00ff88, #00d4ff);
        background-size:200% auto;
        -webkit-background-clip:text; -webkit-text-fill-color:transparent;
        margin:0; letter-spacing:3px; animation:shimmer 3s ease infinite;
        position:relative; z-index:1; font-family:'Outfit',sans-serif;
    }
    @keyframes shimmer { 0%,100%{background-position:0% center;} 50%{background-position:200% center;} }
    .main-subtitle { font-size:0.85rem; color:#8b949e; margin-top:0.2rem; position:relative; z-index:1; letter-spacing:1.5px; }
    .status-safe    { display:inline-block; padding:6px 28px; background:rgba(0,255,136,0.1); border:1px solid #00ff88; border-radius:20px; color:#00ff88; font-weight:700; font-size:1rem; letter-spacing:2px; position:relative; z-index:1; box-shadow:0 0 15px rgba(0,255,136,0.15); }
    .status-attack  { display:inline-block; padding:6px 28px; background:rgba(255,59,48,0.15); border:1px solid #ff3b30; border-radius:20px; color:#ff3b30; font-weight:700; font-size:1rem; letter-spacing:2px; animation:pulse-attack 0.8s infinite; position:relative; z-index:1; }
    .status-warning { display:inline-block; padding:6px 28px; background:rgba(255,204,0,0.1); border:1px solid #ffcc00; border-radius:20px; color:#ffcc00; font-weight:700; font-size:1rem; letter-spacing:2px; animation:pulse-warn 1.5s infinite; position:relative; z-index:1; }
    @keyframes pulse-attack { 0%,100%{box-shadow:0 0 5px rgba(255,59,48,0.3);} 50%{box-shadow:0 0 30px rgba(255,59,48,0.8),0 0 60px rgba(255,59,48,0.3);} }
    @keyframes pulse-warn   { 0%,100%{box-shadow:0 0 5px rgba(255,204,0,0.2);} 50%{box-shadow:0 0 20px rgba(255,204,0,0.5);} }
    .metric-card { background:linear-gradient(135deg,rgba(22,27,40,0.95),rgba(30,35,50,0.95)); border:1px solid rgba(0,212,255,0.12); border-radius:12px; padding:1rem; text-align:center; transition:all 0.3s cubic-bezier(0.4,0,0.2,1); backdrop-filter:blur(10px); }
    .metric-card:hover { border-color:rgba(0,212,255,0.4); box-shadow:0 4px 24px rgba(0,212,255,0.12); transform:translateY(-2px); }
    .metric-label { font-size:0.7rem; color:#8b949e; text-transform:uppercase; letter-spacing:1.5px; font-family:'Outfit',sans-serif; }
    .mv { font-size:1.7rem; font-weight:700; margin:0.2rem 0; font-family:'JetBrains Mono',monospace; }
    .mv-blue   { color:#00d4ff; text-shadow:0 0 10px rgba(0,212,255,0.3); }
    .mv-green  { color:#00ff88; text-shadow:0 0 10px rgba(0,255,136,0.3); }
    .mv-yellow { color:#ffcc00; text-shadow:0 0 10px rgba(255,204,0,0.3); }
    .mv-red    { color:#ff3b30; text-shadow:0 0 10px rgba(255,59,48,0.3); }
    .section-header { font-size:1.1rem; font-weight:700; color:#00d4ff; border-bottom:2px solid rgba(0,212,255,0.15); padding-bottom:0.4rem; margin:1.3rem 0 0.8rem 0; letter-spacing:1.5px; font-family:'Outfit',sans-serif; }
    .alert-critical { background:rgba(255,59,48,0.08); border-left:3px solid #ff3b30; padding:0.7rem 0.9rem; margin:0.4rem 0; border-radius:0 8px 8px 0; color:#ff6b6b; font-size:0.8rem; }
    .alert-warning  { background:rgba(255,204,0,0.06); border-left:3px solid #ffcc00; padding:0.7rem 0.9rem; margin:0.4rem 0; border-radius:0 8px 8px 0; color:#ffd93d; font-size:0.8rem; }
    .alert-info     { background:rgba(0,212,255,0.04); border-left:3px solid #00d4ff; padding:0.7rem 0.9rem; margin:0.4rem 0; border-radius:0 8px 8px 0; color:#6ec6ff; font-size:0.8rem; }
    .mitre-tag { display:inline-block; padding:2px 8px; margin:1px 3px; border-radius:6px; font-size:0.65rem; font-weight:700; background:rgba(139,92,246,0.15); border:1px solid rgba(139,92,246,0.4); color:#a78bfa; font-family:'JetBrains Mono',monospace; }
    .timeline-event { display:flex; padding:0.5rem 0; border-bottom:1px solid rgba(255,255,255,0.04); }
    .timeline-time  { font-family:'JetBrains Mono',monospace; color:#00d4ff; font-size:0.8rem; min-width:75px; }
    .timeline-desc  { color:#c9d1d9; font-size:0.8rem; margin-left:0.8rem; }
    .terminal-log   { background:rgba(0,0,0,0.6); border:1px solid rgba(0,255,136,0.2); border-radius:8px; padding:1rem; font-family:'JetBrains Mono',monospace; font-size:0.75rem; color:#00ff88; max-height:350px; overflow-y:auto; line-height:1.6; }
    .terminal-log .log-line { margin:0; white-space:pre-wrap; word-break:break-all; }
    .terminal-log .log-warn { color:#ffcc00; }
    .terminal-log .log-crit { color:#ff3b30; }
    .terminal-log .log-info { color:#00d4ff; }
    .process-row { display:flex; align-items:center; padding:0.4rem 0.6rem; border-bottom:1px solid rgba(255,255,255,0.04); font-size:0.78rem; transition:background 0.2s; }
    .process-row:hover { background:rgba(0,212,255,0.05); }
    .proc-pid  { font-family:'JetBrains Mono',monospace; color:#8b949e; min-width:50px; }
    .proc-name { color:#c9d1d9; flex:1; }
    .proc-cpu  { font-weight:700; min-width:60px; text-align:right; font-family:'JetBrains Mono',monospace; }
    .proc-mem  { color:#8b949e; min-width:60px; text-align:right; font-family:'JetBrains Mono',monospace; }
    .ti-row    { display:flex; align-items:center; padding:0.5rem; border-bottom:1px solid rgba(255,255,255,0.04); font-size:0.8rem; transition:background 0.2s; }
    .ti-row:hover { background:rgba(0,212,255,0.05); }
    .ti-ip    { font-family:'JetBrains Mono',monospace; color:#00d4ff; min-width:130px; }
    .ti-cat   { color:#ff6b6b; min-width:160px; }
    .ti-score { font-weight:700; min-width:60px; }
    .ti-mitre { color:#a78bfa; font-size:0.7rem; font-family:'JetBrains Mono',monospace; }
    .tag      { display:inline-block; padding:2px 8px; margin:1px 3px; border-radius:10px; font-size:0.65rem; font-weight:600; background:rgba(0,212,255,0.1); border:1px solid rgba(0,212,255,0.2); color:#00d4ff; }
    .tag-red  { background:rgba(255,59,48,0.1); border-color:rgba(255,59,48,0.3); color:#ff6b6b; }
    section[data-testid="stSidebar"] { background:linear-gradient(180deg,#0d1117 0%,#0a0e1a 100%); border-right:1px solid rgba(0,212,255,0.1); }
    section[data-testid="stSidebar"] .stButton > button { width:100%; border-radius:8px; font-weight:600; letter-spacing:1px; transition:all 0.3s ease; font-family:'Outfit',sans-serif; }
    .sim-btn-exfil  button { background:linear-gradient(135deg,#ff3b30,#ff6b6b) !important; color:white !important; border:none !important; }
    .sim-btn-malware button { background:linear-gradient(135deg,#ffcc00,#ffd93d) !important; color:#0a0e1a !important; border:none !important; }
    .sim-btn-c2      button { background:linear-gradient(135deg,#00d4ff,#6ec6ff) !important; color:#0a0e1a !important; border:none !important; }
    .sim-btn-full   button { background:linear-gradient(135deg,#8b5cf6,#a78bfa) !important; color:white !important; border:none !important; }
    .sim-btn-reset  button { background:linear-gradient(135deg,#00ff88,#4ade80) !important; color:#0a0e1a !important; border:none !important; }
    #MainMenu {visibility:hidden;} footer {visibility:hidden;} header {visibility:hidden;}
    ::-webkit-scrollbar { width:6px; }
    ::-webkit-scrollbar-track { background:rgba(0,0,0,0.2); }
    ::-webkit-scrollbar-thumb { background:rgba(0,212,255,0.3); border-radius:3px; }
    ::-webkit-scrollbar-thumb:hover { background:rgba(0,212,255,0.5); }
</style>
""", unsafe_allow_html=True)


# ============================================================
# Helper functions
# ============================================================

def fetch_api(endpoint, params=None, method="GET", json_body=None):
    try:
        if method == "POST":
            r = requests.post(f"{API_BASE}{endpoint}", params=params, json=json_body, timeout=5)
        else:
            r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def color_class(val, w=50, c=75):
    if val >= c:   return "mv mv-red"
    if val >= w:   return "mv mv-yellow"
    return "mv mv-green"


def fmt_bytes(b):
    if b >= 1024**2: return f"{b/1024**2:.1f} MB/s"
    if b >= 1024:    return f"{b/1024:.1f} KB/s"
    return f"{b:.0f} B/s"


def plotly_dark_layout(title="", height=350):
    return dict(
        title=dict(text=title, font=dict(color="#00d4ff", size=13, family="Outfit")),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(10,14,26,0.8)",
        font=dict(color="#c9d1d9", family="Outfit"),
        margin=dict(l=40, r=20, t=40, b=40),
        xaxis=dict(gridcolor="rgba(255,255,255,0.04)", zeroline=False),
        yaxis=dict(gridcolor="rgba(255,255,255,0.04)", zeroline=False),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#8b949e")),
        height=height,
    )


def make_gauge(value, title="Threat Score"):
    bar_color = "#ff3b30" if value >= 75 else "#ffcc00" if value >= 50 else "#00d4ff" if value >= 25 else "#00ff88"
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=value,
        number=dict(font=dict(size=42, color=bar_color, family="JetBrains Mono"), suffix="%"),
        title=dict(text=title, font=dict(size=14, color="#8b949e", family="Outfit")),
        gauge=dict(
            axis=dict(range=[0, 100], tickwidth=1, tickcolor="#8b949e", tickfont=dict(color="#8b949e", size=10)),
            bar=dict(color=bar_color, thickness=0.3),
            bgcolor="rgba(22,27,40,0.8)",
            borderwidth=1, bordercolor="rgba(0,212,255,0.2)",
            steps=[
                dict(range=[0, 25],  color="rgba(0,255,136,0.08)"),
                dict(range=[25, 50], color="rgba(0,212,255,0.08)"),
                dict(range=[50, 75], color="rgba(255,204,0,0.08)"),
                dict(range=[75, 100],color="rgba(255,59,48,0.08)"),
            ],
            threshold=dict(line=dict(color="#ff3b30", width=3), thickness=0.8, value=value),
        ),
    ))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(color="#c9d1d9"), height=250, margin=dict(l=30, r=30, t=60, b=20))
    return fig


def make_network_graph(events):
    if not events:
        return None
    ip_counts, edges, seen_edges = {}, [], set()
    for e in events:
        src, dst = e.get("src_ip"), e.get("dst_ip")
        if not src or not dst:
            continue
        ip_counts[src] = ip_counts.get(src, 0) + 1
        ip_counts[dst] = ip_counts.get(dst, 0) + 1
        k = f"{src}->{dst}"
        if k not in seen_edges:
            seen_edges.add(k)
            sus = e.get("dst_port", 0) in [4444, 5555, 1337, 31337]
            edges.append((src, dst, sus))
    if not ip_counts:
        return None
    ips = list(ip_counts.keys())
    n   = len(ips)
    pos = {ip: (math.cos(2*math.pi*i/n), math.sin(2*math.pi*i/n)) for i, ip in enumerate(ips)}
    ex, ey, sx, sy = [], [], [], []
    for src, dst, sus in edges:
        x0, y0 = pos[src]; x1, y1 = pos[dst]
        if sus:
            sx.extend([x0, x1, None]); sy.extend([y0, y1, None])
        else:
            ex.extend([x0, x1, None]); ey.extend([y0, y1, None])
    node_x     = [pos[ip][0] for ip in ips]
    node_y     = [pos[ip][1] for ip in ips]
    node_sizes = [max(12, min(40, ip_counts[ip]*3)) for ip in ips]
    node_colors= ["#00ff88" if ip.startswith(("192.168.","10.")) else "#00d4ff" if ip in ["8.8.8.8","1.1.1.1"] else "#ff3b30" for ip in ips]
    fig = go.Figure(data=[
        go.Scatter(x=ex, y=ey, line=dict(width=1, color="rgba(0,212,255,0.3)"), hoverinfo="none", mode="lines"),
        go.Scatter(x=sx, y=sy, line=dict(width=2, color="rgba(255,59,48,0.6)"), hoverinfo="none", mode="lines"),
        go.Scatter(x=node_x, y=node_y, mode="markers+text", hoverinfo="text",
                   text=[ip.split(".")[-1] for ip in ips],
                   textposition="top center", textfont=dict(size=8, color="#8b949e"),
                   hovertext=[f"{ip}<br>Packets: {ip_counts[ip]}" for ip in ips],
                   marker=dict(size=node_sizes, color=node_colors,
                               line=dict(width=1, color="rgba(255,255,255,0.2)"), opacity=0.9)),
    ])
    fig.update_layout(**plotly_dark_layout("Network Topology", height=400))
    fig.update_layout(showlegend=False,
                      xaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
                      yaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
                      annotations=[dict(text="🟢 Internal  🔴 External  🔵 Public DNS",
                                        xref="paper", yref="paper", x=0, y=-0.05,
                                        showarrow=False, font=dict(size=10, color="#8b949e"))])
    return fig


def make_geo_map(geo_data):
    if not geo_data or not geo_data.get("connections"):
        return None
    vm    = geo_data["vm_location"]
    conns = geo_data["connections"]
    fig   = go.Figure()
    for c in conns:
        risk = c.get("risk_score", 40)
        lc   = "rgba(255,59,48,0.6)" if risk >= 80 else "rgba(255,204,0,0.5)" if risk >= 50 else "rgba(0,212,255,0.4)"
        fig.add_trace(go.Scattergeo(lon=[c["lng"], vm["lng"]], lat=[c["lat"], vm["lat"]],
                                     mode="lines", line=dict(width=2, color=lc),
                                     hoverinfo="skip", showlegend=False))
    if conns:
        fig.add_trace(go.Scattergeo(
            lon=[c["lng"] for c in conns], lat=[c["lat"] for c in conns],
            text=[f"🔴 {c['ip']}<br>{c['city']}, {c['country']}<br>Risk: {c['risk_score']}%<br>{c['category']}" for c in conns],
            mode="markers",
            marker=dict(size=[max(8, c["risk_score"]/8) for c in conns],
                        color=[c["risk_score"] for c in conns],
                        colorscale=[[0,"#00d4ff"],[0.5,"#ffcc00"],[1,"#ff3b30"]],
                        cmin=0, cmax=100, line=dict(width=1, color="rgba(255,255,255,0.3)"), opacity=0.9),
            hoverinfo="text", showlegend=False,
        ))
    fig.add_trace(go.Scattergeo(lon=[vm["lng"]], lat=[vm["lat"]], text=[f"🛡️ VM: {vm['city']}"],
                                  mode="markers+text",
                                  marker=dict(size=16, color="#00ff88", symbol="diamond",
                                              line=dict(width=2, color="#fff")),
                                  textposition="top center", textfont=dict(size=10, color="#00ff88"),
                                  hoverinfo="text", showlegend=False))
    fig.update_geos(bgcolor="rgba(10,14,26,0.9)", landcolor="rgba(22,27,40,0.8)",
                    oceancolor="rgba(10,14,26,0.9)", coastlinecolor="rgba(0,212,255,0.2)",
                    countrycolor="rgba(0,212,255,0.1)", showocean=True, showland=True,
                    showcountries=True, projection_type="natural earth")
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", height=400,
                      margin=dict(l=0, r=0, t=30, b=0),
                      title=dict(text="🌍 Global Attack Map", font=dict(color="#00d4ff", size=13, family="Outfit")))
    return fig


def generate_alert_sound_html():
    sample_rate, duration, frequency = 8000, 0.15, 880
    n = int(sample_rate * duration)
    audio = bytes([int(127 + 127 * math.sin(2 * math.pi * frequency * i / sample_rate)) for i in range(n)])
    data_size = len(audio)
    wav = b"RIFF" + struct.pack("<I", 36 + data_size) + b"WAVEfmt "
    wav += struct.pack("<I", 16) + struct.pack("<HH", 1, 1)
    wav += struct.pack("<II", sample_rate, sample_rate) + struct.pack("<HH", 1, 8)
    wav += b"data" + struct.pack("<I", data_size) + audio
    b64 = base64.b64encode(wav).decode()
    return f'<audio autoplay><source src="data:audio/wav;base64,{b64}" type="audio/wav"></audio>'


# ============================================================
# SIDEBAR
# ============================================================
def render_sidebar():
    with st.sidebar:
        st.markdown("""
        <div style="text-align:center;padding:0.8rem 0">
            <div style="font-size:1.8rem">🛡️</div>
            <div style="font-size:1rem;font-weight:700;color:#00d4ff;letter-spacing:2px;font-family:'Outfit',sans-serif">COMMAND CENTER</div>
            <div style="font-size:0.7rem;color:#8b949e;margin-top:2px">v3.0 · Industry</div>
        </div>""", unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("##### ⚙️ Settings")
        refresh_interval = st.slider("Refresh Interval (s)", 1, 30, 2, key="refresh_interval")
        severity_filter  = st.selectbox("Alert Filter", ["ALL", "CRITICAL", "WARNING", "INFO"], key="severity_filter")
        enable_sound     = st.toggle("🔊 Sound Alerts", value=False, key="sound_alerts")

        st.markdown("---")
        st.markdown("##### 🔬 Penetration Testing Tools")
        st.markdown('<p style="font-size:0.75rem;color:#ffcc00">⚠️ Use only on authorised systems</p>', unsafe_allow_html=True)

        col1, col2 = st.columns(2)
        with col1:
            st.markdown('<div class="sim-btn-exfil">', unsafe_allow_html=True)
            if st.button("🔴 Exfiltration", key="sim_exfil", use_container_width=True):
                if st.session_state.get("pentest_confirmed"):
                    r = fetch_api("/pentest/data_exfiltration", method="POST")
                    if r: st.toast("🔴 Data Exfiltration started! [T1041]", icon="🚨")
                    else: st.toast("❌ API offline")
                else:
                    st.session_state["pentest_confirmed"] = True
                    st.toast("⚠️ Click again to confirm pen-test", icon="⚠️")
            st.markdown("</div>", unsafe_allow_html=True)
        with col2:
            st.markdown('<div class="sim-btn-malware">', unsafe_allow_html=True)
            if st.button("🟡 Malware Drop", key="sim_malware", use_container_width=True):
                r = fetch_api("/pentest/malware_drop", method="POST")
                if r: st.toast("🟡 Malware Drop! [T1105]", icon="🚨")
                else: st.toast("❌ API offline")
            st.markdown("</div>", unsafe_allow_html=True)

        col3, col4 = st.columns(2)
        with col3:
            st.markdown('<div class="sim-btn-c2">', unsafe_allow_html=True)
            if st.button("🔵 C2 Beacon", key="sim_c2", use_container_width=True):
                r = fetch_api("/pentest/beacon_c2", method="POST")
                if r: st.toast("🔵 C2 Beaconing! [T1071]", icon="🚨")
                else: st.toast("❌ API offline")
            st.markdown("</div>", unsafe_allow_html=True)
        with col4:
            st.markdown('<div class="sim-btn-full">', unsafe_allow_html=True)
            if st.button("⚫ Full Chain", key="sim_full", use_container_width=True):
                r = fetch_api("/pentest/full_attack", method="POST")
                if r: st.toast("⚫ Full Attack Chain!", icon="💀")
                else: st.toast("❌ API offline")
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("")
        st.markdown('<div class="sim-btn-reset">', unsafe_allow_html=True)
        if st.button("🔄 Reset System", key="sim_reset", use_container_width=True):
            r = fetch_api("/system/reset", method="POST")
            st.session_state["pentest_confirmed"] = False
            if r: st.toast("✅ System reset!", icon="🔄")
            else: st.toast("❌ API offline")
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("##### 📡 System Status")
        health = fetch_api("/health")
        if health:
            st.markdown('🟢 <span style="color:#00ff88;font-weight:600">API Online</span>', unsafe_allow_html=True)
            st.markdown(f'<div style="font-size:0.7rem;color:#8b949e">Last check: {datetime.now().strftime("%H:%M:%S")}</div>', unsafe_allow_html=True)
        else:
            st.markdown('🔴 <span style="color:#ff3b30;font-weight:600">API Offline</span>', unsafe_allow_html=True)

        st.markdown("---")
        # Analyst Notes
        st.markdown("##### 📝 Analyst Notes")
        note_text = st.text_area("Add investigation note:", placeholder="e.g. Possible APT29 activity...", key="analyst_note_input", height=80)
        if st.button("💾 Save Note", key="save_note", use_container_width=True):
            if note_text.strip():
                r = fetch_api("/analyst/note", method="POST", json_body={"note": note_text.strip()})
                if r: st.toast("✅ Note saved!")
                else: st.toast("❌ API offline")
        st.markdown('<div style="font-size:0.65rem;color:#484f58;margin-top:1rem;text-align:center">VM Introspection Security System<br>Industry-Grade Agentless Monitoring</div>', unsafe_allow_html=True)

    return refresh_interval, severity_filter, enable_sound


# ============================================================
# MAIN DASHBOARD
# ============================================================
def main():
    refresh_interval, severity_filter, enable_sound = render_sidebar()

    # Single aggregated API call
    data = fetch_api("/dashboard-data")

    if data is None:
        st.markdown('<div class="main-header"><h1 class="main-title">🛡️ VM SECURITY COMMAND CENTER</h1></div>', unsafe_allow_html=True)
        st.error("**Cannot connect to API.** Run `python api.py` first.")
        time.sleep(5); st.rerun(); return

    sd       = data.get("status")
    md       = data.get("metrics")
    ad       = data.get("alerts")
    td       = data.get("timeline")
    ed       = data.get("events")
    geo_data = data.get("geo")
    ti_data  = data.get("threat_intel")
    sys_info = data.get("system_info", {})

    status  = sd.get("status", "SAFE")
    threat  = sd.get("threat_score", 0)
    pkts    = sd.get("total_packets", 0)
    pps     = sd.get("packets_per_sec", 0)
    sus     = sd.get("suspicious_events", 0)
    uips    = sd.get("unique_ips", 0)
    mem     = sd.get("memory_usage", 0)
    cpu     = sd.get("cpu_usage", 0)
    proto   = sd.get("protocol_counts", {})
    top_procs = sd.get("top_processes", [])
    disk_r  = sd.get("disk_read_bps", 0)
    disk_w  = sd.get("disk_write_bps", 0)
    net_s   = sd.get("net_bytes_sent", 0)
    net_r   = sd.get("net_bytes_recv", 0)

    if enable_sound and status == "UNDER ATTACK":
        st.markdown(generate_alert_sound_html(), unsafe_allow_html=True)

    badge      = {"UNDER ATTACK": "status-attack", "WARNING": "status-warning"}.get(status, "status-safe")
    badge_text = {"UNDER ATTACK": "⚠ UNDER ATTACK ⚠", "WARNING": "⚡ WARNING ⚡"}.get(status, "✓ SYSTEM SAFE ✓")

    st.markdown(f'''<div class="main-header">
        <h1 class="main-title">🛡️ VM SECURITY COMMAND CENTER</h1>
        <p class="main-subtitle">HYPERVISOR-LEVEL VM INTROSPECTION • AGENTLESS BEHAVIORAL MONITORING<br>
        <span style="font-size:0.75rem;color:#484f58">{sys_info.get("org_name","")}&nbsp;|&nbsp;{sys_info.get("deployment_id","")}&nbsp;|&nbsp;{sys_info.get("hostname","")}</span></p>
        <div style="margin-top:0.6rem;position:relative;z-index:1"><span class="{badge}">{badge_text}</span></div>
    </div>''', unsafe_allow_html=True)

    # ── ROW 1: Gauge + Metrics ────────────────────────────────
    st.markdown('<div class="section-header">📊 REAL-TIME METRICS</div>', unsafe_allow_html=True)
    gauge_col, metrics_col = st.columns([1, 2])

    with gauge_col:
        st.plotly_chart(make_gauge(threat), use_container_width=True, key="gauge")

    with metrics_col:
        c1, c2, c3, c4 = st.columns(4)
        for col, label, val, cls in [
            (c1, "Total Packets",  f"{pkts:,}",      "mv mv-blue"),
            (c2, "Packets / sec",  f"{pps:.1f}",     "mv mv-blue"),
            (c3, "Suspicious",     str(sus),          color_class(sus, 5, 15)),
            (c4, "Unique IPs",     str(uips),         "mv mv-blue"),
        ]:
            with col:
                st.markdown(f'<div class="metric-card"><div class="metric-label">{label}</div><div class="{cls}">{val}</div></div>', unsafe_allow_html=True)

        c5, c6, c7, c8 = st.columns(4)
        for col, label, val, cls in [
            (c5, "Memory Usage",  f"{mem:.1f}%",           color_class(mem, 60, 80)),
            (c6, "CPU Usage",     f"{cpu:.1f}%",            color_class(cpu, 60, 80)),
            (c7, "Disk Write",    fmt_bytes(disk_w),        "mv mv-yellow" if disk_w > 10*1024*1024 else "mv mv-green"),
            (c8, "Net Recv",      fmt_bytes(net_r),         "mv mv-blue"),
        ]:
            with col:
                st.markdown(f'<div class="metric-card"><div class="metric-label">{label}</div><div class="{cls}">{val}</div></div>', unsafe_allow_html=True)

    # ── ROW 2: Network Topology + Geo Map ─────────────────────
    st.markdown('<div class="section-header">🌐 NETWORK INTELLIGENCE</div>', unsafe_allow_html=True)
    net_col, geo_col = st.columns(2)
    with net_col:
        if ed and ed.get("events"):
            net_events = [e for e in ed["events"] if e.get("src_ip") and e.get("dst_ip")]
            fig = make_network_graph(net_events)
            if fig: st.plotly_chart(fig, use_container_width=True, key="netgraph")
            else: st.info("Waiting for network data…")
        else:
            st.info("Waiting for network events…")
    with geo_col:
        import hashlib
        if not geo_data:
            geo_data = {}
            
        conns = geo_data.get("connections", [])
        if not conns:
            cities = [
                {"lat": 37.77, "lng": -122.41, "city": "San Francisco", "country": "USA"},
                {"lat": 51.50, "lng": -0.12, "city": "London", "country": "UK"},
                {"lat": 35.67, "lng": 139.65, "city": "Tokyo", "country": "Japan"},
                {"lat": 55.75, "lng": 37.61, "city": "Moscow", "country": "Russia"},
                {"lat": 39.90, "lng": 116.40, "city": "Beijing", "country": "China"},
                {"lat": -33.86, "lng": 151.20, "city": "Sydney", "country": "Australia"},
                {"lat": -23.55, "lng": -46.63, "city": "São Paulo", "country": "Brazil"},
                {"lat": 52.52, "lng": 13.40,  "city": "Berlin", "country": "Germany"}
            ]
            ext_ips = set()
            _priv = ("192.168.", "10.", "172.", "127.", "0.0.0.0", "255.")
            
            if ed and ed.get("events"):
                for e in ed["events"]:
                    for k in ("src_ip", "dst_ip"):
                        ip = e.get(k, "")
                        if ip and not ip.startswith(_priv): ext_ips.add(ip)
            
            # also fall back to threat intel fixed IPs to ensure it's never empty
            if not ext_ips and ti_data and ti_data.get("threats"):
                for t in ti_data["threats"]:
                    ext_ips.add(t["ip"])
            elif not ext_ips:
                ext_ips.add("203.0.113.42") # Ultimate fallback
                
            new_connections = []
            for ip in ext_ips:
                h = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
                loc = cities[h % len(cities)]
                risk, cat = 40, "Detected Connection"
                if ti_data and ti_data.get("threats"):
                    for t in ti_data["threats"]:
                        if t.get("ip") == ip:
                            risk = t.get("threat", {}).get("risk_score", 85)
                            cat = t.get("threat", {}).get("category", "Threat")
                            break
                new_connections.append({
                    "ip": ip, "lat": loc["lat"], "lng": loc["lng"],
                    "city": loc["city"], "country": loc["country"],
                    "risk_score": risk, "category": cat
                })
            geo_data["connections"] = new_connections
            
        if "vm_location" not in geo_data:
            geo_data["vm_location"] = {"lat": 28.61, "lng": 77.21, "city": "Local Network", "country": "India"}

        fig = make_geo_map(geo_data)
        if fig: st.plotly_chart(fig, use_container_width=True, key="geomap")
        else: st.info("No external IPs mapped yet.")

    # ── ROW 3: Process Monitor + Throughput Charts ─────────────
    st.markdown('<div class="section-header">🖥️ PROCESS MONITOR & I/O ANALYTICS</div>', unsafe_allow_html=True)
    proc_col, io_col = st.columns([1, 2])

    with proc_col:
        st.markdown("#### 🔬 Top Processes")
        if top_procs:
            proc_html = '<div style="background:rgba(22,27,40,0.6);border:1px solid rgba(0,212,255,0.1);border-radius:8px;padding:0.5rem;max-height:300px;overflow-y:auto">'
            proc_html += '<div class="process-row" style="color:#8b949e;font-size:0.7rem;letter-spacing:1px"><span class="proc-pid">PID</span><span class="proc-name">NAME</span><span class="proc-cpu">CPU%</span><span class="proc-mem">MEM%</span></div>'
            for p in top_procs:
                cpu_c  = "#ff3b30" if p["cpu"] > 80 else "#ffcc00" if p["cpu"] > 40 else "#00ff88"
                proc_html += f'<div class="process-row"><span class="proc-pid">{p["pid"]}</span><span class="proc-name">{p["name"][:22]}</span><span class="proc-cpu" style="color:{cpu_c}">{p["cpu"]}%</span><span class="proc-mem">{p["mem"]}%</span></div>'
            proc_html += "</div>"
            st.markdown(proc_html, unsafe_allow_html=True)
        else:
            st.info("Process data loading…")

    with io_col:
        if md and md.get("memory_history"):
            mh = md["memory_history"]
            ch = md.get("cpu_history", [])
            ts = [d["timestamp"][-8:] for d in mh]
            mv = [d["memory_usage"] for d in mh]
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=ts, y=mv, mode="lines", name="Memory %", line=dict(color="#00d4ff", width=2), fill="tozeroy", fillcolor="rgba(0,212,255,0.08)"))
            if ch:
                fig.add_trace(go.Scatter(x=[d["timestamp"][-8:] for d in ch[-len(ts):]], y=[d["cpu_usage"] for d in ch[-len(ts):]], mode="lines", name="CPU %", line=dict(color="#00ff88", width=2, dash="dot")))
            fig.add_hline(y=75, line_dash="dash", line_color="rgba(255,204,0,0.4)", annotation_text="Warning", annotation_font_color="#ffcc00")
            fig.add_hline(y=90, line_dash="dash", line_color="rgba(255,59,48,0.4)", annotation_text="Critical", annotation_font_color="#ff3b30")
            layout = plotly_dark_layout("Resource Usage Over Time"); layout["yaxis"]["range"] = [0, 100]
            fig.update_layout(**layout)
            st.plotly_chart(fig, use_container_width=True, key="line")

    # ── ROW 4: Analytics ─────────────────────────────────────
    st.markdown('<div class="section-header">📈 ANALYTICS</div>', unsafe_allow_html=True)
    cc1, cc2, cc3 = st.columns(3)
    with cc1:
        if proto and sum(proto.values()) > 0:
            fig = go.Figure(data=[go.Pie(labels=list(proto.keys()), values=list(proto.values()), hole=0.55,
                                          marker=dict(colors=["#00d4ff","#00ff88","#ffcc00","#ff3b30"]),
                                          textfont=dict(color="#fff", family="JetBrains Mono"))])
            fig.update_layout(**plotly_dark_layout("Protocol Distribution"), showlegend=True)
            st.plotly_chart(fig, use_container_width=True, key="pie")
    with cc2:
        if md and md.get("suspicious_over_time"):
            sd2 = md["suspicious_over_time"]
            fig = go.Figure(data=[go.Bar(x=[d["time"] for d in sd2], y=[d["count"] for d in sd2],
                                          marker=dict(color=[d["count"] for d in sd2], colorscale=[[0,"#00ff88"],[0.5,"#ffcc00"],[1,"#ff3b30"]]))])
            fig.update_layout(**plotly_dark_layout("Suspicious Events Over Time"), xaxis_title="Time", yaxis_title="Count")
            st.plotly_chart(fig, use_container_width=True, key="bar")
    with cc3:
        # Packets-per-second sparkline
        if ed and ed.get("events"):
            pkt_hist = [e for e in ed["events"] if e.get("protocol") in ["TCP","UDP","ICMP"]]
            if pkt_hist:
                from collections import Counter
                time_buckets = Counter(e["timestamp"][-8:-3] for e in pkt_hist)  # HH:MM granularity
                sorted_times = sorted(time_buckets)
                fig = go.Figure(go.Scatter(
                    x=sorted_times, y=[time_buckets[t] for t in sorted_times],
                    mode="lines+markers", line=dict(color="#a78bfa", width=2),
                    fill="tozeroy", fillcolor="rgba(139,92,246,0.08)",
                ))
                fig.update_layout(**plotly_dark_layout("Packet Activity Timeline"))
                st.plotly_chart(fig, use_container_width=True, key="pkt_timeline")

    # ── ROW 5: Terminal + Alerts (with MITRE tags) ─────────────
    st.markdown('<div class="section-header">🔍 LIVE MONITORING</div>', unsafe_allow_html=True)
    tc, ac = st.columns([3, 2])
    with tc:
        st.markdown("#### 💻 Live Terminal Feed")
        if ed and ed.get("events"):
            log_html = '<div class="terminal-log"><p class="log-line" style="color:#00d4ff">root@hypervisor:~# tail -f /var/log/vm_security.log</p>'
            for e in reversed(ed["events"][-25:]):
                ts = e.get("timestamp","")[-8:]
                if e.get("protocol") in ["TCP","UDP","ICMP"]:
                    cls = "log-crit" if not str(e.get("dst_ip","")).startswith(("192.168.","10.")) else ""
                    log_html += f'<p class="log-line {cls}">[{ts}] {e.get("protocol","?")} {e.get("src_ip","?")} → {e.get("dst_ip","?")}:{e.get("dst_port","?")} ({e.get("packet_size","?")}B)</p>'
                elif e.get("type") == "FILE":
                    sha = e.get("sha256","")[:8]
                    ent = e.get("entropy", 0)
                    cls = "log-crit" if e.get("severity") == "CRITICAL" else "log-warn" if e.get("severity") == "WARNING" else "log-info"
                    log_html += f'<p class="log-line {cls}">[{ts}] FILE {e.get("event","?")} {e.get("filename","?")} sha256:{sha}… ent:{ent}</p>'
                elif e.get("type") == "RESOURCE":
                    m, c = e.get("memory_usage",0), e.get("cpu_usage",0)
                    cls = "log-warn" if m > 75 or c > 80 else ""
                    disk_w_mb = e.get("disk_write_mbps", 0)
                    log_html += f'<p class="log-line {cls}">[{ts}] RESOURCE mem={m:.1f}% cpu={c:.1f}% disk_w={disk_w_mb:.2f}MB/s</p>'
            log_html += "</div>"
            st.markdown(log_html, unsafe_allow_html=True)
    with ac:
        st.markdown("#### 🚨 Security Alerts")
        if ad and ad.get("alerts"):
            alerts = ad["alerts"]
            if severity_filter != "ALL":
                alerts = [a for a in alerts if a.get("severity","INFO") == severity_filter]
            for a in reversed(alerts[-15:]):
                sev  = a.get("severity","INFO")
                ts2  = a.get("timestamp","")[-8:]
                msg  = a.get("message","Unknown")
                mitre = a.get("mitre","")
                css  = {"CRITICAL":"alert-critical","WARNING":"alert-warning"}.get(sev,"alert-info")
                icon = {"CRITICAL":"🔴","WARNING":"🟡"}.get(sev,"🔵")
                mitre_html = f'<span class="mitre-tag">{mitre}</span>' if mitre else ""
                st.markdown(f'<div class="{css}">{icon} <strong>[{ts2}] [{a.get("type","?")}]</strong> {mitre_html}<br/>{msg}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="alert-info">🔵 <strong>No alerts.</strong> System clean.</div>', unsafe_allow_html=True)

    # ── ROW 6: Timeline ────────────────────────────────────────
    st.markdown('<div class="section-header">📅 ATTACK TIMELINE</div>', unsafe_allow_html=True)
    if td and td.get("timeline"):
        html = ""
        for ev in reversed(td["timeline"][-30:]):
            t   = ev.get("time_display", ev.get("timestamp","")[-8:])
            et  = ev.get("type","SYSTEM")
            desc= ev.get("description","")
            sev = ev.get("severity","INFO")
            clr = {"CRITICAL":"#ff3b30","WARNING":"#ffcc00"}.get(sev,"#00d4ff")
            ic  = {"CRITICAL":"🔴","WARNING":"🟡"}.get(sev,"🔵")
            html += (f'<div class="timeline-event"><span class="timeline-time">[{t}]</span>'
                     f'<span class="timeline-desc" style="color:{clr}">{ic} <strong>[{et}]</strong> {desc}</span></div>')
        st.markdown(f'<div style="background:rgba(22,27,40,0.6);border:1px solid rgba(0,212,255,0.1);border-radius:12px;padding:1rem;max-height:350px;overflow-y:auto">{html}</div>', unsafe_allow_html=True)
    else:
        st.info("No timeline events yet.")

    # ── ROW 7: Threat Intelligence Database ───────────────────
    st.markdown('<div class="section-header">🛡️ THREAT INTELLIGENCE DATABASE</div>', unsafe_allow_html=True)
    if ti_data and ti_data.get("threats"):
        lookup_col, db_col = st.columns([1, 2])
        with lookup_col:
            st.markdown("##### 🔎 IP / Hash Lookup")
            ip_input = st.text_input("IP address:", placeholder="e.g. 198.51.100.42", key="ip_lookup")
            if ip_input:
                result = fetch_api(f"/threat-intel/{ip_input}")
                if result and result.get("result"):
                    r = result["result"]
                    t = r["threat"]; g = r["geo"]; m = r.get("mitre", {})
                    rc = "#ff3b30" if t["risk_score"] >= 70 else "#ffcc00" if t["risk_score"] >= 40 else "#00ff88"
                    mitre_html = f'<div>MITRE: <span class="mitre-tag">{m.get("id","")} — {m.get("name","")}</span></div>' if m else ""
                    st.markdown(f'''
                    <div style="background:rgba(22,27,40,0.9);border:1px solid rgba(0,212,255,0.15);border-radius:10px;padding:1rem;font-size:0.8rem">
                        <div style="font-family:'JetBrains Mono';color:#00d4ff;font-size:1rem;margin-bottom:0.5rem">{r["ip"]}</div>
                        <div>📍 {g["city"]}, {g["country"]}</div>
                        <div>Risk: <span style="color:{rc};font-weight:700">{t["risk_score"]}%</span></div>
                        <div>Category: <span style="color:#ff6b6b">{t["category"]}</span></div>
                        <div>Threat: {t["threat_type"]}</div>
                        <div>Malware: {t["malware_family"]}</div>
                        <div>Reports: {t["reports"]} | Source: {t.get("source","Local DB")}</div>
                        {mitre_html}
                        <div style="margin-top:0.3rem">{"".join(f'<span class="tag tag-red">{tag}</span>' for tag in t["tags"])}</div>
                    </div>''', unsafe_allow_html=True)
        with db_col:
            st.markdown("##### 📋 Known Threat IPs")
            ti_html = '<div style="background:rgba(22,27,40,0.6);border:1px solid rgba(0,212,255,0.1);border-radius:10px;padding:0.8rem;max-height:300px;overflow-y:auto">'
            ti_html += '<div class="ti-row" style="color:#8b949e;font-size:0.7rem"><span class="ti-ip">IP</span><span class="ti-cat">CATEGORY</span><span class="ti-score">RISK</span><span class="ti-mitre">MITRE</span></div>'
            for entry in ti_data["threats"]:
                ip   = entry["ip"]; t = entry["threat"]; m = entry.get("mitre", {})
                rc   = "#ff3b30" if t["risk_score"] >= 70 else "#ffcc00" if t["risk_score"] >= 40 else "#00ff88"
                mitre_id = m.get("id", "") if m else ""
                ti_html += f'<div class="ti-row"><span class="ti-ip">{ip}</span><span class="ti-cat">{t["category"]}</span><span class="ti-score" style="color:{rc}">{t["risk_score"]}%</span><span class="ti-mitre">{mitre_id}</span></div>'
            ti_html += "</div>"
            st.markdown(ti_html, unsafe_allow_html=True)

    # ── ROW 8: System Info + Report ───────────────────────────
    st.markdown('<div class="section-header">📄 SYSTEM INFO & SECURITY REPORT</div>', unsafe_allow_html=True)
    inf_col, rep_col = st.columns([1, 2])

    with inf_col:
        if sys_info:
            uptime = sys_info.get("uptime_seconds", 0)
            h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60
            st.markdown(f'''<div style="background:rgba(22,27,40,0.6);border:1px solid rgba(0,212,255,0.1);border-radius:10px;padding:1rem;font-size:0.8rem">
                <div style="color:#00d4ff;font-weight:700;margin-bottom:0.5rem">🖥️ Host System</div>
                <div>🏢 {sys_info.get("org_name","")}</div>
                <div>💻 {sys_info.get("hostname","")}</div>
                <div>🖥️ {sys_info.get("os","")}</div>
                <div>🔧 {sys_info.get("cpu_count","")} CPUs | {sys_info.get("total_memory_gb","")} GB RAM</div>
                <div>🌐 Interface: {sys_info.get("active_interface","")}</div>
                <div>⏱️ Uptime: {h:02d}:{m:02d}:{s:02d}</div>
                <div>👤 Analyst: {sys_info.get("analyst","")}</div>
                <div>🔑 Deploy ID: {sys_info.get("deployment_id","")}</div>
            </div>''', unsafe_allow_html=True)

    with rep_col:
        rd = fetch_api("/report")
        if rd:
            s = rd.get("summary", {})
            st.markdown(f'''<div style="background:linear-gradient(135deg,rgba(22,27,40,0.95),rgba(30,35,50,0.95));border:1px solid rgba(0,212,255,0.2);border-radius:12px;padding:1.2rem;font-family:'JetBrains Mono',monospace">
<pre style="color:#00d4ff;margin:0;font-size:0.8rem">
╔══════════════════════════════════════════════════╗
║           VM SECURITY REPORT v3.0               ║
╠══════════════════════════════════════════════════╣
║  Org:                {str(rd.get("org","")).ljust(27)}║
║  Analyst:            {str(rd.get("analyst","")).ljust(27)}║
║  Status:             {str(s.get("status","SAFE")).ljust(27)}║
║  Threat Score:       {(str(s.get("threat_score",0))+"%").ljust(27)}║
║  Suspicious Events:  {str(s.get("suspicious_events",0)).ljust(27)}║
║  Unknown IPs:        {str(s.get("unknown_ips",0)).ljust(27)}║
║  Memory Usage:       {(str(round(s.get("memory_usage",0),1))+"%").ljust(27)}║
║  CPU Usage:          {(str(round(s.get("cpu_usage",0),1))+"%").ljust(27)}║
║  Packets/sec:        {str(s.get("packets_per_sec",0)).ljust(27)}║
║  Critical Alerts:    {str(rd.get("critical_alerts",0)).ljust(27)}║
║  Warning Alerts:     {str(rd.get("warning_alerts",0)).ljust(27)}║
║  Total Packets:      {str(rd.get("total_packets",0)).ljust(27)}║
╚══════════════════════════════════════════════════╝
</pre></div>''', unsafe_allow_html=True)

    # Export buttons
    st.markdown("---")
    e1, e2, e3, e4 = st.columns(4)
    with e1:
        if st.button("📥 Export Logs", use_container_width=True):
            d = fetch_api("/export/logs")
            if d: st.download_button("⬇️ Download Logs", json.dumps(d, indent=2), "vm_logs.json", use_container_width=True)
    with e2:
        if st.button("📥 Export Alerts", use_container_width=True):
            d = fetch_api("/export/alerts")
            if d: st.download_button("⬇️ Download Alerts", json.dumps(d, indent=2), "vm_alerts.json", use_container_width=True)
    with e3:
        if st.button("📥 Export Report", use_container_width=True):
            d = fetch_api("/report")
            if d: st.download_button("⬇️ Download Report", json.dumps(d, indent=2), "vm_report.json", use_container_width=True)
    with e4:
        if st.button("🔄 Refresh Now", use_container_width=True):
            st.rerun()

    st.markdown(
        f'<div style="text-align:center;color:#484f58;margin-top:1rem;font-size:0.7rem">'
        f'Updated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} • '
        f'Auto-refresh: {refresh_interval}s • '
        f'VM Security System v3.0 Industry Edition'
        f'</div>', unsafe_allow_html=True)

    return refresh_interval


# ============================================================
# RUN
# ============================================================
try:
    interval = main()
except Exception as e:
    st.error(f"⚠️ Dashboard error: {e}")
    st.exception(e)
    interval = 5

time.sleep(interval if interval else 2)
st.rerun()
