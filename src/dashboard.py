"""
dashboard.py — Member 2: Dashboard & Network Analytics

Reads packet stats from the Flask API in api.py (built by teammates,
runs on http://localhost:5000). Reads alerts/risk_scores directly via
database.py, since api.py doesn't expose those yet (ask Member 3 to add
/alerts and /risk_scores endpoints later if you want this fully decoupled
over the network; for now, direct DB read works fine when everyone runs
on the same machine at demo time).

Run (from inside the src/ folder, with capture.py + api.py already running):
    streamlit run dashboard.py
"""

import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh

import database  # must sit in the same src/ folder as this file

API_BASE = "http://localhost:5000"

st.set_page_config(page_title="AnomalyX — Network Traffic Monitor", page_icon="📡", layout="wide")


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

@st.cache_data(ttl=1)
def load_latest_packets(limit: int) -> pd.DataFrame:
    try:
        r = requests.get(f"{API_BASE}/packets/latest", params={"limit": limit}, timeout=3)
        r.raise_for_status()
        df = pd.DataFrame(r.json())
    except Exception as e:
        st.error(f"Couldn't reach the API at {API_BASE} — make sure api.py is running. ({e})")
        return pd.DataFrame()
    if not df.empty and "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s", errors="coerce")
        df = df.dropna(subset=["timestamp"])
    return df


@st.cache_data(ttl=2)
def load_protocol_counts() -> pd.DataFrame:
    try:
        r = requests.get(f"{API_BASE}/stats/protocols", timeout=3)
        r.raise_for_status()
        return pd.DataFrame(r.json())
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=1)
def load_total_count() -> int:
    try:
        r = requests.get(f"{API_BASE}/stats/total", timeout=3)
        r.raise_for_status()
        return r.json().get("total", 0)
    except Exception:
        return 0


@st.cache_data(ttl=2)
def load_alerts(limit: int = 25) -> pd.DataFrame:
    try:
        conn = database.connect_db()
        df = pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", conn, params=(limit,)
        )
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=2)
def load_risk_scores() -> pd.DataFrame:
    try:
        conn = database.connect_db()
        df = pd.read_sql_query("SELECT * FROM risk_scores ORDER BY risk_score DESC", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

st.sidebar.title("📡 Controls")
refresh_seconds = st.sidebar.slider("Auto-refresh interval (sec)", 1, 15, 3)
packet_limit = st.sidebar.slider("Packets to load", 100, 3000, 500, step=100)
top_n = st.sidebar.slider("Top N IPs", 3, 20, 8)
st.sidebar.caption(f"API: {API_BASE}")

st_autorefresh(interval=refresh_seconds * 1000, key="auto_refresh")

st.title("📡 AnomalyX — Real-Time Network Traffic Dashboard")

df = load_latest_packets(packet_limit)
total_count = load_total_count()

if df.empty:
    st.warning(
        "No packet data yet. Make sure `capture.py` (packet capture) and "
        "`api.py` (Flask server) are both running."
    )
    st.stop()

# ---------------------------------------------------------------------------
# Top metrics
# ---------------------------------------------------------------------------

duration_s = max((df["timestamp"].max() - df["timestamp"].min()).total_seconds(), 1)
packet_rate = len(df) / duration_s
bandwidth_bps = df["packet_size"].sum() / duration_s
avg_packet_size = df["packet_size"].mean()

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Live Packet Counter", f"{total_count:,}", help="Total packets captured all-time")
c2.metric("Packets Loaded", f"{len(df):,}")
c3.metric("Packet Rate", f"{packet_rate:,.1f} pkt/s")
c4.metric("Bandwidth Usage", f"{bandwidth_bps * 8 / 1000:,.1f} kbps")
c5.metric("Avg Packet Size", f"{avg_packet_size:,.0f} bytes")

st.divider()

# ---------------------------------------------------------------------------
# Alerts + risk scores (from Member 3's detector, via database.py directly)
# ---------------------------------------------------------------------------

alerts_df = load_alerts()
if not alerts_df.empty:
    st.subheader("⚠️ Active Alerts")
    for _, row in alerts_df.head(5).iterrows():
        confidence = str(row.get("confidence", "")).title()
        color = {"High": "🔴", "Medium": "🟠", "Low": "🟡"}.get(confidence, "⚪")
        st.markdown(
            f"{color} **{row['alert_type']}** — Source IP: `{row['src_ip']}` — "
            f"Risk: **{row['risk_score']}/100** — Confidence: **{confidence}**"
        )
    with st.expander(f"View all {len(alerts_df)} recent alerts"):
        st.dataframe(alerts_df, use_container_width=True, hide_index=True)
    st.divider()

risk_df = load_risk_scores()
if not risk_df.empty:
    st.subheader("🎯 Risk Scores by IP")
    st.dataframe(risk_df, use_container_width=True, hide_index=True)
    st.divider()

# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

row1_col1, row1_col2 = st.columns(2)

with row1_col1:
    st.subheader("Protocol Distribution")
    proto_df = load_protocol_counts()
    if proto_df.empty:
        proto_df = df["protocol"].value_counts().reset_index()
        proto_df.columns = ["protocol", "count"]
    fig = px.pie(proto_df, names="protocol", values="count", hole=0.45)
    fig.update_traces(textinfo="percent+label")
    st.plotly_chart(fig, use_container_width=True)

with row1_col2:
    st.subheader("Traffic Timeline (packets over time)")
    timeline = df.set_index("timestamp").resample("1s").size().reset_index(name="packet_count")
    fig = px.line(timeline, x="timestamp", y="packet_count")
    fig.update_layout(yaxis_title="packets/sec", xaxis_title="time")
    st.plotly_chart(fig, use_container_width=True)

row2_col1, row2_col2 = st.columns(2)

with row2_col1:
    st.subheader(f"Top {top_n} Source IPs")
    top_src = df["src_ip"].value_counts().head(top_n).reset_index()
    top_src.columns = ["src_ip", "count"]
    fig = px.bar(top_src, x="count", y="src_ip", orientation="h")
    fig.update_layout(yaxis={"categoryorder": "total ascending"})
    st.plotly_chart(fig, use_container_width=True)

with row2_col2:
    st.subheader(f"Top {top_n} Destination IPs")
    top_dst = df["dst_ip"].value_counts().head(top_n).reset_index()
    top_dst.columns = ["dst_ip", "count"]
    fig = px.bar(top_dst, x="count", y="dst_ip", orientation="h", color_discrete_sequence=["#ef553b"])
    fig.update_layout(yaxis={"categoryorder": "total ascending"})
    st.plotly_chart(fig, use_container_width=True)

st.subheader("Bandwidth Usage Over Time")
bw_timeline = df.set_index("timestamp").resample("1s")["packet_size"].sum().reset_index(name="bytes_per_sec")
bw_timeline["kbps"] = bw_timeline["bytes_per_sec"] * 8 / 1000
fig = go.Figure()
fig.add_trace(go.Scatter(x=bw_timeline["timestamp"], y=bw_timeline["kbps"], fill="tozeroy", mode="lines"))
fig.update_layout(yaxis_title="kbps", xaxis_title="time")
st.plotly_chart(fig, use_container_width=True)

with st.expander("Raw packet table (latest loaded)"):
    st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)