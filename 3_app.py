import streamlit as st
import pandas as pd
import time
import hashlib
import plotly.express as px
import plotly.graph_objects as go
from cassandra.cluster import Cluster

# ==========================================
# 1. PAGE CONFIGURATION & CYBER CSS
# ==========================================
st.set_page_config(page_title="Global Threat Radar", page_icon="🌍", layout="wide")

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');
    
    .stApp { 
        background: radial-gradient(circle at top center, #0B0F19, #050608);
        color: #E0E6ED;
        font-family: 'Inter', sans-serif;
    }
    [data-testid="stHeader"] { background-color: transparent !important; }
    .block-container { padding-top: 1.5rem !important; padding-bottom: 0rem !important; }
    
    h1, h2, h3, h4 { color: #00E6FF !important; font-family: 'Inter', sans-serif; font-weight: 800; letter-spacing: -0.5px; }
    
    .glowing-title {
        font-size: 3.5rem;
        background: linear-gradient(90deg, #00E6FF, #00FFCC, #00E6FF);
        background-size: 200% auto;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: shine 3s linear infinite;
        text-shadow: 0px 4px 20px rgba(0, 230, 255, 0.4);
        font-weight: 800; margin-bottom: 0px; margin-top: -30px;
    }
    @keyframes shine { to { background-position: 200% center; } }
    
    .subtitle-text { color: #94A3B8; font-size: 1.1rem; margin-top: -10px; margin-bottom: 25px; border-left: 3px solid #FF2D55; padding-left: 10px;}
    
    /* Advanced Glassmorphism Cards */
    div[data-testid="metric-container"] {
        background: linear-gradient(145deg, rgba(18, 22, 29, 0.8), rgba(10, 12, 17, 0.9)) !important;
        backdrop-filter: blur(15px); -webkit-backdrop-filter: blur(15px);
        border: 1px solid rgba(0, 230, 255, 0.1);
        padding: 20px; border-radius: 12px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255,255,255,0.05);
        transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
    }
    div[data-testid="metric-container"]:hover {
        transform: translateY(-5px); box-shadow: 0 12px 40px 0 rgba(0, 230, 255, 0.15);
        border-color: rgba(0, 230, 255, 0.3);
    }
    
    [data-testid="stMetricValue"] { font-size: 2.2rem !important; font-weight: 800 !important; color: #FFFFFF !important; }
    [data-testid="stMetricLabel"] { color: #00E6FF !important; font-weight: 700 !important; text-transform: uppercase; letter-spacing: 1.5px; font-size: 0.8rem !important; }
    [data-testid="stMetricDelta"] { font-weight: 700 !important; }
    
    [data-testid="stSidebar"] { background: rgba(8, 10, 15, 0.95) !important; border-right: 1px solid rgba(255, 255, 255, 0.05); }
    .dataframe { font-family: 'JetBrains Mono', monospace !important; font-size: 0.85rem; }
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: #0A0C11; }
    ::-webkit-scrollbar-thumb { background: #2B303B; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #3C4352; }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 2. CASSANDRA & DATA ENGINEERING
# ==========================================
@st.cache_resource
def get_session():
    try:
        cluster = Cluster(['127.0.0.1'], port=9042)
        return cluster.connect('cyber_defense')
    except Exception as e:
        return None

session = get_session()

# Deterministic IP to Geo-Location Simulator
def simulate_geo_location(ip):
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    lat = (h % 120) - 60 
    lon = ((h // 120) % 360) - 180
    return lat, lon

def fetch_data():
    if not session: return pd.DataFrame()
    try:
        rows = session.execute("SELECT ip_address, window_start, request_count, reason FROM blocked_ips")
        data = [[r.ip_address, r.window_start, r.request_count, r.reason] for r in rows]
        df = pd.DataFrame(data, columns=['IP Address', 'Blocked At', 'Request Count', 'Reason'])
        if not df.empty:
            df['Blocked At'] = pd.to_datetime(df['Blocked At'])
            df = df.sort_values(by='Blocked At', ascending=False)
            df['Attack Type'] = df['Reason'].apply(lambda x: 'Volumetric DDoS' if 'DDoS' in str(x) else 'Brute-Force Scan')
            df['Lat'], df['Lon'] = zip(*df['IP Address'].map(simulate_geo_location))
        return df
    except:
        return pd.DataFrame()

# ==========================================
# 3. SIDEBAR & OPERATIONS
# ==========================================
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/3063/3063259.png", width=70)
    st.title("COMMAND CENTER")
    is_live = st.toggle("🔴 Real-Time Sync", value=True)
    refresh_rate = st.slider("Polling Rate (sec)", 1, 10, 3)
    
    st.markdown("---")
    st.markdown("### 📡 Node Status")
    st.info("⚡ Spark Core: **ACTIVE**")
    st.info("📨 Kafka Broker: **ACTIVE**")
    st.info("🗄️ Cassandra DB: **ONLINE**")

# ==========================================
# 4. MAIN DASHBOARD UI
# ==========================================
st.markdown("<p class='glowing-title'>GLOBAL THREAT RADAR</p>", unsafe_allow_html=True)
st.markdown("<p class='subtitle-text'>Autonomous DDoS Mitigation & Geo-Spatial Threat Tracking System</p>", unsafe_allow_html=True)

df = fetch_data()

if df.empty:
    st.success("✅ Network is secure. Zero anomalous traffic detected across all vectors.")
else:
    # --- SMART KPI ROW WITH DELTAS ---
    col1, col2, col3, col4 = st.columns(4)
    
    half_point = len(df) // 2 if len(df) > 10 else len(df)
    recent_attacks = len(df.head(half_point))
    old_attacks = len(df.tail(len(df) - half_point)) if len(df) > 10 else 1
    trend = int(((recent_attacks - old_attacks) / old_attacks) * 100) if old_attacks > 0 else 0
    
    total_attacks = len(df)
    unique_ips = df['IP Address'].nunique()
    current_load = int(df.head(10)['Request Count'].mean()) if not df.empty else 0
    threat_level = "CRITICAL 🔴" if current_load > 300 else "ELEVATED 🟠"
    
    col1.metric("Intrusion Events", f"{total_attacks:,}", f"{trend}% vs last window", delta_color="inverse")
    col2.metric("Hostile Signatures", f"{unique_ips:,}", "Active Track")
    col3.metric("Current Server Stress", f"{current_load} req/s", "Threshold: 150", delta_color="off")
    col4.metric("Threat Condition", threat_level, "Auto-Blocking Active", delta_color="normal")

    st.markdown("<br>", unsafe_allow_html=True)

    # --- TABS FOR ORGANIZATION ---
    tab1, tab2 = st.tabs(["🌍 Global Command", "🗄️ Raw Telemetry & Logs"])

    with tab1:
        # --- ROW 1: 3D MAP & GAUGE ---
        map_col, gauge_col = st.columns((7, 3))
        
        with map_col:
            st.subheader("🌍 Live 3D Origin Mapping")
            fig_map = px.scatter_geo(df.head(100), lat="Lat", lon="Lon", 
                                     color="Attack Type", size="Request Count",
                                     hover_name="IP Address", projection="orthographic",
                                     color_discrete_map={'Volumetric DDoS':'#FF2D55', 'Brute-Force Scan':'#00FFCC'})
            fig_map.update_geos(
                showcoastlines=True, coastlinecolor="rgba(0, 230, 255, 0.3)",
                showland=True, landcolor="#0B0F19",
                showocean=True, oceancolor="#050608",
                showlakes=False,
                projection_rotation=dict(lon=10, lat=20, roll=0)
            )
            fig_map.update_layout(margin=dict(l=0, r=0, t=0, b=0), height=350, paper_bgcolor="rgba(0,0,0,0)", showlegend=False)
            st.plotly_chart(fig_map, width="stretch")

        with gauge_col:
            st.subheader("⏱️ Live Stress Gauge")
            fig_gauge = go.Figure(go.Indicator(
                mode = "gauge+number", value = current_load, title = {'text': "Requests / Sec", 'font': {'color': '#94A3B8'}},
                gauge = {
                    'axis': {'range': [None, 500], 'tickcolor': "white"},
                    'bar': {'color': "#00E6FF"},
                    'bgcolor': "rgba(0,0,0,0)",
                    'borderwidth': 2, 'bordercolor': "rgba(255,255,255,0.1)",
                    'steps': [
                        {'range': [0, 150], 'color': "rgba(0, 255, 204, 0.2)"},
                        {'range': [150, 300], 'color': "rgba(255, 149, 0, 0.3)"},
                        {'range': [300, 500], 'color': "rgba(255, 45, 85, 0.4)"}],
                }))
            fig_gauge.update_layout(height=300, margin=dict(l=20, r=20, t=50, b=20), paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
            st.plotly_chart(fig_gauge, width="stretch")

        # --- ROW 2: TIMELINE & DONUT ---
        r2c1, r2c2 = st.columns((7, 3))
        
        with r2c1:
            st.subheader("📈 Global Attack Trajectory")
            df_time = df.groupby('Blocked At')['Request Count'].sum().reset_index()
            fig_area = px.area(df_time, x='Blocked At', y='Request Count', 
                               color_discrete_sequence=['#00E6FF'], template="plotly_dark")
            fig_area.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=300, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_area, width="stretch")
            
        with r2c2:
            st.subheader("🧬 Attack Signatures")
            df_pie = df['Attack Type'].value_counts().reset_index()
            df_pie.columns = ['Attack Type', 'Count']
            fig_pie = px.pie(df_pie, names='Attack Type', values='Count', hole=0.6,
                             color='Attack Type', color_discrete_map={'Volumetric DDoS':'#FF2D55', 'Brute-Force Scan':'#00FFCC'},
                             template="plotly_dark")
            fig_pie.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=300, paper_bgcolor="rgba(0,0,0,0)", showlegend=True, legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01))
            st.plotly_chart(fig_pie, width="stretch")

        # --- ROW 3: BAR & BUBBLE ---
        r3c1, r3c2 = st.columns((4, 6))

        with r3c1:
            st.subheader("🎯 Primary Targets (Top IPs)")
            df_top = df.groupby('IP Address')['Request Count'].sum().nlargest(8).reset_index()
            fig_bar = px.bar(df_top, x='Request Count', y='IP Address', orientation='h',
                             color='Request Count', color_continuous_scale='GnBu', template="plotly_dark")
            fig_bar.update_layout(yaxis={'categoryorder':'total ascending'}, margin=dict(l=0, r=0, t=10, b=0), 
                                  height=350, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", coloraxis_showscale=False)
            st.plotly_chart(fig_bar, width="stretch")

        with r3c2:
            st.subheader("🦠 Threat Clusters")
            fig_scatter = px.scatter(df.head(100), x="Blocked At", y="IP Address", size="Request Count", 
                                     color="Attack Type", hover_name="Reason", size_max=40,
                                     color_discrete_map={'Volumetric DDoS':'#FF2D55', 'Brute-Force Scan':'#00FFCC'}, template="plotly_dark")
            fig_scatter.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=350, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_scatter, width="stretch")

    with tab2:
        st.subheader("🔴 Raw Telemetry Feed")
        st.markdown("Live export of the top 200 blocked connection requests directly from Cassandra.")
        
        df_display = df.head(200).copy()
        # Drop the simulated Lat/Lon for the raw logs
        df_display = df_display.drop(columns=['Lat', 'Lon'])
        df_display['Blocked At'] = df_display['Blocked At'].dt.strftime('%H:%M:%S | %Y-%m-%d')
        df_display.insert(0, 'Action', '⚡ TERMINATED')
        
        # Color coding rows based on attack type
        def color_rows(row):
            if row['Attack Type'] == 'Volumetric DDoS': return ['background-color: rgba(255, 45, 85, 0.15)'] * len(row)
            return ['background-color: rgba(0, 255, 204, 0.15)'] * len(row)

        st.dataframe(
            df_display.style.map(lambda _: '', subset=[]).apply(color_rows, axis=1),
            width="stretch", hide_index=True, height=600
        )

# ==========================================
# 5. AUTO-REFRESH LOGIC
# ==========================================
if is_live:
    time.sleep(refresh_rate)
    st.rerun()


