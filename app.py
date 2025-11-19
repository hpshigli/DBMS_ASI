# app.py — Overview Dashboard
import streamlit as st
import pandas as pd
from db import run_query  # uses your helper with DictCursor + commit/close

st.set_page_config(page_title="ASI Dashboard", layout="wide")

# ---------- Optional: tidy sidebar ----------
# with st.sidebar:
#     st.title("⚙️ Controls")
#     st.caption("These are saved in session_state for all pages.")
#     host = st.text_input("Host", st.session_state.get("db_host", "localhost"))
#     user = st.text_input("User", st.session_state.get("db_user", "root"))
#     pwd  = st.text_input("Password", st.session_state.get("db_pass", ""), type="password")
#     dbn  = st.text_input("Database", st.session_state.get("db_name", "asi"))
#     if st.button("Save connection"):
#         st.session_state["db_host"] = host
#         st.session_state["db_user"] = user
#         st.session_state["db_pass"] = pwd
#         st.session_state["db_name"] = dbn
#         st.success("Saved connection settings")
#     st.divider()
#     st.page_link("app.py", label="🏠 Overview")
#     st.page_link("pages/1_Cloud_Account.py", label="📂 Cloud Accounts")
#     st.page_link("pages/2_Asset.py", label="🖥️ Assets")
#     st.page_link("pages/3_Vulnerability.py", label="🧷 Vulnerabilities")
#     st.page_link("pages/4_Exposure.py", label="🌐 Exposures")
#     st.page_link("pages/5_Patch.py", label="🩹 Patches")
#     st.page_link("pages/6_Patch_Deployment.py", label="🚀 Patch Deployment")
#     st.page_link("pages/7_Alert.py", label="🚨 Alerts")
#     st.page_link("pages/8_Incident.py", label="🧯 Incidents")
#     st.page_link("pages/9_Aggregate_Functions.py", label="🧮 Aggregates")
#     st.page_link("pages/10_Join_Queries.py", label="🔗 Joins")
#     st.page_link("pages/11_Nested_Queries.py", label="🔍 Nested")
#     st.divider()
#     if st.button("🔄 Refresh"):
#         st.rerun()

# ---------- Title ----------
st.title("ASI Cloud Security — Overview Dashboard")

# ---------- KPI Row ----------
kpi_q = {
    "total_assets":       "SELECT COUNT(*) AS n FROM ASSET;",
    "total_vulns":        "SELECT COUNT(*) AS n FROM VULNERABILITY;",
    "open_incidents":     "SELECT COUNT(*) AS n FROM INCIDENT WHERE status IN ('Open','In Progress');",
    "alerts_last_7_days": "SELECT COUNT(*) AS n FROM ALERT WHERE created_at >= NOW() - INTERVAL 7 DAY;",
}
def kpi_val(sql):
    r = run_query(sql)[0]["n"] if run_query(sql) else 0
    return r or 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Assets",            f"{kpi_val(kpi_q['total_assets'])}")
c2.metric("Vulnerabilities",   f"{kpi_val(kpi_q['total_vulns'])}")
c3.metric("Open/Active Incidents", f"{kpi_val(kpi_q['open_incidents'])}")
c4.metric("Alerts (7 days)",   f"{kpi_val(kpi_q['alerts_last_7_days'])}")

st.divider()

# ---------- Charts Row ----------
colA, colB, colC = st.columns((1.2, 1, 1))

# Alerts last 14 days (line)
with colA:
    st.subheader("Alerts (last 14 days)")
    rows = run_query("""
        SELECT DATE(created_at) AS Day, COUNT(*) AS Alerts
        FROM ALERT
        WHERE created_at >= CURDATE() - INTERVAL 13 DAY
        GROUP BY DATE(created_at)
        ORDER BY Day;
    """)
    df = pd.DataFrame(rows)
    if df.empty:
        st.info("No alerts in the last 14 days.")
    else:
        st.line_chart(df.set_index("Day"))

# Vulnerabilities by severity (bar)
with colB:
    st.subheader("🧷 Vulnerabilities by Severity")
    rows = run_query("""
        SELECT severity AS Severity, COUNT(*) AS Count
        FROM VULNERABILITY
        GROUP BY severity
        ORDER BY FIELD(Severity,'Critical','High','Medium','Low');
    """)
    df = pd.DataFrame(rows)
    if df.empty:
        st.info("No vulnerabilities recorded.")
    else:
        st.bar_chart(df.set_index("Severity"))

# Patch deployments by status (bar)
with colC:
    st.subheader("🚀 Patch Deployments by Status")
    rows = run_query("""
        SELECT status AS Status, COUNT(*) AS Count
        FROM PATCH_DEPLOYMENT
        GROUP BY status;
    """)
    df = pd.DataFrame(rows)
    if df.empty:
        st.info("No patch deployment records.")
    else:
        st.bar_chart(df.set_index("Status"))

st.divider()

# ---------- Top Risky Assets (works without the function) ----------
st.subheader("Top Risky Assets (simple composite score)")
st.caption("Score = 2×vulns + 1×exposures + 3×open/incidents (higher = riskier)")

top_rows = run_query("""
    SELECT
      a.asset_id,
      a.name AS Asset,
      COALESCE(v.vcnt,0) AS Vulns,
      COALESCE(e.ecnt,0) AS Exposures,
      COALESCE(i.icnt,0) AS Open_Incidents,
      (COALESCE(v.vcnt,0)*2 + COALESCE(e.ecnt,0) + COALESCE(i.icnt,0)*3) AS Score
    FROM ASSET a
    LEFT JOIN (
      SELECT asset_id, COUNT(*) AS vcnt
      FROM VULNERABILITY
      GROUP BY asset_id
    ) v USING (asset_id)
    LEFT JOIN (
      SELECT asset_id, COUNT(*) AS ecnt
      FROM EXPOSURE
      GROUP BY asset_id
    ) e USING (asset_id)
    LEFT JOIN (
      SELECT al.asset_id, COUNT(*) AS icnt
      FROM INCIDENT i
      JOIN ALERT al ON al.alert_id = i.alert_id
      WHERE i.status IN ('Open','In Progress')
      GROUP BY al.asset_id
    ) i USING (asset_id)
    ORDER BY Score DESC, a.asset_id
    LIMIT 10;
""")
top_df = pd.DataFrame(top_rows)
if top_df.empty:
    st.info("No risk data to display yet.")
else:
    st.dataframe(top_df[["Asset","Vulns","Exposures","Open_Incidents","Score"]], use_container_width=True)

st.divider()

# ---------- Recent Alerts + context ----------
st.subheader("Recent Alerts")
limit = st.slider("Show last N alerts", 5, 100, 20, 5)
rows = run_query(f"""
    SELECT al.alert_id,
           a.name AS Asset,
           al.severity AS Severity,
           al.description AS Description,
           al.created_at AS Created_At
    FROM ALERT al
    LEFT JOIN ASSET a ON a.asset_id = al.asset_id
    ORDER BY al.alert_id DESC
    LIMIT {int(limit)};
""")
alerts_df = pd.DataFrame(rows)
if alerts_df.empty:
    st.info("No alerts yet — perform CRUD on Vulnerability/Exposure/Patch/Deployment to see triggers populate alerts here.")
else:
    st.dataframe(alerts_df, use_container_width=True)
